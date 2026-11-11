// Copyright (c) 2026 Stellar Compliance Kit contributors
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! `allowlist-token` is a `#![no_std]` Soroban contract that wraps an existing
//! SEP-41 token and only permits `transfer` calls between two addresses that
//! are both present on an on-chain allowlist.
//!
//! **Purpose**: give issuers of permissioned tokens (e.g. RWA or regulated
//! stablecoins) a drop-in gate that blocks transfers to or from addresses
//! that haven't cleared KYC/onboarding, without modifying the underlying
//! token contract's own logic.
//!
//! **Composition**: deploy this contract in front of an issuer's real token
//! and point clients at it instead of the underlying token — cleared
//! transfers are forwarded on via a cross-contract call.
//!
//! **Roles**: `admin` is the primary privileged role. `add_to_allowlist`
//! (and `add_to_allowlist_delegated`) are admin-only. An optional
//! compliance officer, assigned with `set_compliance_officer` and removed
//! with `revoke_compliance_officer` (both admin-only), may call
//! `remove_from_allowlist` but can never grant access or manage roles.
//!
//! **Delegated actions**: `add_to_allowlist_delegated` lets a relayer submit
//! an allowlist addition on the admin's behalf, without the admin account
//! signing the transaction. The admin first registers an ed25519 public key
//! with `set_delegated_admin_key`. The holder of the matching private key then
//! signs the payload
//! `allowlist-delegated-v1:<target>:add_to_allowlist:<nonce>:<expiry>`, where
//! `<target>` is the address being allowlisted, `<nonce>` is a `u64` and
//! `<expiry>` is a ledger timestamp in seconds. Each admin has a
//! replay-protection nonce: a call is rejected with `InvalidNonce` unless
//! `nonce` is strictly greater than the last accepted one (readable via
//! `get_delegated_nonce`), and with `ExpiredSignature` once the ledger
//! timestamp reaches `expiry`. Use this path when the admin key is kept
//! offline or in cold storage and a relayer pays the fees; use the direct
//! path (`admin.require_auth()`) whenever the admin can sign the transaction
//! itself.
//! `allowlist-token` is a Soroban contract that wraps an existing
//! SEP-41 token and only permits `transfer` calls between two addresses that
//! are both present on an on-chain allowlist.
//!
//! **Purpose**: give issuers of permissioned tokens (e.g. RWA or regulated
//! stablecoins) a drop-in gate that blocks transfers to or from addresses
//! that haven't cleared KYC/onboarding, without modifying the underlying
//! token contract's own logic.
//!
//! **Composition**: deploy this contract in front of an issuer's real token
//! and point clients at it instead of the underlying token — cleared
//! transfers are forwarded on via a cross-contract call.
//!
//! **Roles**: there is a single privileged role, `admin`. Both
//! `add_to_allowlist` and `remove_from_allowlist` are admin-only, and this
//! contract has no compliance-officer role (that role exists only on
//! `denylist-gate` and `jurisdiction-flag`). If an "officers may revoke but not
//! grant" split is ever wanted here, it must be added deliberately, with
//! `add_to_allowlist` staying admin-only.
#![no_std]

extern crate alloc;

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, token, Address, Bytes,
    BytesN, Env, String, Symbol, Vec,
};

/// Extend a persistent allowlist entry when its remaining TTL drops below
/// this many ledgers (~7 days at ~5s/ledger on mainnet).
pub(crate) const ALLOWED_TTL_THRESHOLD: u32 = 120_960; // ~7 days

/// Target remaining TTL after extension (~90 days at ~5s/ledger).
pub(crate) const ALLOWED_TTL_EXTEND_TO: u32 = 1_555_200; // ~90 days

/// Extend the contract's instance storage when its remaining TTL drops below
/// this many ledgers (~7 days at ~5s/ledger).
pub const INSTANCE_TTL_THRESHOLD: u32 = 120_960;

/// Target remaining TTL, in ledgers, after an instance TTL extension (~90 days
/// at ~5s/ledger).
pub const INSTANCE_TTL_EXTEND_TO: u32 = 1_555_200;

fn extend_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
}

/// Maximum number of addresses accepted by a batch allowlist operation.
pub const MAX_BATCH_SIZE: u32 = 45;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The admin address, set once in `initialize`. Instance storage.
    Admin,
    /// Optional compliance officer, who may revoke allowlist entries. Instance storage.
    ComplianceOfficer,
    Token,
    Allowed(Address),
    Paused,
    PendingAdmin,
    /// ed25519 public key allowed to authorize delegated admin actions.
    DelegatedAdminPubKey,
    /// Last accepted delegated-action nonce for an admin. Persistent storage.
    DelegatedNonce(Address),
    PendingUpgrade,
}

#[contracttype]
#[derive(Clone)]
pub struct AllowlistEntry {
    pub expiration_ledger: Option<u32>,
}

#[contractevent]
pub struct AllowAdd {
    #[topic]
    pub address: Address,
}

#[contractevent]
pub struct AllowRemove {
    #[topic]
    pub address: Address,
}

#[contractevent]
pub struct Blocked {
    #[topic]
    pub from: Address,
    #[topic]
    pub to: Address,
    pub amount: i128,
}

#[contractevent]
pub struct AdminTransferred {
    #[topic]
    pub old_admin: Address,
    #[topic]
    pub new_admin: Address,
}

#[contractevent]
pub struct AdminProposed {
    #[topic]
    pub current: Address,
    #[topic]
    pub proposed: Address,
}

#[contractevent]
pub struct UpgradeProposed {
    #[topic]
    pub admin: Address,
    pub new_wasm: BytesN<32>,
    pub activated_at: u64,
}

#[contractevent]
pub struct UpgradeCancelled {
    #[topic]
    pub admin: Address,
}

#[contractevent]
pub struct UpgradeCommitted {
    #[topic]
    pub admin: Address,
    pub new_wasm: BytesN<32>,
}

#[contractevent]
pub struct Paused {
    #[topic]
    pub admin: Address,
}

#[contractevent]
pub struct Unpaused {
    #[topic]
    pub admin: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct Metadata {
    pub version: String,
    pub admin: Address,
}

/// Delayed upgrade proposal state.
#[contracttype]
#[derive(Clone)]
pub struct UpgradeState {
    pub new_wasm: BytesN<32>,
    pub activated_at: u64,
}

/// Current on-chain schema version for this contract instance.
pub const SCHEMA_VERSION: u32 = 1;

/// Minimum upgrade review window, approximately one day at five seconds per ledger.
pub const MIN_UPGRADE_DELAY_LEDGERS: u32 = 17_280;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    /// Caller supplied an argument that is structurally invalid — e.g. a
    /// negative token amount.
    InvalidInput = 4,
    ContractPaused = 5,
    NoPendingAdmin = 6,
    PendingAdminMismatch = 7,
    DelegationNotConfigured = 8,
    InvalidSignature = 9,
    InvalidNonce = 10,
    ExpiredSignature = 11,
    /// `commit_upgrade` called with no pending upgrade, or before `activated_at`.
    UpgradeNotReady = 12,
    BatchTooLarge = 13,
}

#[contract]
pub struct AllowlistToken;

#[contractimpl]
impl AllowlistToken {
    /// One-time setup. `admin` may manage the allowlist; `token` is the
    /// address of the underlying SEP-41 token contract that real transfers
    /// are forwarded to once both parties clear the allowlist check.
    pub fn initialize(env: Env, admin: Address, token: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        extend_instance_ttl(&env);
        Ok(())
    }

    /// Returns metadata about this contract instance.
    pub fn metadata(env: Env) -> Result<Metadata, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        Ok(Metadata {
            version: String::from_str(&env, env!("CARGO_PKG_VERSION")),
            admin,
        })
    }

    /// Return the configured admin address.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Configure the ed25519 public key that may authorize delegated admin
    /// actions without the admin account itself needing to submit the
    /// transaction. The direct-auth path remains unchanged and still uses
    /// `admin.require_auth()`. Admin-only.
    pub fn set_delegated_admin_key(
        env: Env,
        admin: Address,
        pubkey: BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::DelegatedAdminPubKey, &pubkey);
        Ok(())
    }

    /// Add `address` to the allowlist. Admin-only.
    ///
    /// Granting access is deliberately stricter than revoking it: putting an
    /// address on the allowlist lets it receive and send the wrapped token, so
    /// it is restricted to the `admin` (directly, or through
    /// `add_to_allowlist_delegated`). The compliance officer may revoke access
    /// via `remove_from_allowlist` but never grant it.
    pub fn add_to_allowlist(
        env: Env,
        admin: Address,
        address: Address,
        expiration_ledger: Option<u32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if let Some(exp) = expiration_ledger {
            if exp < env.ledger().sequence() {
                return Err(Error::InvalidInput);
            }
        }
        let key = DataKey::Allowed(address.clone());
        env.storage()
            .persistent()
            .set(&key, &AllowlistEntry { expiration_ledger });
        env.storage().persistent().extend_ttl(
            &key,
            ALLOWED_TTL_THRESHOLD,
            ALLOWED_TTL_EXTEND_TO,
        );
        AllowAdd { address }.publish(&env);
        Ok(())
    }

    /// Add every address to the allowlist. Admin-only; each entry receives the
    /// same optional expiration ledger and an individual `AllowAdd` event.
    pub fn add_multiple_to_allowlist(
        env: Env,
        admin: Address,
        addresses: Vec<Address>,
        expiration_ledger: Option<u32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(Error::BatchTooLarge);
        }
        if let Some(expiration) = expiration_ledger {
            if expiration < env.ledger().sequence() {
                return Err(Error::InvalidInput);
            }
        }

        for address in addresses.iter() {
            let key = DataKey::Allowed(address.clone());
            env.storage()
                .persistent()
                .set(&key, &AllowlistEntry { expiration_ledger });
            env.storage().persistent().extend_ttl(
                &key,
                ALLOWED_TTL_THRESHOLD,
                ALLOWED_TTL_EXTEND_TO,
            );
            AllowAdd { address }.publish(&env);
        }
        Ok(())
    }

    /// Add `address` to the allowlist using a signed off-chain authorization
    /// payload. This path verifies a nonce and expiry before applying the
    /// allowlist change, so a relayer can submit it on behalf of the admin.
    ///
    /// Returns `Err(ContractPaused)` if the contract is currently paused.
    pub fn add_to_allowlist_delegated(
        env: Env,
        admin: Address,
        address: Address,
        nonce: u64,
        expiry: u64,
        signature: BytesN<64>,
    ) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_configured_admin(&env, &admin)?;

        let now = env.ledger().timestamp();
        if expiry <= now {
            return Err(Error::ExpiredSignature);
        }

        let last_nonce: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::DelegatedNonce(admin.clone()))
            .unwrap_or(0);
        if nonce <= last_nonce {
            return Err(Error::InvalidNonce);
        }

        let pubkey: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::DelegatedAdminPubKey)
            .ok_or(Error::DelegationNotConfigured)?;
        let action = Symbol::new(&env, "add_to_allowlist");
        let message = Self::delegated_action_message(&env, &address, &action, nonce, expiry);
        match soroban_sdk::env::internal::Env::verify_sig_ed25519(
            &env,
            pubkey.to_object(),
            message.to_object(),
            signature.to_object(),
        ) {
            Ok(_) => {}
            Err(_) => return Err(Error::NotAuthorized),
        }
        let key = DataKey::Allowed(address.clone());
        env.storage()
            .persistent()
            .set(&key, &AllowlistEntry { expiration_ledger: None });
        env.storage().persistent().extend_ttl(
            &key,
            ALLOWED_TTL_THRESHOLD,
            ALLOWED_TTL_EXTEND_TO,
        );
        AllowAdd { address }.publish(&env);
        Ok(())
    }

    /// Remove `address` from the allowlist. Admin or compliance officer.
    ///
    /// Returns `Err(ContractPaused)` if the contract is currently paused.
    pub fn remove_from_allowlist(env: Env, admin: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_compliance_authority(&env, &admin)?;
        extend_instance_ttl(&env);
        env.storage()
            .persistent()
            .remove(&DataKey::Allowed(address.clone()));
        AllowRemove { address }.publish(&env);
        Ok(())
    }

    /// Remove every address from the allowlist. Admin or compliance officer;
    /// each address emits an individual `AllowRemove` event.
    pub fn remove_multiple_from_allowlist(
        env: Env,
        admin: Address,
        addresses: Vec<Address>,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &admin)?;
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(Error::BatchTooLarge);
        }
        extend_instance_ttl(&env);

        for address in addresses.iter() {
            env.storage()
                .persistent()
                .remove(&DataKey::Allowed(address.clone()));
            AllowRemove { address }.publish(&env);
        }
        Ok(())
    }

    /// Assign the compliance-officer role. Admin-only.
    pub fn set_compliance_officer(env: Env, admin: Address, officer: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::ComplianceOfficer, &officer);
        Ok(())
    }

    /// Revoke the compliance-officer role. Admin-only.
    pub fn revoke_compliance_officer(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().remove(&DataKey::ComplianceOfficer);
        Ok(())
    }

    /// Returns the last-used delegated-action nonce for `admin`, or 0 if none
    /// has been used. A relayer should sign its next payload with a nonce
    /// strictly greater than this value.
    pub fn get_delegated_nonce(env: Env, admin: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::DelegatedNonce(admin))
            .unwrap_or(0)
    }

    /// Propose a new admin. The current admin remains active until the
    /// proposed admin calls `accept_admin`.
    pub fn propose_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
        AdminProposed {
            current: current_admin,
            proposed: new_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Accept a pending admin transfer. Must be called by the proposed admin.
    pub fn accept_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        new_admin.require_auth();

        let pending_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(Error::NoPendingAdmin)?;
        if pending_admin != new_admin {
            return Err(Error::PendingAdminMismatch);
        }

        let old_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        extend_instance_ttl(&env);
        AdminTransferred { old_admin, new_admin }.publish(&env);
        Ok(())
    }

    /// Immediately reassign the admin role to `new_admin`. Requires auth from
    /// `current_admin`, which must be the stored admin.
    ///
    /// Unlike `propose_admin` / `accept_admin`, this is single-step: the old
    /// admin loses all privileges as soon as this call succeeds, and any
    /// pending two-step proposal is cleared. Prefer the two-step flow when
    /// `new_admin`'s key has not yet been proven to work; use this one when
    /// the current key must be rotated out right away.
    ///
    /// Emits `AdminTransferred { old_admin, new_admin }`.
    pub fn transfer_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        AdminTransferred {
            old_admin: current_admin,
            new_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Propose a two-step upgrade to `new_wasm_hash` (the hash of the
    /// already-uploaded replacement contract Wasm).
    ///
    /// Admin-only. The upgrade does **not** take effect immediately: it becomes
    /// committable only once the ledger sequence reaches `activated_at`, which
    /// `propose_upgrade` sets to `current_ledger + delay_ledgers`. This gives the
    /// admin, the compliance officer, and any external watchguard a
    /// `delay_ledgers`-long window to review the proposed Wasm and call
    /// `cancel_upgrade` before it can be installed — the safe "migration path"
    /// required by issue #113, in contrast to `jurisdiction-flag::upgrade`, which
    /// is single-step and issuer-only (see threat model J6).
    pub fn propose_upgrade(
        env: Env,
        admin: Address,
        new_wasm: BytesN<32>,
        delay_ledgers: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if delay_ledgers < MIN_UPGRADE_DELAY_LEDGERS {
            return Err(Error::UpgradeDelayTooShort);
        }
        let state = UpgradeState {
            new_wasm: new_wasm.clone(),
            activated_at: u64::from(env.ledger().sequence())
                .saturating_add(delay_ledgers as u64),
        };
        env.storage().instance().set(&DataKey::PendingUpgrade, &state);
        UpgradeProposed {
            admin,
            new_wasm,
            activated_at: state.activated_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Commit a previously proposed upgrade, installing `new_wasm_hash`.
    ///
    /// Admin-only. Errors with `UpgradeNotReady` if no upgrade is pending or if
    /// the current ledger has not yet reached `activated_at`.
    pub fn commit_upgrade(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let state: UpgradeState = env
            .storage()
            .instance()
            .get(&DataKey::PendingUpgrade)
            .ok_or(Error::UpgradeNotReady)?;
        if u64::from(env.ledger().sequence()) < state.activated_at {
            return Err(Error::UpgradeNotReady);
        }
        env.deployer()
            .update_current_contract_wasm(state.new_wasm.clone());
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        UpgradeCommitted {
            admin,
            new_wasm: state.new_wasm,
        }
        .publish(&env);
        Ok(())
    }

    /// Cancel a pending upgrade. Admin-only.
    pub fn cancel_upgrade(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        UpgradeCancelled { admin }.publish(&env);
        Ok(())
    }

    /// Return the pending admin proposal, if one exists.
    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingAdmin)
    }

    /// Return the pending upgrade and activation ledger, if one exists.
    pub fn get_pending_upgrade(env: Env) -> Option<UpgradeState> {
        env.storage().instance().get(&DataKey::PendingUpgrade)
    }

    /// Current on-chain schema version (see [`SCHEMA_VERSION`]).
    pub fn schema_version(_env: Env) -> u32 {
        SCHEMA_VERSION
    }

    /// Returns true if `address` is currently allowlisted.
    ///
    /// Not affected by pause state — reads always succeed. This view does not
    /// extend the entry's TTL; transfer checks refresh existing entries when
    /// their remaining TTL falls below the configured threshold.
    pub fn is_allowed(env: Env, address: Address) -> bool {
        let entry: Option<AllowlistEntry> =
            env.storage().persistent().get(&DataKey::Allowed(address));
        match entry {
            None => false,
            Some(AllowlistEntry {
                expiration_ledger: None,
            }) => true,
            Some(AllowlistEntry {
                expiration_ledger: Some(exp),
            }) => env.ledger().sequence() <= exp,
        }
    }

    /// Returns the raw allowlist entry stored for `address`, if any.
    ///
    /// An already-expired entry is still returned here (it is only ignored,
    /// not deleted) — use `is_allowed` for the effective status.
    pub fn get_allowlist_entry(env: Env, address: Address) -> Option<AllowlistEntry> {
        env.storage().persistent().get(&DataKey::Allowed(address))
    }

    /// Unified compliance check — returns `true` if `address` is on the
    /// allowlist, identical to calling [`is_allowed`].
    ///
    /// This entry point implements the shared `ComplianceCheck` interface
    /// (`is_compliant(address) -> bool`) so external contracts can call any
    /// of the three compliance primitives through the same pattern.
    ///
    /// Not affected by pause state — reads always succeed.
    pub fn is_compliant(env: Env, address: Address) -> bool {
        Self::is_allowed(env, address)
    }

    /// Pause all mutating operations. Admin-only.
    ///
    /// While paused:
    /// - `transfer` returns `Err(ContractPaused)`.
    /// - `add_to_allowlist`, `add_to_allowlist_delegated`, and
    ///   `remove_from_allowlist` return `Err(ContractPaused)`.
    ///
    /// The following are deliberately **not** blocked by pause so that an
    /// operator can always recover from an incident:
    /// - `unpause` — to resume normal operation.
    /// - `propose_admin` / `accept_admin` / `transfer_admin` — to rotate a
    ///   compromised key.
    /// - `set_compliance_officer` / `revoke_compliance_officer`.
    /// - Read-only functions (`is_allowed`, `is_paused`, `metadata`, …).
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Paused {
            admin: admin.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Unpause. Admin-only.
    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Unpaused {
            admin: admin.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Returns true if the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Transfer `amount` of the underlying token from `from` to `to`.
    ///
    /// Returns `Ok(false)` without forwarding if either party is not
    /// allowlisted, emitting a `Blocked` event for auditability. Checking an
    /// existing allowlist entry extends its TTL when it falls below the
    /// configured threshold.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<bool, Error> {
        if amount < 0 {
            return Err(Error::InvalidInput);
        }

        if Self::is_paused(env.clone()) {
            return Err(Error::ContractPaused);
        }

        from.require_auth();

        let from_allowed = Self::is_allowed_and_extend_ttl(&env, from.clone());
        let to_allowed = Self::is_allowed_and_extend_ttl(&env, to.clone());
        if !from_allowed || !to_allowed {
            Blocked { from, to, amount }.publish(&env);
            return Ok(false);
        }

        let token_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)?;
        extend_instance_ttl(&env);
        let token_client = token::Client::new(&env, &token_address);
        token_client.transfer(&from, &to, &amount);
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        admin.require_auth();
        Self::require_configured_admin(env, admin)
    }

    fn require_configured_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if stored_admin != *admin {
            return Err(Error::NotAuthorized);
        }
        extend_instance_ttl(env);
        Ok(())
    }

    fn is_allowed_and_extend_ttl(env: &Env, address: Address) -> bool {
        let key = DataKey::Allowed(address);
        let allowed = env.storage().persistent().get(&key).unwrap_or(false);
        if allowed {
            env.storage().persistent().extend_ttl(
                &key,
                ALLOWED_TTL_THRESHOLD,
                ALLOWED_TTL_EXTEND_TO,
            );
        }
        Err(Error::NotAuthorized)
    }

    fn reject_if_paused(env: &Env) -> Result<(), Error> {
        if env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
        {
            return Err(Error::ContractPaused);
        }
        Ok(())
    }

    /// Message signed by the delegated admin key:
    /// `allowlist-delegated-v1:<target>:<action>:<nonce>:<expiry>`.
    fn delegated_action_message(
        env: &Env,
        target: &Address,
        action: &Symbol,
        nonce: u64,
        expiry: u64,
    ) -> Bytes {
        let mut message = Bytes::new(env);
        message.append(&Bytes::from_slice(env, b"allowlist-delegated-v1:"));
        let target_str = target.to_string().to_string();
        message.append(&Bytes::from_slice(env, target_str.as_bytes()));
        message.push_back(b':');
        let action_str = action.to_string().to_string();
        message.append(&Bytes::from_slice(env, action_str.as_bytes()));
        message.push_back(b':');
        let nonce_str = alloc::format!("{nonce}");
        message.append(&Bytes::from_slice(env, nonce_str.as_bytes()));
        message.push_back(b':');
        let expiry_str = alloc::format!("{expiry}");
        message.append(&Bytes::from_slice(env, expiry_str.as_bytes()));
        message
    }
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod fuzz_test;

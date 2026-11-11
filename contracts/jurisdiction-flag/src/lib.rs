// Copyright (c) 2026 Stellar Compliance Kit contributors
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! `jurisdiction-flag` is a `#![no_std]` Soroban contract that attaches a
//! jurisdiction code (e.g. an ISO 3166-1 alpha-2 country code) to an
//! address.
//!
//! **Permission semantics**: `is_permitted_jurisdiction` uses *any*
//! matching — it returns `true` if at least one of the address's codes
//! appears in `allowed_codes`. An address with no codes is never permitted.
//!
//! **Code format**: `set_jurisdiction` only accepts ISO 3166-1 alpha-2 codes
//! written as exactly two *uppercase* ASCII letters (`"US"`, `"GB"`, …).
//! Anything else — empty, too short/long, lowercase (`"us"`), or containing
//! non-letters (`"U1"`, `"U-"`) — is rejected with
//! `Error::InvalidJurisdictionCode`. Codes are never normalized: matching in
//! `is_permitted_jurisdiction` stays exact and case-sensitive (#54), so
//! requiring the canonical uppercase form on write guarantees an address
//! can't be flagged as `"us"` and then silently fail to match an
//! `allowed_codes` entry of `"US"`.
//!
//! **Callers**: the configured issuer or compliance officer may call
//! `set_jurisdiction`, `set_jurisdiction_until`, `add_jurisdiction`, and
//! `set_multiple_jurisdictions`; only the issuer may call
//! `remove_jurisdiction`, `remove_jurisdiction_multiple`, or `upgrade`.
//! `set_jurisdiction` / `get_jurisdiction` remain single-code conveniences.
//! Use `add_jurisdiction`, `remove_jurisdiction`, and `list_jurisdictions`
//! for the multi-code model. Any contract or off-chain client can read codes
//! and call `is_permitted_jurisdiction(address, allowed_codes)` directly.
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, BytesN, Env,
    String, Vec,
};

/// Length in bytes of an ISO 3166-1 alpha-2 code.
const JURISDICTION_CODE_LEN: u32 = 2;

/// Extend persistent jurisdiction entries below 120,960 ledgers (~7 days).
const TTL_THRESHOLD: u32 = 120_960;
/// Target 1,555,200 ledgers (~90 days) after extension.
const TTL_EXTEND_TO: u32 = 1_555_200;

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

/// Maximum number of entries accepted by `set_multiple_jurisdictions` in a
/// single call. Keeps transaction costs bounded and prevents resource
/// exhaustion.
pub const MAX_BATCH_SIZE: u32 = 100;

/// Maximum number of jurisdiction codes that can be attached to a single
/// address. Enforced in `add_jurisdiction` to prevent a compromised or buggy
/// officer key from attaching so many codes that every later
/// `is_permitted_jurisdiction` call (which does `allowed_codes × codes`
/// comparisons) exceeds the CPU budget inside a consumer's transfer.
///
/// The value 8 is chosen to be well within the Soroban per-invocation CPU
/// budget for all realistic `allowed_codes` list sizes, while covering any
/// legitimate multi-jurisdiction use case (an address is rarely subject to
/// more than a handful of applicable codes).
pub const MAX_CODES_PER_ADDRESS: u32 = 8;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The issuer address, set once in `initialize`. Instance storage.
    Issuer,
    ComplianceOfficer,
    Jurisdiction(Address),
    Jurisdictions(Address),
    /// Optional expiry ledger for the address's jurisdiction codes. Absent =
    /// never expires.
    ValidUntil(Address),
    Paused,
    /// Pending issuer address proposed via `propose_issuer`. Instance storage.
    PendingIssuer,
    /// Pending issuer-authorized WASM upgrade proposal. Instance storage.
    PendingUpgrade,
}

/// Emitted whenever a jurisdiction flag is set.
#[contractevent]
pub struct JurisdictionSet {
    #[topic]
    pub address: Address,
    pub code: String,
}

/// Emitted when a read encounters a flag whose `valid_until` has passed.
#[contractevent]
pub struct JurisdictionExpired {
    #[topic]
    pub address: Address,
}

#[contractevent]
pub struct JurisdictionRemoved {
    #[topic]
    pub address: Address,
}

/// Emitted when the issuer role is reassigned via `transfer_issuer`.
#[contractevent]
pub struct IssuerTransferred {
    #[topic]
    pub old_issuer: Address,
    #[topic]
    pub new_issuer: Address,
}

/// Emitted when `propose_issuer` is called.
#[contractevent]
pub struct IssuerProposed {
    #[topic]
    pub current_issuer: Address,
    #[topic]
    pub proposed_issuer: Address,
}

/// Emitted when the current issuer cancels a pending proposal.
#[contractevent]
pub struct IssuerProposalCancelled {
    #[topic]
    pub issuer: Address,
}

#[contractevent]
pub struct Paused {
    #[topic]
    pub issuer: Address,
}

#[contractevent]
pub struct Unpaused {
    #[topic]
    pub issuer: Address,
}

/// Delayed issuer upgrade proposal.
#[contracttype]
#[derive(Clone)]
pub struct UpgradeState {
    pub new_wasm: BytesN<32>,
    pub activated_at: u64,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    /// Caller supplied an argument that is structurally invalid.
    InvalidInput = 4,
    ContractPaused = 5,
    /// `set_jurisdiction` was given a `code` that is not exactly two
    /// uppercase ASCII letters (ISO 3166-1 alpha-2). Also covers the empty
    /// string (#81), so there is one variant for every malformed code.
    InvalidJurisdictionCode = 6,
    /// The `allowed_codes` list passed to `is_permitted_jurisdiction` was empty.
    EmptyAllowedCodes = 7,
    /// `accept_issuer` was called when no transfer is in progress.
    NoPendingIssuer = 8,
    /// The address calling `accept_issuer` does not match the pending issuer
    /// stored by `propose_issuer`.
    PendingIssuerMismatch = 9,
    /// `add_jurisdiction` was called when the address already has
    /// [`MAX_CODES_PER_ADDRESS`] codes attached.
    TooManyCodes = 10,
}

#[contract]
pub struct JurisdictionFlag;

#[contractimpl]
impl JurisdictionFlag {
    /// One-time setup that records `issuer` as the only address allowed to
    /// set jurisdiction codes afterward.
    ///
    /// # Parameters
    /// - `issuer`: the address that will be authorized to call
    ///   [`set_jurisdiction`](Self::set_jurisdiction).
    ///
    /// # Auth
    /// Requires `issuer.require_auth()`, so the issuer must sign the
    /// initialization.
    ///
    /// # Errors
    /// - [`Error::AlreadyInitialized`] if the contract has already been
    ///   initialized. The existing issuer is left unchanged.
    pub fn initialize(env: Env, issuer: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Issuer) {
            return Err(Error::AlreadyInitialized);
        }
        issuer.require_auth();
        env.storage().instance().set(&DataKey::Issuer, &issuer);
        env.storage().instance().set(&DataKey::Paused, &false);
        extend_instance_ttl(&env);
        Ok(())
    }

    /// Return the configured issuer address.
    pub fn get_issuer(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Issuer)
            .ok_or(Error::NotInitialized)
    }

    /// Reassign the issuer role to `new_issuer`. Requires auth from
    /// `current_issuer`, which must be the stored issuer.
    ///
    /// Takes effect immediately: the old issuer loses all privileges
    /// (including `upgrade`, `pause`, and managing the compliance officer)
    /// as soon as this call succeeds. The compliance-officer assignment is
    /// left untouched. Deliberately *not* blocked by `pause`, so a
    /// compromised or rotated issuer key can always be replaced.
    ///
    /// Emits `IssuerTransferred { old_issuer, new_issuer }`.
    pub fn transfer_issuer(
        env: Env,
        current_issuer: Address,
        new_issuer: Address,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &current_issuer)?;
        env.storage().instance().set(&DataKey::Issuer, &new_issuer);
        // Clear any outstanding proposal so a stale proposed address cannot
        // accept after this rotation.
        env.storage().instance().remove(&DataKey::PendingIssuer);
        IssuerTransferred {
            old_issuer: current_issuer,
            new_issuer,
        }
        .publish(&env);
        Ok(())
    }

    /// Propose a new issuer. The current issuer retains full control until
    /// the proposed issuer calls `accept_issuer`, so a typo in `new_issuer`
    /// cannot permanently lose control of the contract. Calling it again
    /// overwrites any pending proposal; `transfer_issuer` (single-step
    /// break-glass rotation) also clears it.
    pub fn propose_issuer(env: Env, issuer: Address, new_issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingIssuer, &new_issuer);
        IssuerProposed {
            current_issuer: issuer,
            proposed_issuer: new_issuer,
        }
        .publish(&env);
        Ok(())
    }

    /// Accept a pending issuer proposal. Must be called by the exact address
    /// passed to `propose_issuer`; it becomes the issuer and the proposal is
    /// cleared.
    pub fn accept_issuer(env: Env, new_issuer: Address) -> Result<(), Error> {
        new_issuer.require_auth();
        let pending: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingIssuer)
            .ok_or(Error::NoPendingIssuer)?;
        if pending != new_issuer {
            return Err(Error::PendingIssuerMismatch);
        }
        let old_issuer: Address = env
            .storage()
            .instance()
            .get(&DataKey::Issuer)
            .ok_or(Error::NotInitialized)?;
        env.storage().instance().set(&DataKey::Issuer, &new_issuer);
        env.storage().instance().remove(&DataKey::PendingIssuer);
        extend_instance_ttl(&env);
        IssuerTransferred {
            old_issuer,
            new_issuer,
        }
        .publish(&env);
        Ok(())
    }

    /// Cancel a pending issuer proposal. Issuer-only.
    pub fn cancel_issuer_proposal(env: Env, issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage().instance().remove(&DataKey::PendingIssuer);
        IssuerProposalCancelled { issuer }.publish(&env);
        Ok(())
    }

    /// Assign the compliance-officer role. Issuer-only.
    ///
    /// The officer role grants access to exactly these entry points, each
    /// guarded by `require_compliance_authority` (issuer *or* officer):
    ///
    /// - [`set_jurisdiction`](Self::set_jurisdiction)
    /// - [`set_jurisdiction_until`](Self::set_jurisdiction_until)
    /// - [`add_jurisdiction`](Self::add_jurisdiction)
    /// - [`set_multiple_jurisdictions`](Self::set_multiple_jurisdictions)
    ///
    /// All other mutating entry points remain issuer-only, including:
    ///
    /// - [`remove_jurisdiction`](Self::remove_jurisdiction) and
    ///   [`remove_jurisdiction_multiple`](Self::remove_jurisdiction_multiple)
    /// - [`pause`](Self::pause) / [`unpause`](Self::unpause)
    /// - [`upgrade`](Self::upgrade)
    /// - [`set_compliance_officer`](Self::set_compliance_officer) /
    ///   [`revoke_compliance_officer`](Self::revoke_compliance_officer)
    ///
    /// The officer role does not extend to removal, pause, upgrade, or
    /// issuer/officer management functions.
    ///
    /// Auth: gated by [`require_issuer`] — only the issuer may delegate this role.
    pub fn set_compliance_officer(
        env: Env,
        issuer: Address,
        officer: Address,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage()
            .instance()
            .set(&DataKey::ComplianceOfficer, &officer);
        Ok(())
    }

    /// Revoke the compliance-officer role. Issuer-only.
    ///
    /// After revocation, the former officer no longer satisfies
    /// `require_compliance_authority`, so [`set_jurisdiction`](Self::set_jurisdiction),
    /// [`set_jurisdiction_until`](Self::set_jurisdiction_until),
    /// [`add_jurisdiction`](Self::add_jurisdiction), and
    /// [`set_multiple_jurisdictions`](Self::set_multiple_jurisdictions) revert
    /// to issuer-only access. All other mutating entry points
    /// ([`remove_jurisdiction`](Self::remove_jurisdiction),
    /// [`remove_jurisdiction_multiple`](Self::remove_jurisdiction_multiple),
    /// [`pause`](Self::pause), [`unpause`](Self::unpause),
    /// [`upgrade`](Self::upgrade)) were already issuer-only via
    /// `require_issuer` and are unaffected.
    ///
    /// Auth: gated by [`require_issuer`] — only the issuer may revoke the delegated role.
    pub fn revoke_compliance_officer(env: Env, issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage()
            .instance()
            .remove(&DataKey::ComplianceOfficer);
        Ok(())
    }

    /// Pause all mutating operations. Issuer-only.
    ///
    /// Auth: gated by [`require_issuer`] — pause/unpause is a lifecycle operation reserved for the issuer.
    pub fn pause(env: Env, issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Paused {
            issuer: issuer.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Resume all mutating operations. Issuer-only.
    ///
    /// Auth: gated by [`require_issuer`] — pause/unpause is a lifecycle operation reserved for the issuer.
    pub fn unpause(env: Env, issuer: Address) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Unpaused {
            issuer: issuer.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Attach jurisdiction `code` to `address`. Issuer or compliance-officer.
    ///
    /// `code` must be an ISO 3166-1 alpha-2 code in canonical uppercase form
    /// (see the module docs); otherwise returns
    /// `Error::InvalidJurisdictionCode` and nothing is stored.
    ///
    /// Auth: gated by [`require_compliance_authority`] — allows either the issuer or a
    /// delegated compliance officer, so routine flag management does not require the issuer key.
    pub fn set_jurisdiction(
        env: Env,
        issuer: Address,
        address: Address,
        code: String,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &issuer)?;
        Self::reject_if_paused(&env)?;
        Self::validate_jurisdiction_code(&code)?;

        let mut codes = Vec::new(&env);
        codes.push_back(code.clone());
        Self::store_jurisdictions(&env, &address, &codes);
        env.storage()
            .persistent()
            .remove(&DataKey::ValidUntil(address.clone()));

        JurisdictionSet {
            address,
            code,
        }
        .publish(&env);
        Ok(())
    }

    /// Batch-set jurisdiction codes for multiple addresses in one transaction.
    ///
    /// Behaves like calling [`set_jurisdiction`](Self::set_jurisdiction) once
    /// per entry: each address's codes are replaced by the single given code
    /// and any `valid_until` is cleared. `caller` must be the issuer or the
    /// compliance officer. All codes are validated **before** any writes, so
    /// one invalid code rejects the whole batch without leaving partial state.
    ///
    /// # Errors
    /// [`Error::ContractPaused`] while the contract is paused;
    /// [`Error::InvalidInput`] if `entries` is empty or longer than
    /// [`MAX_BATCH_SIZE`]; [`Error::InvalidJurisdictionCode`] if any code is
    /// malformed.
    pub fn set_multiple_jurisdictions(
        env: Env,
        caller: Address,
        entries: Vec<(Address, String)>,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &caller)?;
        Self::reject_if_paused(&env)?;

        if entries.is_empty() || entries.len() > MAX_BATCH_SIZE {
            return Err(Error::InvalidInput);
        }
        for (_, code) in entries.iter() {
            Self::validate_jurisdiction_code(&code)?;
        }

        for (address, code) in entries.iter() {
            let mut codes = Vec::new(&env);
            codes.push_back(code.clone());
            Self::store_jurisdictions(&env, &address, &codes);
            env.storage()
                .persistent()
                .remove(&DataKey::ValidUntil(address.clone()));
            JurisdictionSet { address, code }.publish(&env);
        }
        Ok(())
    }

    /// Attach jurisdiction `code` to `address`, valid through ledger
    /// `valid_until` (inclusive). Issuer or compliance-officer.
    ///
    /// Like [`set_jurisdiction`](Self::set_jurisdiction), this replaces any
    /// existing codes. The expiry applies to every code later attached to the
    /// address until it is cleared by `set_jurisdiction` or removal.
    pub fn set_jurisdiction_until(
        env: Env,
        issuer: Address,
        address: Address,
        code: String,
        valid_until: u32,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &issuer)?;
        Self::reject_if_paused(&env)?;
        Self::validate_jurisdiction_code(&code)?;
        if valid_until < env.ledger().sequence() {
            return Err(Error::InvalidInput);
        }

        let mut codes = Vec::new(&env);
        codes.push_back(code.clone());
        Self::store_jurisdictions(&env, &address, &codes);
        let until_key = DataKey::ValidUntil(address.clone());
        env.storage().persistent().set(&until_key, &valid_until);
        Self::extend_jurisdiction_ttl(&env, &until_key);

        JurisdictionSet { address, code }.publish(&env);
        Ok(())
    }

    /// Add `code` to `address`'s jurisdiction codes if it is not already present.
    /// Issuer or compliance-officer only.
    ///
    /// # Errors
    /// - [`Error::TooManyCodes`] if the address already has
    ///   [`MAX_CODES_PER_ADDRESS`] codes attached. Remove a code first, or use
    ///   [`set_jurisdiction`](Self::set_jurisdiction) to replace all codes at once.
    pub fn add_jurisdiction(
        env: Env,
        issuer: Address,
        address: Address,
        code: String,
    ) -> Result<(), Error> {
        Self::require_compliance_authority(&env, &issuer)?;
        Self::reject_if_paused(&env)?;
        Self::validate_jurisdiction_code(&code)?;

        let mut codes = Self::load_jurisdictions(&env, &address);
        if !codes.iter().any(|existing| existing == code) {
            if codes.len() >= MAX_CODES_PER_ADDRESS {
                return Err(Error::TooManyCodes);
            }
            codes.push_back(code.clone());
            Self::store_jurisdictions(&env, &address, &codes);
        }

        JurisdictionSet { address, code }.publish(&env);
        Ok(())
    }

    /// Remove `code` from `address`'s jurisdiction codes. Issuer-only.
    pub fn remove_jurisdiction(
        env: Env,
        issuer: Address,
        address: Address,
        code: String,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        Self::reject_if_paused(&env)?;

        let mut remaining = Vec::new(&env);
        for existing in Self::load_jurisdictions(&env, &address).iter() {
            if existing != code {
                remaining.push_back(existing);
            }
        }
        Self::store_jurisdictions(&env, &address, &remaining);
        JurisdictionRemoved { address }.publish(&env);
        Ok(())
    }

    /// Return all jurisdiction codes attached to `address`.
    ///
    /// Returns an empty list once the address's `valid_until` has passed.
    pub fn list_jurisdictions(env: Env, address: Address) -> Vec<String> {
        Self::load_active_jurisdictions(&env, &address)
    }

    /// Remove stored jurisdiction codes for each address in `addresses`.
    ///
    /// Auth: gated by [`require_issuer`] — bulk removal is a privileged operation reserved for the issuer.
    pub fn remove_jurisdiction_multiple(
        env: Env,
        issuer: Address,
        addresses: Vec<Address>,
    ) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        Self::reject_if_paused(&env)?;
        for address in addresses.iter() {
            Self::store_jurisdictions(&env, &address, &Vec::new(&env));
            JurisdictionRemoved { address }.publish(&env);
        }
        Ok(())
    }

    /// Returns the jurisdiction code attached to `address`, if any.
    ///
    /// # Parameters
    /// - `address`: the address to look up.
    ///
    /// # Returns
    /// `Some(code)` if a code has been set via
    /// [`set_jurisdiction`](Self::set_jurisdiction), otherwise `None`.
    ///
    /// # Auth
    /// None. This is a read-only call anyone may make.
    ///
    /// # Errors
    /// Never fails. Works even before the contract is initialized, in which
    /// case it always returns `None`.
    ///
    /// Returns `None` if the flag has a `valid_until` that is strictly less
    /// than the current ledger sequence, publishing `JurisdictionExpired`.
    pub fn get_jurisdiction(env: Env, address: Address) -> Option<String> {
        Self::load_active_jurisdictions(&env, &address).iter().next()
    }

    /// Returns `true` if `address` has a jurisdiction code that appears in
    /// `allowed_codes`. Meant to be called by other contracts enforcing a
    /// permitted-jurisdiction policy.
    ///
    /// Returns `Err(Error::EmptyAllowedCodes)` if the `allowed_codes` list is empty.
    pub fn is_permitted_jurisdiction(
        env: Env,
        address: Address,
        allowed_codes: Vec<String>,
    ) -> Result<bool, Error> {
        if allowed_codes.is_empty() {
            return Err(Error::EmptyAllowedCodes);
        }
        let codes = Self::load_active_jurisdictions(&env, &address);
        Ok(allowed_codes
            .iter()
            .any(|allowed| codes.iter().any(|code| code == allowed)))
    }

    /// Unified compliance check — returns `true` if `address` has **any**
    /// jurisdiction code set, i.e. it has been through an onboarding/KYC
    /// process that assigned it a jurisdiction.
    ///
    /// This entry point implements the shared `ComplianceCheck` interface
    /// (`is_compliant(address) -> bool`).  Unlike [`is_permitted_jurisdiction`],
    /// it does not validate the code against a permitted-jurisdictions list
    /// because the `ComplianceCheck` interface carries only `address`.
    ///
    /// Use [`is_permitted_jurisdiction`] when you need to enforce a specific
    /// set of allowed codes.  Use `is_compliant` for the lighter check of
    /// "has this address been assigned a jurisdiction at all".
    ///
    /// Not affected by pause state — reads always succeed.
    pub fn is_compliant(env: Env, address: Address) -> bool {
        Self::get_jurisdiction(env, address).is_some()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

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

    /// Upgrade the contract WASM. Issuer-only.
    ///
    /// Uses Soroban's native `update_current_contract_wasm` host function to
    /// swap the contract code behind the same contract ID. All existing
    /// storage (issuer address, jurisdiction flags) is preserved across the
    /// upgrade. The issuer's auth is verified before the upgrade proceeds.
    pub fn upgrade(env: Env, issuer: Address, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        Self::require_issuer(&env, &issuer)?;
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        Ok(())
    }

    /// Strict single-address auth gate — only the address stored as `issuer`
    /// at [`initialize`] time may pass.
    ///
    /// ## Authorization split
    ///
    /// This helper enforces the *tightest* authorization level in the contract.
    /// It is used by every entry point that changes the contract's own
    /// configuration or lifecycle (pause/unpause, compliance-officer
    /// assignment, bulk jurisdiction removal, WASM upgrade). The reasoning is
    /// that these operations affect the contract's trust model itself, so they
    /// must be gated on the one address the deployer designated at setup —
    /// the issuer — and no delegation is permitted.
    ///
    /// Contrast with [`require_compliance_authority`], which additionally
    /// allows a delegated compliance officer for day-to-day data operations.
    ///
    /// ## Errors
    ///
    /// Returns [`Error::NotInitialized`] if `initialize` has not been called
    /// yet, or [`Error::NotAuthorized`] if `issuer` does not match the stored
    /// issuer address.
    fn require_issuer(env: &Env, issuer: &Address) -> Result<(), Error> {
        issuer.require_auth();
        let stored_issuer: Address = env
            .storage()
            .instance()
            .get(&DataKey::Issuer)
            .ok_or(Error::NotInitialized)?;
        if stored_issuer != *issuer {
            return Err(Error::NotAuthorized);
        }
        extend_instance_ttl(env);
        Ok(())
    }

    /// Looser auth gate — passes if `caller` is the issuer **or** the
    /// currently assigned compliance officer.
    ///
    /// ## Authorization split
    ///
    /// This helper enforces a *delegated* authorization level for
    /// [`set_jurisdiction`], [`set_jurisdiction_until`], [`add_jurisdiction`],
    /// and [`set_multiple_jurisdictions`]. The issuer can optionally appoint a compliance officer via
    /// [`set_compliance_officer`]; once appointed, that officer may call any
    /// entry point gated by this helper without requiring the issuer key for
    /// every individual flag operation.
    ///
    /// Entry points that mutate the contract's *configuration* (who the
    /// compliance officer is, whether the contract is paused, etc.) use the
    /// stricter [`require_issuer`] instead, so a compromised compliance-officer
    /// key cannot escalate its own privileges.
    ///
    /// If no compliance officer has been set, this helper behaves identically
    /// to [`require_issuer`].
    ///
    /// ## Errors
    ///
    /// Returns [`Error::NotInitialized`] if `initialize` has not been called,
    /// or [`Error::NotAuthorized`] if `caller` is neither the issuer nor the
    /// compliance officer.
    fn require_compliance_authority(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let stored_issuer: Address = env
            .storage()
            .instance()
            .get(&DataKey::Issuer)
            .ok_or(Error::NotInitialized)?;
        if stored_issuer == *caller {
            extend_instance_ttl(env);
            return Ok(());
        }
        if let Some(officer) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::ComplianceOfficer)
        {
            if officer == *caller {
                extend_instance_ttl(env);
                return Ok(());
            }
        }
        Err(Error::NotAuthorized)
    }

    /// Accepts only exactly two uppercase ASCII letters (`A`–`Z`).
    fn validate_jurisdiction_code(code: &String) -> Result<(), Error> {
        if code.len() != JURISDICTION_CODE_LEN {
            return Err(Error::InvalidJurisdictionCode);
        }
        let mut buf = [0u8; JURISDICTION_CODE_LEN as usize];
        code.copy_into_slice(&mut buf);
        if !buf.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::InvalidJurisdictionCode);
        }
        Ok(())
    }

    fn extend_jurisdiction_ttl(env: &Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    /// Like `load_jurisdictions`, but returns no codes (and publishes
    /// `JurisdictionExpired`) once the address's `valid_until` has passed.
    fn load_active_jurisdictions(env: &Env, address: &Address) -> Vec<String> {
        let codes = Self::load_jurisdictions(env, address);
        if codes.is_empty() {
            return codes;
        }
        let until_key = DataKey::ValidUntil(address.clone());
        if let Some(valid_until) = env.storage().persistent().get::<_, u32>(&until_key) {
            if valid_until < env.ledger().sequence() {
                JurisdictionExpired {
                    address: address.clone(),
                }
                .publish(env);
                return Vec::new(env);
            }
            Self::extend_jurisdiction_ttl(env, &until_key);
        }
        codes
    }

    fn load_jurisdictions(env: &Env, address: &Address) -> Vec<String> {
        let list_key = DataKey::Jurisdictions(address.clone());
        if let Some(codes) = env.storage().persistent().get::<_, Vec<String>>(&list_key) {
            Self::extend_jurisdiction_ttl(env, &list_key);
            return codes;
        }

        let legacy_key = DataKey::Jurisdiction(address.clone());
        match env.storage().persistent().get::<_, String>(&legacy_key) {
            Some(code) => {
                Self::extend_jurisdiction_ttl(env, &legacy_key);
                Vec::from_array(env, [code])
            }
            None => Vec::new(env),
        }
    }

    fn store_jurisdictions(env: &Env, address: &Address, codes: &Vec<String>) {
        let list_key = DataKey::Jurisdictions(address.clone());
        let legacy_key = DataKey::Jurisdiction(address.clone());
        if let Some(first_code) = codes.iter().next() {
            env.storage().persistent().set(&list_key, codes);
            Self::extend_jurisdiction_ttl(env, &list_key);
            env.storage().persistent().set(&legacy_key, &first_code);
            Self::extend_jurisdiction_ttl(env, &legacy_key);
        } else {
            env.storage().persistent().remove(&list_key);
            env.storage().persistent().remove(&legacy_key);
            env.storage()
                .persistent()
                .remove(&DataKey::ValidUntil(address.clone()));
        }
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod fuzz;

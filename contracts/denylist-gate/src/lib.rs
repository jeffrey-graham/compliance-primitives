// Copyright (c) 2026 Stellar Compliance Kit contributors
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! `denylist-gate` is a `#![no_std]` Soroban contract that maintains a
//! standalone on-chain denylist.
//!
//! **Purpose**: give issuers a shared, independently auditable place to
//! record addresses that must never transact (sanctions hits, fraud, court
//! orders, etc.), decoupled from any single token contract's own storage.
//!
//! **Callers**: an `admin` address manages the denylist through
//! `add_to_denylist`/`remove_from_denylist`/`remove_multiple_from_denylist`. Other contracts — typically a
//! token's `transfer` function — call the read-only `check(address)` via a
//! cross-contract call before moving funds, so the denylist can be updated
//! without redeploying or touching the token contract itself.
//!
//! **Composition**: this contract is meant to be called into, not deployed
//! as a token itself. See `/examples/denylist-gate-consumer` for a worked
//! example of a token contract wiring `check()` into its `transfer` path.
//!
//! # Authorization model
//!
//! The contract starts in single-admin mode: `admin` (set in `initialize`)
//! authorizes every denylist mutation via `require_auth()`.
//!
//! Denylist entry mutations (`add_to_denylist`, `remove_from_denylist`, and
//! `remove_multiple_from_denylist`) also accept the compliance officer, if one
//! is set. Single and batch removal share the same authority check, so an
//! officer never needs admin rights to do a batch what it can do one by one.
//! Officer assignment, audit-log configuration, pause, and signer governance
//! remain admin-only.
//!
//! `initialize_multisig` (admin-only, callable once) additionally installs an
//! M-of-N signer set. From then on the signer set is governed as follows:
//!
//! - `add_signer` and `remove_signer` take the calling `caller` explicitly.
//!   Each call runs `caller.require_auth()` and then requires `caller` to be in
//!   the *current* signer set; any other address is rejected with
//!   `NotAuthorized`.
//! - A change does not take effect on a single signer's say-so. Each call
//!   records one timestamped approval from `caller` in persistent storage for
//!   that exact action (add X / remove X), bounded by [`APPROVAL_TTL_LEDGERS`].
//!   Approvals are per action, expire after [`APPROVAL_TTL_LEDGERS`] ledgers,
//!   and are de-duplicated per signer, so one signer calling twice still counts
//!   once. A signer can withdraw an unexecuted vote via `revoke_approval`, and
//!   active votes can be inspected via `pending_approvals`. The change is
//!   applied, and its pending approvals cleared, only once `threshold` distinct
//!   current signers hold non-expired approvals for it.
//! - Removals are validated before an approval is recorded: the set can never
//!   shrink to empty, nor below the threshold (`InvalidSignerSet` /
//!   `InvalidThreshold`). To remove a signer from a set that is already at its
//!   threshold, lower the threshold first.
//! - `set_threshold` goes through the same approval flow. Each call records an
//!   approval of `SetThreshold(n)`, applied once `threshold` distinct current
//!   signers have approved it. When applied, `n` must satisfy
//!   `1 <= n <= signers.len()` (`InvalidThreshold`), and a `ThresholdChanged`
//!   event is emitted. The threshold can therefore be raised or lowered, e.g. a
//!   3-of-3 set can lower to 2-of-3 and then remove a lost key.
#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, Address,
    BytesN, Env, String, Symbol, Vec,
};

/// Batch operations are capped to reduce the chance of a single invocation
/// exceeding Soroban instruction/resource limits. Set to 45 to fit comfortably
/// within Soroban's default per-invocation write-entry budget of ~50.
const MAX_BATCH_SIZE: u32 = 45;

/// Minimum upgrade review window, approximately one day at five seconds per ledger.
pub const MIN_UPGRADE_DELAY_LEDGERS: u32 = 17_280;

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The admin address, set once in `initialize`. Instance storage.
    Admin,
    /// Admin proposed by `propose_admin`, awaiting `accept_admin`. Instance storage.
    PendingAdmin,
    Paused,
    ComplianceOfficer,
    AuditLog,
    SignerSet,
    Denied(Address),
    PendingUpgrade,
    /// Approvals collected so far for one pending signer-set change (`Vec<PendingApproval>`).
    /// Stored in persistent storage with TTL [`APPROVAL_TTL_LEDGERS`].
    PendingSignerAction(SignerAction),
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

/// Number of ledgers for which a pending multisig signer approval remains
/// valid (~7 days at 5 seconds per ledger). Approvals older than this window
/// are treated as expired, and persistent `PendingSignerAction` entries are
/// given this TTL so abandoned proposals expire automatically without bloating
/// instance storage.
pub const APPROVAL_TTL_LEDGERS: u32 = 120_960;

/// A single signer's approval for a pending [`SignerAction`], stamped with the
/// ledger sequence at which it was recorded.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingApproval {
    pub signer: Address,
    pub created_at_ledger: u32,
}

/// The M-of-N signer set.
#[contracttype]
#[derive(Clone)]
pub struct SignerSet {
    pub signers: Vec<Address>,
    pub threshold: u32,
}

/// A signer-set change that needs `threshold` distinct approvals to apply.
#[contracttype]
#[derive(Clone)]
pub enum SignerAction {
    Add(Address),
    Remove(Address),
    SetThreshold(u32),
}

#[contractclient(name = "AuditLogClient")]
pub trait AuditLogInterface {
    fn record(env: Env, source: Address, kind: Symbol, subject: Address, detail: String);
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[contractevent]
pub struct DenyAdd {
    #[topic]
    pub address: Address,
}

#[contractevent]
pub struct DenyRemove {
    #[topic]
    pub address: Address,
}

/// Emitted when the optional audit-log write fails (paused, archived, or
/// reverting). The denylist mutation itself still succeeds; see
/// `docs/fail-open-fail-closed-audit.md`.
#[contractevent]
pub struct AuditLogFailed {
    pub kind: Symbol,
    #[topic]
    pub subject: Address,
}

#[contractevent]
pub struct MultisigInitialized {
    pub threshold: u32,
    pub signer_count: u32,
}

#[contractevent]
pub struct SignerApproved {
    #[topic]
    pub signer: Address,
}

#[contractevent]
pub struct SignerAdded {
    #[topic]
    pub signer: Address,
}

#[contractevent]
pub struct SignerRemoved {
    #[topic]
    pub signer: Address,
}

#[contractevent]
pub struct ThresholdChanged {
    pub old_threshold: u32,
    pub new_threshold: u32,
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
pub struct AdminProposalCancelled {
    #[topic]
    pub current: Address,
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

#[contractevent]
pub struct ComplianceOfficerSet {
    #[topic]
    pub officer: Address,
}

#[contractevent]
pub struct ComplianceOfficerRevoked {
    #[topic]
    pub officer: Address,
}

#[contractevent]
pub struct AuditLogSet {
    #[topic]
    pub audit_log: Address,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    ContractPaused = 4,
    BatchTooLarge = 5,
    ThresholdNotMet = 6,
    InvalidThreshold = 7,
    InvalidSignerSet = 8,
    SignerNotInSet = 9,
    UpgradeNotReady = 10,
    SignerAlreadyExists = 11,
    MultisigNotEnabled = 12,
    NoPendingAdmin = 13,
    PendingAdminMismatch = 14,
    UpgradeDelayTooShort = 15,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct DenylistGate;

#[contractimpl]
impl DenylistGate {
    /// One-time setup. Stores `admin` as the only address allowed to update
    /// the denylist afterward.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        Ok(())
    }

    /// Return the configured admin address.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Assign the compliance-officer role. Admin-only.
    pub fn set_compliance_officer(
        env: Env,
        admin: Address,
        officer: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::ComplianceOfficer, &officer);
        ComplianceOfficerSet {
            officer: officer.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Revoke the compliance-officer role. Admin-only.
    pub fn revoke_compliance_officer(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if let Some(officer) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::ComplianceOfficer)
        {
            env.storage().instance().remove(&DataKey::ComplianceOfficer);
            ComplianceOfficerRevoked { officer }.publish(&env);
        }
        Ok(())
    }

    /// Return the currently assigned compliance officer, if any.
    pub fn get_compliance_officer(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::ComplianceOfficer)
    }

    /// Configure the optional append-only audit log. Admin-only.
    pub fn set_audit_log(env: Env, admin: Address, audit_log: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::AuditLog, &audit_log);
        AuditLogSet {
            audit_log: audit_log.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Propose a new admin. The current admin remains active until the
    /// proposed admin calls `accept_admin`. Replaces any earlier proposal.
    pub fn propose_admin(env: Env, current_admin: Address, new_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        env.storage().instance().set(&DataKey::PendingAdmin, &new_admin);
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
        AdminTransferred { old_admin, new_admin }.publish(&env);
        Ok(())
    }

    /// Withdraw a pending admin proposal. Admin-only.
    pub fn cancel_admin_proposal(env: Env, current_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        if !env.storage().instance().has(&DataKey::PendingAdmin) {
            return Err(Error::NoPendingAdmin);
        }
        env.storage().instance().remove(&DataKey::PendingAdmin);
        AdminProposalCancelled {
            current: current_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Disconnect the audit log so denylist mutations stop calling it. Admin-only.
    pub fn clear_audit_log(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().remove(&DataKey::AuditLog);
        Ok(())
    }

    /// Return the currently configured audit-log address, if any.
    pub fn get_audit_log(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::AuditLog)
    }

    /// Reassign the admin role to `new_admin` immediately. Requires auth from
    /// `current_admin`, which must be the stored admin.
    ///
    /// Single-step, for emergency rotation: the old admin loses all privileges
    /// as soon as this call succeeds, and `new_admin`'s key is not checked
    /// first. Use `propose_admin` / `accept_admin` for routine handovers.
    /// Clears any pending proposal from `propose_admin`. Deliberately *not*
    /// blocked by `pause`, so a compromised or rotated admin key can always be
    /// replaced.
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
    /// required by issue #114, in contrast to `jurisdiction-flag::upgrade`, which
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

    /// Pause admin mutations (`add_to_denylist` / `remove_from_denylist`).
    /// `check()` continues to work while paused. Admin-only.
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Paused {
            admin: admin.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Resume admin mutations after a `pause`. Admin-only.
    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Unpaused {
            admin: admin.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Add `address` to the denylist. Admin or compliance-officer.
    ///
    /// Uses persistent storage with a long TTL to avoid fail-open archival.
    ///
    /// Persistent denylist entries receive an explicit long TTL because their
    /// reads can happen independently of instance-storage activity. Instance
    /// configuration keys do not need the same treatment: Soroban bumps the
    /// instance entry TTL when this contract is invoked.
    pub fn add_to_denylist(env: Env, admin: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_compliance_authority(&env, &admin)?;

        const MAX_TTL: u32 = 6_311_520;
        const THRESHOLD: u32 = MAX_TTL / 2;

        let key = DataKey::Denied(address.clone());
        env.storage().persistent().set(&key, &true);
        env.storage()
            .persistent()
            .extend_ttl(&key, THRESHOLD, MAX_TTL);

        DenyAdd {
            address: address.clone(),
        }
        .publish(&env);
        Self::record_audit(&env, Symbol::new(&env, "deny_add"), &address, "address added to denylist");
        Ok(())
    }

    /// Remove `address` from the denylist. Admin or compliance-officer.
    pub fn remove_from_denylist(env: Env, admin: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_compliance_authority(&env, &admin)?;
        env.storage()
            .persistent()
            .remove(&DataKey::Denied(address.clone()));
        DenyRemove {
            address: address.clone(),
        }
        .publish(&env);
        Self::record_audit(&env, Symbol::new(&env, "deny_remove"), &address, "address removed from denylist");
        Ok(())
    }

    /// Remove every address in `addresses` from the denylist. Admin or compliance-officer.
    pub fn remove_multiple_from_denylist(
        env: Env,
        admin: Address,
        addresses: Vec<Address>,
    ) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        Self::require_compliance_authority(&env, &admin)?;
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(Error::BatchTooLarge);
        }

        for address in addresses.iter() {
            env.storage()
                .persistent()
                .remove(&DataKey::Denied(address.clone()));
            DenyRemove { address }.publish(&env);
        }
        Ok(())
    }

    /// Returns `true` if `address` is clear to transact, i.e. it is NOT on
    /// the denylist. This is the function other contracts should call via
    /// cross-contract invocation before proceeding with a transfer.
    ///
    /// **Not** affected by pause state — reads always succeed.
    pub fn check(env: Env, address: Address) -> bool {
        !env.storage()
            .persistent()
            .get(&DataKey::Denied(address))
            .unwrap_or(false)
    }

    /// Unified compliance check — returns `true` if `address` is NOT on the
    /// denylist, identical to calling [`check`].
    ///
    /// This entry point implements the shared `ComplianceCheck` interface
    /// (`is_compliant(address) -> bool`) so external contracts can call any
    /// of the three compliance primitives through the same pattern.
    ///
    /// **Not** affected by pause state — reads always succeed.
    pub fn is_compliant(env: Env, address: Address) -> bool {
        Self::check(env, address)
    }

    /// Return whether `address` is currently stored on the denylist.
    pub fn is_denylisted(env: Env, address: Address) -> bool {
        !Self::check(env, address)
    }

    /// Install an M-of-N signer set. Admin-only; callable once.
    ///
    /// `signers` must be non-empty and free of duplicates, and `threshold`
    /// must be between 1 and `signers.len()`.
    pub fn initialize_multisig(
        env: Env,
        admin: Address,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if env.storage().instance().has(&DataKey::SignerSet) {
            return Err(Error::AlreadyInitialized);
        }
        if signers.is_empty() {
            return Err(Error::InvalidSignerSet);
        }
        if threshold == 0 || threshold > signers.len() {
            return Err(Error::InvalidThreshold);
        }
        for (i, signer) in signers.iter().enumerate() {
            for other in signers.iter().skip(i + 1) {
                if signer == other {
                    return Err(Error::InvalidSignerSet);
                }
            }
        }

        let signer_count = signers.len();
        env.storage()
            .instance()
            .set(&DataKey::SignerSet, &SignerSet { signers, threshold });
        MultisigInitialized {
            threshold,
            signer_count,
        }
        .publish(&env);
        Ok(())
    }

    /// Approve adding `new_signer` to the signer set. `caller` must authorize
    /// the call and be in the current signer set. The signer is added once
    /// `threshold` distinct signers have approved this exact action.
    pub fn add_signer(env: Env, caller: Address, new_signer: Address) -> Result<(), Error> {
        let signer_set = Self::require_signer(&env, &caller)?;
        if Self::contains(&signer_set.signers, &new_signer) {
            return Err(Error::SignerAlreadyExists);
        }
        Self::approve(&env, caller, SignerAction::Add(new_signer), signer_set)
    }

    /// Approve removing `signer_to_remove` from the signer set. `caller` must
    /// authorize the call and be in the current signer set. The signer is
    /// removed once `threshold` distinct signers have approved this exact
    /// action. The set may never become empty or smaller than the threshold.
    pub fn remove_signer(
        env: Env,
        caller: Address,
        signer_to_remove: Address,
    ) -> Result<(), Error> {
        let signer_set = Self::require_signer(&env, &caller)?;
        if !Self::contains(&signer_set.signers, &signer_to_remove) {
            return Err(Error::SignerNotInSet);
        }
        if signer_set.signers.len() <= 1 {
            return Err(Error::InvalidSignerSet);
        }
        if signer_set.threshold > signer_set.signers.len() - 1 {
            return Err(Error::InvalidThreshold);
        }
        Self::approve(&env, caller, SignerAction::Remove(signer_to_remove), signer_set)
    }

    /// Approve changing the signing threshold to `new_threshold`. `caller` must
    /// authorize the call and be in the current signer set. The threshold is
    /// changed once `threshold` distinct signers have approved this exact
    /// action; `new_threshold` must be between 1 and the signer count at that
    /// point.
    pub fn set_threshold(env: Env, caller: Address, new_threshold: u32) -> Result<(), Error> {
        let signer_set = Self::require_signer(&env, &caller)?;
        Self::approve(&env, caller, SignerAction::SetThreshold(new_threshold), signer_set)
    }

    /// The current signer set, or empty when multisig is not enabled.
    pub fn signers(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get::<_, SignerSet>(&DataKey::SignerSet)
            .map(|set| set.signers)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Withdraw `caller`'s pending approval for `action` before `threshold` is
    /// reached. `caller` must authorize the call and belong to the current
    /// signer set. If no active approvals remain for `action`, its persistent
    /// storage entry is removed immediately.
    pub fn revoke_approval(
        env: Env,
        caller: Address,
        action: SignerAction,
    ) -> Result<(), Error> {
        let signer_set = Self::require_signer(&env, &caller)?;
        let key = DataKey::PendingSignerAction(action);
        // Purge any pre-upgrade legacy instance-storage entry for this action.
        env.storage().instance().remove(&key);
        let stored: Vec<PendingApproval> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(&env));
        let now = env.ledger().sequence();
        let mut remaining = Vec::new(&env);
        for entry in stored.iter() {
            let not_expired = now.saturating_sub(entry.created_at_ledger) <= APPROVAL_TTL_LEDGERS;
            if entry.signer != caller
                && not_expired
                && Self::contains(&signer_set.signers, &entry.signer)
            {
                remaining.push_back(entry);
            }
        }
        if remaining.is_empty() {
            env.storage().persistent().remove(&key);
        } else {
            env.storage().persistent().set(&key, &remaining);
            env.storage()
                .persistent()
                .extend_ttl(&key, APPROVAL_TTL_LEDGERS, APPROVAL_TTL_LEDGERS);
        }
        Ok(())
    }

    /// Return the addresses of current signers whose approvals for `action` are
    /// still active (not expired under [`APPROVAL_TTL_LEDGERS`]).
    pub fn pending_approvals(env: Env, action: SignerAction) -> Vec<Address> {
        let Some(signer_set) = env
            .storage()
            .instance()
            .get::<_, SignerSet>(&DataKey::SignerSet)
        else {
            return Vec::new(&env);
        };
        let key = DataKey::PendingSignerAction(action);
        let stored: Vec<PendingApproval> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(&env));
        let now = env.ledger().sequence();
        let mut active = Vec::new(&env);
        for entry in stored.iter() {
            if now.saturating_sub(entry.created_at_ledger) <= APPROVAL_TTL_LEDGERS
                && Self::contains(&signer_set.signers, &entry.signer)
            {
                active.push_back(entry.signer);
            }
        }
        active
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn contains(signers: &Vec<Address>, address: &Address) -> bool {
        signers.iter().any(|s| s == *address)
    }

    /// Requires `caller`'s authorization and membership in the current signer
    /// set; returns that set.
    fn require_signer(env: &Env, caller: &Address) -> Result<SignerSet, Error> {
        caller.require_auth();
        let signer_set: SignerSet = env
            .storage()
            .instance()
            .get(&DataKey::SignerSet)
            .ok_or(Error::MultisigNotEnabled)?;
        if !Self::contains(&signer_set.signers, caller) {
            return Err(Error::NotAuthorized);
        }
        Ok(signer_set)
    }

    /// Records `caller`'s approval of `action` in persistent storage with a
    /// bounded TTL ([`APPROVAL_TTL_LEDGERS`]), prunes expired or non-member
    /// approvals, and applies `action` once `threshold` distinct signers have
    /// non-expired approvals.
    fn approve(
        env: &Env,
        caller: Address,
        action: SignerAction,
        mut signer_set: SignerSet,
    ) -> Result<(), Error> {
        let key = DataKey::PendingSignerAction(action.clone());
        // Purge any pre-upgrade legacy instance-storage entry for this action.
        env.storage().instance().remove(&key);
        let stored: Vec<PendingApproval> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));
        let now = env.ledger().sequence();

        // Keep only non-expired approvals from current signers, replacing any
        // prior approval from `caller` with a fresh timestamp.
        let mut approvals: Vec<PendingApproval> = Vec::new(env);
        for entry in stored.iter() {
            let not_expired = now.saturating_sub(entry.created_at_ledger) <= APPROVAL_TTL_LEDGERS;
            if entry.signer != caller
                && not_expired
                && Self::contains(&signer_set.signers, &entry.signer)
            {
                approvals.push_back(entry);
            }
        }
        approvals.push_back(PendingApproval {
            signer: caller.clone(),
            created_at_ledger: now,
        });
        SignerApproved { signer: caller }.publish(env);

        if approvals.len() < signer_set.threshold {
            env.storage().persistent().set(&key, &approvals);
            env.storage()
                .persistent()
                .extend_ttl(&key, APPROVAL_TTL_LEDGERS, APPROVAL_TTL_LEDGERS);
            return Ok(());
        }

        env.storage().persistent().remove(&key);
        match action {
            SignerAction::Add(new_signer) => {
                signer_set.signers.push_back(new_signer.clone());
                env.storage().instance().set(&DataKey::SignerSet, &signer_set);
                SignerAdded { signer: new_signer }.publish(env);
            }
            SignerAction::Remove(removed) => {
                let mut remaining = Vec::new(env);
                for signer in signer_set.signers.iter() {
                    if signer != removed {
                        remaining.push_back(signer);
                    }
                }
                signer_set.signers = remaining;
                env.storage().instance().set(&DataKey::SignerSet, &signer_set);
                SignerRemoved { signer: removed }.publish(env);
            }
            SignerAction::SetThreshold(new_threshold) => {
                if new_threshold == 0 || new_threshold > signer_set.signers.len() {
                    return Err(Error::InvalidThreshold);
                }
                let old_threshold = signer_set.threshold;
                signer_set.threshold = new_threshold;
                env.storage().instance().set(&DataKey::SignerSet, &signer_set);
                ThresholdChanged {
                    old_threshold,
                    new_threshold,
                }
                .publish(env);
            }
        }
        Ok(())
    }

    fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if stored_admin != *admin {
            return Err(Error::NotAuthorized);
        }
        Ok(())
    }

    fn require_compliance_authority(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if admin == *caller {
            return Ok(());
        }
        if env.storage().instance().get::<DataKey, Address>(&DataKey::ComplianceOfficer)
            == Some(caller.clone())
        {
            return Ok(());
        }
        Err(Error::NotAuthorized)
    }

    /// Best-effort audit write. A paused, archived, or reverting audit-log must
    /// not block denylist mutations (fail-open on the audit dependency), so
    /// failures are surfaced as an `AuditLogFailed` event instead of reverting.
    fn record_audit(env: &Env, kind: Symbol, subject: &Address, detail: &str) {
        if let Some(audit_log) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::AuditLog)
        {
            let written = AuditLogClient::new(env, &audit_log)
                .try_record(
                    &env.current_contract_address(),
                    &kind,
                    subject,
                    &String::from_str(env, detail),
                )
                .is_ok_and(|inner| inner.is_ok());
            if !written {
                AuditLogFailed {
                    kind,
                    subject: subject.clone(),
                }
                .publish(env);
            }
        }
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
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod fuzz_test;

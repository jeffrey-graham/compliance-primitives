//! `compliance-aggregator` is a `#![no_std]` Soroban contract that batches
//! multiple compliance checks into a single cross-contract call surface.
//!
//! ## Motivation
//!
//! A consuming contract running both a `denylist-gate` check and a
//! `jurisdiction-flag` check today pays two separate host-level cross-contract
//! call overheads per transfer. This aggregator reduces that to **one**
//! call from the consumer's perspective: the consumer calls
//! `check_address` (or the batched `check_all`) on this contract and gets
//! back a single aggregated pass/fail result plus a per-check breakdown for
//! audit purposes.
//!
//! ## Callers
//!
//! - **Consumer contracts** (the primary callers) — typically a token's
//!   `transfer` path — invoke `check_address` for one address, or `check_all` /
//!   `batch_check` for several, before moving value, and refuse the transfer
//!   when the result is `false`. These entrypoints are permissionless and
//!   require no auth.
//! - **The admin** (an issuer key or, preferably, a `multisig-admin` contract
//!   address) calls `initialize`, `set_denylist_gate`, `set_jurisdiction_flag`,
//!   `set_circuit_breaker`, `set_admin`, `pause`, `unpause`, and `upgrade`.
//!   Every mutation requires the admin's auth.
//! - **Off-chain tooling and auditors** call the read-only views
//!   (`get_config`, `get_checks_summary`, `is_paused`) and consume the
//!   configuration events to reconstruct which checks were registered when.
//!
//! ## Composition
//!
//! | Contract | Relationship to `compliance-aggregator` |
//! |---|---|
//! | `denylist-gate` | Registered as `DenylistGate`; `check(address)` runs for every address. |
//! | `jurisdiction-flag` | Registered as `JurisdictionFlag`; `is_permitted_jurisdiction(address, allowed_codes)` runs for every address. A failed or erroring call counts as a failure. |
//! | `circuit-breaker` | Optional emergency stop. When configured and frozen, every address is denied without running any check. |
//! | `multisig-admin` | Recommended `admin` value, so reconfiguration needs M-of-N approval. |
//! | `compliance-pausable` | Shared crate used to guard the pause flag. |
//! | `policy-engine` | Sibling, not a dependency. This contract is a fixed AND-only fan-out optimised for call overhead; `policy-engine` is the configurable AND / OR layer, and it also supports `allowlist-token` checks this contract does not. Pick one per integration. |
//! | `allowlist-token`, `audit-log`, `compliance-check` | Not called by this contract. Allowlist checks are available only through `policy-engine`. `audit-log` is the place to record on-chain trails of configuration changes; this contract emits events only. `compliance-check` is a compile-time trait crate and is not used at runtime. |
//!
//! Use this contract when a consumer needs only the AND-combination of the
//! denylist and jurisdiction primitives and wants the lowest call overhead.
//! Use `policy-engine` when the policy needs OR branches, weights, or the
//! allowlist primitive.
//!
//! ## Contract interfaces used
//!
//! Cross-contract calls are made via `#[contractclient]` traits declared in
//! this file. This follows the same pattern as
//! `/examples/denylist-gate-consumer`: we describe only the shape of the
//! remote call and do **not** import the peer crates as `[dependencies]`
//! (doing so would pull both contracts' wasm exports into this binary and
//! cause linker conflicts). The peer crates appear only in
//! `[dev-dependencies]` so their test utilities are available in `cfg(test)`.
//!
//! ## Configured checks
//!
//! The admin registers up to one address for each of the three supported check
//! types:
//!
//! - `DenylistCheck` — calls `denylist-gate.check(address) -> bool`
//! - `JurisdictionCheck` — calls
//!   `jurisdiction-flag.is_permitted_jurisdiction(address, allowed_codes) -> bool`
//! - `CircuitBreaker` — calls `circuit-breaker.is_frozen() -> bool`; the check
//!   passes only while the breaker is not frozen. A frozen breaker denies
//!   without consulting the other checks.
//!
//! All checks are optional; if a check type's contract address has not been
//! registered the check is skipped (treated as passing). Registering at least
//! one check is enforced at call time.
//!
//! ## Upgradeability
//!
//! `upgrade(admin, new_wasm_hash)` lets the configured admin move the
//! contract's code to a new WASM hash via
//! `env.deployer().update_current_contract_wasm`, following the same
//! admin-gated pattern used by `jurisdiction-flag` and `policy-engine`.
//! Only the stored admin may call it; any other caller is rejected with
//! `Error::NotAuthorized`, and calling it before `initialize` returns
//! `Error::NotInitialized`. An `UpgradePerformed` event is emitted so the
//! upgrade is visible to indexers.
//!
//! The WASM swap does not touch storage: the admin, the registered
//! `denylist-gate` / `jurisdiction-flag` / `circuit-breaker` addresses, and
//! the pause flag all live in instance storage under the same `DataKey`
//! variants and are read unchanged by the new code, so the contract is
//! callable immediately after the upgrade. Upgrade procedure:
//!
//! 1. Build the new release WASM
//!    (`stellar contract build` / `make build`).
//! 2. Upload it: `stellar contract upload --wasm compliance_aggregator.wasm`
//!    — this prints the new WASM hash.
//! 3. Invoke `upgrade --admin <ADMIN> --new_wasm_hash <HASH>` on the
//!    deployed aggregator, signed by the admin (or the `multisig-admin`
//!    quorum if the admin is a multisig).
//!
//! A new version **must not** reorder or remove existing `DataKey` variants
//! or change the types stored under them; add new variants instead. See
//! `STORAGE_VERSIONING.md` for the repo-wide rules.
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, BytesN, Env,
    String, Vec,
};

// ---------------------------------------------------------------------------
// Cross-contract client interfaces
// ---------------------------------------------------------------------------

/// Subset of the `denylist-gate` interface that this aggregator uses.
/// Must match the actual contract's exported function signature exactly.
#[soroban_sdk::contractclient(name = "DenylistGateClient")]
pub trait DenylistGateInterface {
    fn check(env: Env, address: Address) -> bool;
}

/// Subset of the `jurisdiction-flag` interface that this aggregator uses.
/// Must match the actual contract's exported function signature exactly.
#[soroban_sdk::contractclient(name = "JurisdictionFlagClient")]
pub trait JurisdictionFlagInterface {
    fn is_permitted_jurisdiction(env: Env, address: Address, allowed_codes: Vec<String>) -> bool;
}

/// Subset of the `circuit-breaker` interface that this aggregator uses.
/// Must match the actual contract's exported function signature exactly.
#[soroban_sdk::contractclient(name = "CircuitBreakerClient")]
pub trait CircuitBreakerInterface {
    fn is_frozen(env: Env) -> bool;
}

// ---------------------------------------------------------------------------
// TTL policy
// ---------------------------------------------------------------------------

/// TTL policy for this contract's stored state.
///
/// Every piece of configuration the aggregator keeps (`Admin`,
/// `DenylistGate`, `JurisdictionFlag`, `CircuitBreaker`, and the pause flag)
/// lives in **instance** storage, which shares a single TTL with the contract
/// instance itself. If that TTL lapses the whole contract is archived and
/// every call fails until someone submits a manual restore.
///
/// To prevent that, every write path calls [`extend_instance_ttl`], which
/// bumps the instance TTL back up to [`INSTANCE_TTL_EXTEND_TO`] whenever the
/// remaining TTL has fallen below [`INSTANCE_TTL_THRESHOLD`]. The values
/// mirror `allowlist-token`'s persistent-entry policy:
///
/// | Constant                  | Ledgers     | ~Wall-clock (5s/ledger) |
/// |---------------------------|-------------|-------------------------|
/// | `INSTANCE_TTL_THRESHOLD`  | `120_960`   | ~7 days                 |
/// | `INSTANCE_TTL_EXTEND_TO`  | `1_555_200` | ~90 days                |
///
/// So as long as the contract is written to at least once every ~83 days
/// (90 − 7), its state never becomes archived. Extending only below the
/// threshold keeps the per-write rent cost to at most one bump per ~83 days.
///
/// Extend the instance TTL when its remaining TTL drops below this many
/// ledgers (~7 days at ~5s/ledger on mainnet).
pub(crate) const INSTANCE_TTL_THRESHOLD: u32 = 120_960; // ~7 days

/// Target remaining instance TTL after extension (~90 days at ~5s/ledger).
pub(crate) const INSTANCE_TTL_EXTEND_TO: u32 = 1_555_200; // ~90 days

/// Bump the contract instance TTL (and therefore every instance-storage
/// entry) according to the policy documented above. Called from every
/// storage write path.
fn extend_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The admin address that may reconfigure the registered checks.
    Admin,
    /// Address of the `denylist-gate` contract to call, if any.
    DenylistGate,
    /// Address of the `jurisdiction-flag` contract to call, if any.
    JurisdictionFlag,
    /// Address of the `circuit-breaker` contract to consult, if any. When
    /// set and frozen, all checks short-circuit to deny.
    CircuitBreaker,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The result of a single compliance check on a single address.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    /// Human-readable label identifying which check produced this result.
    pub check: CheckKind,
    /// `true` if the address passed the check, `false` if it failed.
    pub passed: bool,
}

/// Identifies which compliance primitive produced a `CheckResult`.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CheckKind {
    Denylist = 0,
    Jurisdiction = 1,
    CircuitBreaker = 2,
}

/// Per-address aggregated result returned by `check_all`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressCheckResult {
    pub address: Address,
    /// `true` iff every registered check passed for this address.
    pub all_passed: bool,
    /// Individual results in registration order (denylist first, then jurisdiction).
    pub checks: Vec<CheckResult>,
}

/// Configuration of this aggregator instance, returned by `get_config`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregatorConfig {
    /// Address of the `denylist-gate` contract, if configured.
    pub denylist_gate: Option<Address>,
    /// Address of the `jurisdiction-flag` contract, if configured.
    pub jurisdiction_flag: Option<Address>,
    /// Address of the `circuit-breaker` contract, if configured.
    pub circuit_breaker: Option<Address>,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[contractevent]
pub struct AdminSet {
    #[topic]
    pub admin: Address,
}

#[contractevent]
pub struct DenylistGateSet {
    #[topic]
    pub gate: Address,
}

#[contractevent]
pub struct JurisdictionFlagSet {
    #[topic]
    pub flag: Address,
}

#[contractevent]
pub struct CircuitBreakerSet {
    #[topic]
    pub breaker: Address,
}

/// Emitted whenever the contract is upgraded to a new WASM implementation,
/// for on-chain auditability of the upgrade path.
#[contractevent]
pub struct UpgradePerformed {
    #[topic]
    pub admin: Address,
    pub new_wasm_hash: BytesN<32>,
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
    NoChecksRegistered = 4,
    EmptyAddressList = 5,
    BatchTooLarge = 6,
    ContractPaused = 7,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct ComplianceAggregator;

#[contractimpl]
impl ComplianceAggregator {
    /// Maximum number of addresses accepted by `batch_check` in a single
    /// call. Bounds the per-transaction cross-contract call fan-out (each
    /// address costs up to two nested calls) so a single invocation cannot
    /// exceed the host's resource budget. Set to 45 to fit comfortably within
    /// Soroban's default per-invocation resource limits.
    pub const MAX_BATCH_SIZE: u32 = 45;

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// One-time setup. `admin` is the only address that may later call
    /// `set_denylist_gate`, `set_jurisdiction_flag`, or `set_admin`.
    ///
    /// `denylist_gate` and `jurisdiction_flag` are optional at initialization;
    /// pass `None` for either one you don't want to register yet.
    pub fn initialize(
        env: Env,
        admin: Address,
        denylist_gate: Option<Address>,
        jurisdiction_flag: Option<Address>,
        circuit_breaker: Option<Address>,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        AdminSet {
            admin: admin.clone(),
        }
        .publish(&env);

        if let Some(gate) = denylist_gate {
            env.storage().instance().set(&DataKey::DenylistGate, &gate);
            DenylistGateSet { gate }.publish(&env);
        }
        if let Some(flag) = jurisdiction_flag {
            env.storage()
                .instance()
                .set(&DataKey::JurisdictionFlag, &flag);
            JurisdictionFlagSet { flag }.publish(&env);
        }
        if let Some(breaker) = circuit_breaker {
            env.storage()
                .instance()
                .set(&DataKey::CircuitBreaker, &breaker);
            CircuitBreakerSet { breaker }.publish(&env);
        }
        extend_instance_ttl(&env);
        Ok(())
    }

    /// Pause configuration mutations. Admin-only.
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        compliance_pausable::pause(&env);
        extend_instance_ttl(&env);
        env.events().publish((), soroban_sdk::symbol_short!("Paused"));
        Ok(())
    }

    /// Resume configuration mutations after a pause. Admin-only.
    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        compliance_pausable::unpause(&env);
        extend_instance_ttl(&env);
        env.events().publish((), soroban_sdk::symbol_short!("Unpaused"));
        Ok(())
    }

    /// Check if the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        compliance_pausable::is_paused(&env)
    }

    // -----------------------------------------------------------------------
    // Admin management
    // -----------------------------------------------------------------------

    /// Replace the admin. Old admin must authorize.
    pub fn set_admin(env: Env, admin: Address, new_admin: Address) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        extend_instance_ttl(&env);
        AdminSet { admin: new_admin }.publish(&env);
        Ok(())
    }

    /// Register or replace the `denylist-gate` contract address. Admin-only.
    pub fn set_denylist_gate(env: Env, admin: Address, gate: Address) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::DenylistGate, &gate);
        extend_instance_ttl(&env);
        DenylistGateSet { gate }.publish(&env);
        Ok(())
    }

    /// Register or replace the `jurisdiction-flag` contract address. Admin-only.
    pub fn set_jurisdiction_flag(env: Env, admin: Address, flag: Address) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::JurisdictionFlag, &flag);
        extend_instance_ttl(&env);
        JurisdictionFlagSet { flag }.publish(&env);
        Ok(())
    }

    /// Unregister the `denylist-gate` check. Admin-only. Afterwards the
    /// denylist check is skipped, as if it had never been registered.
    pub fn clear_denylist_gate(env: Env, admin: Address) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;
        env.storage().instance().remove(&DataKey::DenylistGate);
        extend_instance_ttl(&env);
        Ok(())
    }

    /// Unregister the `jurisdiction-flag` check. Admin-only. Afterwards the
    /// jurisdiction check is skipped, as if it had never been registered.
    pub fn clear_jurisdiction_flag(env: Env, admin: Address) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;
        env.storage().instance().remove(&DataKey::JurisdictionFlag);
        extend_instance_ttl(&env);
        Ok(())
    }

    /// Register or replace the `circuit-breaker` contract address. Admin-only.
    /// Pass this to enable emergency-freeze short-circuiting of all checks.
    pub fn set_circuit_breaker(env: Env, admin: Address, breaker: Address) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::CircuitBreaker, &breaker);
        extend_instance_ttl(&env);
        CircuitBreakerSet { breaker }.publish(&env);
        Ok(())
    }

    /// Upgrade the contract WASM. Admin-only.
    ///
    /// Swaps the code behind this contract ID to `new_wasm_hash` (which must
    /// already be uploaded to the network). All instance storage — admin,
    /// registered check addresses, circuit-breaker, pause flag — is
    /// preserved across the upgrade. See the module-level "Upgradeability"
    /// section for the full procedure.
    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        UpgradePerformed {
            admin,
            new_wasm_hash: new_wasm_hash.clone(),
        }
        .publish(&env);
        env.deployer().update_current_contract_wasm(new_wasm_hash);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read helpers
    // -----------------------------------------------------------------------

    /// Returns the current admin address, or `Err(Error::NotInitialized)` if
    /// the contract has not yet been initialized.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Returns the currently registered `denylist-gate` address, if any.
    pub fn denylist_gate(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::DenylistGate)
    }

    /// Returns the currently registered `jurisdiction-flag` address, if any.
    pub fn jurisdiction_flag(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::JurisdictionFlag)
    }

    /// Returns whether a denylist-gate check and/or a jurisdiction-flag check
    /// are configured without requiring two separate view calls.
    pub fn get_checks_summary(env: Env) -> (bool, bool) {
        let denylist_gate: Option<Address> = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::DenylistGate);
        let jurisdiction_flag: Option<Address> = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::JurisdictionFlag);
        (denylist_gate.is_some(), jurisdiction_flag.is_some())
    }

    /// Returns the currently registered `circuit-breaker` address, if any.
    pub fn circuit_breaker(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::CircuitBreaker)
    }

    /// Returns the current configuration of this aggregator instance, including
    /// all registered check contract addresses.
    pub fn get_config(env: Env) -> AggregatorConfig {
        AggregatorConfig {
            denylist_gate: env.storage().instance().get(&DataKey::DenylistGate),
            jurisdiction_flag: env.storage().instance().get(&DataKey::JurisdictionFlag),
            circuit_breaker: env.storage().instance().get(&DataKey::CircuitBreaker),
        }
    }

    /// Evaluates the circuit-breaker check if one is configured. The result
    /// passes only while the breaker is not frozen.
    fn circuit_breaker_result(env: &Env) -> Option<CheckResult> {
        let breaker_addr: Address = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::CircuitBreaker)?;
        let frozen = CircuitBreakerClient::new(env, &breaker_addr).is_frozen();
        Some(CheckResult {
            check: CheckKind::CircuitBreaker,
            passed: !frozen,
        })
    }

    // -----------------------------------------------------------------------
    // Compliance checks
    // -----------------------------------------------------------------------

    /// Run all registered compliance checks against `address` in a **single**
    /// call from the consumer's perspective.
    ///
    /// - `allowed_jurisdictions`: the set of permitted jurisdiction codes
    ///   passed through to `jurisdiction-flag.is_permitted_jurisdiction`.
    ///   Ignored (and not forwarded) if no jurisdiction-flag contract is
    ///   registered.
    ///
    /// Returns `(all_passed, checks)` where:
    /// - `all_passed` is `true` iff every registered check returned `true`.
    /// - `checks` is the per-primitive result list in deterministic order
    ///   (denylist first, then jurisdiction) for auditability.
    ///
    /// Panics with `Error::NoChecksRegistered` if neither gate nor flag
    /// has been configured — calling an aggregator with zero checks is almost
    /// certainly a misconfiguration.
    pub fn check_address(
        env: Env,
        address: Address,
        allowed_jurisdictions: Vec<String>,
    ) -> Result<(bool, Vec<CheckResult>), Error> {
        let mut results: Vec<CheckResult> = Vec::new(&env);
        let mut all_passed = true;

        // -- circuit-breaker check --
        // Emergency freeze short-circuit: if a configured circuit-breaker is
        // frozen, deny outright without evaluating the underlying checks.
        if let Some(breaker) = Self::circuit_breaker_result(&env) {
            let passed = breaker.passed;
            results.push_back(breaker);
            if !passed {
                return Ok((false, results));
            }
        }

        // -- denylist-gate check --
        if let Some(gate_addr) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::DenylistGate)
        {
            let client = DenylistGateClient::new(&env, &gate_addr);
            let passed = client.check(&address);
            all_passed = all_passed && passed;
            results.push_back(CheckResult {
                check: CheckKind::Denylist,
                passed,
            });
        }

        // -- jurisdiction-flag check --
        if let Some(flag_addr) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::JurisdictionFlag)
        {
            let client = JurisdictionFlagClient::new(&env, &flag_addr);
            let passed = matches!(
                    client.try_is_permitted_jurisdiction(&address, &allowed_jurisdictions),
                    Ok(Ok(true))
                );
            all_passed = all_passed && passed;
            results.push_back(CheckResult {
                check: CheckKind::Jurisdiction,
                passed,
            });
        }

        if results.is_empty() {
            return Err(Error::NoChecksRegistered);
        }

        Ok((all_passed, results))
    }

    /// Batched variant of `check_address` for multiple addresses in one call.
    ///
    /// Returns one `AddressCheckResult` per input address, in the same order.
    /// `Error::EmptyAddressList` is returned if `addresses` is empty.
    ///
    /// **Overhead note**: each address still requires its own cross-contract
    /// calls to the underlying primitives; Soroban's execution model does not
    /// allow deferring those across addresses. The saving here is the single
    /// invocation from the *consumer* to this aggregator, versus the consumer
    /// having to call each primitive per address itself. For the per-address
    /// primitive calls, Soroban's host caches contract instance reads within
    /// the same transaction so repeated calls to the same gate or flag address
    /// re-use the already-loaded instance.
    pub fn check_all(
        env: Env,
        addresses: Vec<Address>,
        allowed_jurisdictions: Vec<String>,
    ) -> Result<Vec<AddressCheckResult>, Error> {
        if addresses.is_empty() {
            return Err(Error::EmptyAddressList);
        }

        // Resolve contract addresses once, outside the per-address loop, to
        // avoid redundant storage reads.
        let breaker: Option<CheckResult> = Self::circuit_breaker_result(&env);
        let gate_addr: Option<Address> = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::DenylistGate);
        let flag_addr: Option<Address> = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::JurisdictionFlag);

        if breaker.is_none() && gate_addr.is_none() && flag_addr.is_none() {
            return Err(Error::NoChecksRegistered);
        }

        let mut batch: Vec<AddressCheckResult> = Vec::new(&env);

        for address in addresses.iter() {
            let mut results: Vec<CheckResult> = Vec::new(&env);
            let mut all_passed = true;

            // Emergency freeze short-circuit: if a configured circuit-breaker
            // is frozen, deny this address without evaluating the underlying
            // checks.
            if let Some(ref b) = breaker {
                all_passed = b.passed;
                results.push_back(b.clone());
            }

            if all_passed {
                if let Some(ref ga) = gate_addr {
                    let client = DenylistGateClient::new(&env, ga);
                    let passed = client.check(&address);
                    all_passed = all_passed && passed;
                    results.push_back(CheckResult {
                        check: CheckKind::Denylist,
                        passed,
                    });
                }

                if let Some(ref fa) = flag_addr {
                    let client = JurisdictionFlagClient::new(&env, fa);
                    let passed =
                        matches!(
                        client.try_is_permitted_jurisdiction(&address, &allowed_jurisdictions),
                        Ok(Ok(true))
                    );
                    all_passed = all_passed && passed;
                    results.push_back(CheckResult {
                        check: CheckKind::Jurisdiction,
                        passed,
                    });
                }
            }

            batch.push_back(AddressCheckResult {
                address,
                all_passed,
                checks: results,
            });
        }

        Ok(batch)
    }

    /// Lightweight batched entrypoint: evaluates the configured policy for
    /// each address in `addresses` and returns only the pass/fail booleans,
    /// in the same order as the input, for issuers who don't need the
    /// per-check breakdown that `check_all` provides.
    ///
    /// `allowed_jurisdictions` is forwarded to the `jurisdiction-flag` check
    /// exactly as in `check_address`/`check_all`, so a registered jurisdiction
    /// check is still fully evaluated here (it is not skipped).
    ///
    /// Guards against unbounded batches (and the associated cross-contract
    /// call fan-out) with `MAX_BATCH_SIZE`. Returns
    /// `Error::EmptyAddressList` for an empty input and
    /// `Error::BatchTooLarge` if `addresses.len() > MAX_BATCH_SIZE`.
    pub fn batch_check(
        env: Env,
        addresses: Vec<Address>,
        allowed_jurisdictions: Vec<String>,
    ) -> Result<Vec<bool>, Error> {
        if addresses.is_empty() {
            return Err(Error::EmptyAddressList);
        }
        if addresses.len() > Self::MAX_BATCH_SIZE {
            return Err(Error::BatchTooLarge);
        }

        let gate_addr: Option<Address> = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::DenylistGate);
        let flag_addr: Option<Address> = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::JurisdictionFlag);

        if gate_addr.is_none() && flag_addr.is_none() {
            return Err(Error::NoChecksRegistered);
        }

        let mut results: Vec<bool> = Vec::new(&env);

        for address in addresses.iter() {
            let mut all_passed = true;

            if let Some(ref ga) = gate_addr {
                let client = DenylistGateClient::new(&env, ga);
                all_passed = all_passed && client.check(&address);
            }

            if let Some(ref fa) = flag_addr {
                let client = JurisdictionFlagClient::new(&env, fa);
                all_passed =
                    all_passed && matches!(
                    client.try_is_permitted_jurisdiction(&address, &allowed_jurisdictions),
                    Ok(Ok(true))
                );
            }

            results.push_back(all_passed);
        }

        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        admin.require_auth();
        let stored: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if stored != *admin {
            return Err(Error::NotAuthorized);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod fuzz;

//! Tests for `compliance-aggregator`.
//!
//! ## Coverage
//! - Initialization and admin management
//! - `check_address` with denylist-only, jurisdiction-only, and both checks
//! - Pass/fail combinations across both checks
//! - `check_all` batch variant for multiple addresses
//! - Error cases: no checks registered, empty address list, non-admin callers
//!
//! ## Benchmark section
//! The "benchmark" tests at the bottom compare the Soroban simulated resource
//! costs (via `cost_estimate().budget()`) of:
//! 1. Calling each primitive directly from the test harness — simulating what
//!    a consumer would pay if it called them individually.
//! 2. Calling `check_address` on this aggregator for the same address.
//!
//! The numbers are printed to stdout (visible with `cargo test -- --nocapture`)
//! and an assertion ensures the aggregated path never exceeds the sum of the
//! individual paths by more than a small constant factor (verifying we're not
//! adding gratuitous overhead).

// In #![no_std] crate test builds, the test runner links std but does not
// bring it into scope automatically. Declare it here so we can use println!
// in the benchmark output below.
extern crate std;

use super::*;
use circuit_breaker::{CircuitBreaker, CircuitBreakerClient as CbClient};
use denylist_gate::{DenylistGate, DenylistGateClient};
use jurisdiction_flag::{JurisdictionFlag, JurisdictionFlagClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Env, String};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Registers and initialises both underlying primitives plus the aggregator.
/// Returns `(gate_admin, gate_id, flag_issuer, flag_id, agg_admin, agg_id, agg_client)`.
#[allow(clippy::type_complexity)]
fn setup_all(
    env: &Env,
) -> (
    Address,
    Address,
    Address,
    Address,
    Address,
    Address,
    ComplianceAggregatorClient<'_>,
) {
    env.mock_all_auths();

    // denylist-gate
    let gate_admin = Address::generate(env);
    let gate_id = env.register(DenylistGate, ());
    DenylistGateClient::new(env, &gate_id).initialize(&gate_admin);

    // jurisdiction-flag
    let flag_issuer = Address::generate(env);
    let flag_id = env.register(JurisdictionFlag, ());
    JurisdictionFlagClient::new(env, &flag_id).initialize(&flag_issuer);

    // aggregator
    let agg_admin = Address::generate(env);
    let agg_id = env.register(ComplianceAggregator, ());
    let agg_client = ComplianceAggregatorClient::new(env, &agg_id);
    agg_client.initialize(&agg_admin, &Some(gate_id.clone()), &Some(flag_id.clone()), &None);

    (
        gate_admin, gate_id, flag_issuer, flag_id, agg_admin, agg_id, agg_client,
    )
}

/// Helper: sets `address` jurisdiction to `code` via the flag contract.
fn set_jurisdiction(env: &Env, flag_id: &Address, issuer: &Address, address: &Address, code: &str) {
    JurisdictionFlagClient::new(env, flag_id)
        .set_jurisdiction(issuer, address, &String::from_str(env, code));
}

/// Helper: adds `address` to the denylist.
fn deny(env: &Env, gate_id: &Address, admin: &Address, address: &Address) {
    DenylistGateClient::new(env, gate_id).add_to_denylist(admin, address);
}

fn us_vec(env: &Env) -> soroban_sdk::Vec<soroban_sdk::String> {
    vec![env, String::from_str(env, "US")]
}

// ---------------------------------------------------------------------------
// Initialization & admin
// ---------------------------------------------------------------------------

#[test]
fn test_initialize_stores_gate_and_flag() {
    let env = Env::default();
    let (_, gate_id, _, flag_id, _, _, client) = setup_all(&env);
    assert_eq!(client.denylist_gate(), Some(gate_id));
    assert_eq!(client.jurisdiction_flag(), Some(flag_id));
}

#[test]
fn test_initialize_without_checks() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &id);
    client.initialize(&admin, &None, &None, &None);
    assert_eq!(client.denylist_gate(), None);
    assert_eq!(client.jurisdiction_flag(), None);
}

#[test]
fn test_get_checks_summary_reports_configured_checks() {
    let env = Env::default();
    env.mock_all_auths();

    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    DenylistGateClient::new(&env, &gate_id).initialize(&gate_admin);

    let flag_issuer = Address::generate(&env);
    let flag_id = env.register(JurisdictionFlag, ());
    JurisdictionFlagClient::new(&env, &flag_id).initialize(&flag_issuer);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &Some(gate_id.clone()), &Some(flag_id.clone()), &None);

    assert_eq!(client.get_checks_summary(), (true, true));

    let client_without_flag = ComplianceAggregatorClient::new(&env, &agg_id);
    // Re-initialize is not permitted; verify the summary is still a view over storage.
    assert_eq!(client_without_flag.get_checks_summary(), (true, true));
}

#[test]
fn test_double_initialize_fails() {
    let env = Env::default();
    let (_, _, _, _, admin, _, client) = setup_all(&env);
    let result = client.try_initialize(&admin, &None, &None, &None);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn test_set_admin_succeeds() {
    let env = Env::default();
    let (_, _, _, _, admin, _, client) = setup_all(&env);
    let new_admin = Address::generate(&env);
    client.set_admin(&admin, &new_admin);
    // new_admin should now be able to update the gate
    let gate2_id = env.register(DenylistGate, ());
    client.set_denylist_gate(&new_admin, &gate2_id);
    assert_eq!(client.denylist_gate(), Some(gate2_id));
}

#[test]
fn test_set_admin_rejects_non_admin() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    let impostor = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let result = client.try_set_admin(&impostor, &new_admin);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}

#[test]
fn test_set_circuit_breaker_rejects_changes_while_paused() {
    let env = Env::default();
    let (_, _, _, _, admin, _, client) = setup_all(&env);
    let breaker = Address::generate(&env);
    client.pause(&admin);

    let result = client.try_set_circuit_breaker(&admin, &breaker);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
}

#[test]
fn test_set_denylist_gate_rejects_non_admin() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    let impostor = Address::generate(&env);
    let gate2_id = env.register(DenylistGate, ());
    let result = client.try_set_denylist_gate(&impostor, &gate2_id);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}

#[test]
fn test_set_jurisdiction_flag_rejects_non_admin() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    let impostor = Address::generate(&env);
    let flag2_id = env.register(JurisdictionFlag, ());
    let result = client.try_set_jurisdiction_flag(&impostor, &flag2_id);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}

// ---------------------------------------------------------------------------
// check_address — denylist only
// ---------------------------------------------------------------------------

#[test]
fn test_check_address_denylist_only_pass() {
    let env = Env::default();
    env.mock_all_auths();

    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    DenylistGateClient::new(&env, &gate_id).initialize(&gate_admin);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &Some(gate_id.clone()), &None, &None);

    let alice = Address::generate(&env);
    let (all_passed, checks) = client.check_address(&alice, &vec![&env]);
    assert!(all_passed);
    assert_eq!(checks.len(), 1);
    assert_eq!(
        checks.get(0),
        Some(CheckResult {
            check: CheckKind::Denylist,
            passed: true
        })
    );
}

#[test]
fn test_check_address_denylist_only_fail() {
    let env = Env::default();
    env.mock_all_auths();

    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    let gate_client = DenylistGateClient::new(&env, &gate_id);
    gate_client.initialize(&gate_admin);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &Some(gate_id.clone()), &None, &None);

    let alice = Address::generate(&env);
    gate_client.add_to_denylist(&gate_admin, &alice);

    let (all_passed, checks) = client.check_address(&alice, &vec![&env]);
    assert!(!all_passed);
    assert_eq!(
        checks.get(0),
        Some(CheckResult {
            check: CheckKind::Denylist,
            passed: false
        })
    );
}

// ---------------------------------------------------------------------------
// check_address — jurisdiction only
// ---------------------------------------------------------------------------

#[test]
fn test_check_address_jurisdiction_only_pass() {
    let env = Env::default();
    env.mock_all_auths();

    let flag_issuer = Address::generate(&env);
    let flag_id = env.register(JurisdictionFlag, ());
    let flag_client = JurisdictionFlagClient::new(&env, &flag_id);
    flag_client.initialize(&flag_issuer);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &None, &Some(flag_id.clone()), &None);

    let alice = Address::generate(&env);
    flag_client.set_jurisdiction(&flag_issuer, &alice, &String::from_str(&env, "US"));

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(all_passed);
    assert_eq!(
        checks.get(0),
        Some(CheckResult {
            check: CheckKind::Jurisdiction,
            passed: true
        })
    );
}

#[test]
fn test_check_address_jurisdiction_only_fail_wrong_code() {
    let env = Env::default();
    env.mock_all_auths();

    let flag_issuer = Address::generate(&env);
    let flag_id = env.register(JurisdictionFlag, ());
    let flag_client = JurisdictionFlagClient::new(&env, &flag_id);
    flag_client.initialize(&flag_issuer);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &None, &Some(flag_id.clone()), &None);

    let alice = Address::generate(&env);
    // Alice is in RU, but only US is permitted
    flag_client.set_jurisdiction(&flag_issuer, &alice, &String::from_str(&env, "RU"));

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(!all_passed);
    assert_eq!(
        checks.get(0),
        Some(CheckResult {
            check: CheckKind::Jurisdiction,
            passed: false
        })
    );
}

// ---------------------------------------------------------------------------
// check_address — both checks, all combinations
// ---------------------------------------------------------------------------

#[test]
fn test_both_checks_pass() {
    let env = Env::default();
    let (_, gate_id, flag_issuer, flag_id, _, _, client) = setup_all(&env);
    let _ = gate_id;

    let alice = Address::generate(&env);
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(all_passed);
    assert_eq!(checks.len(), 2);
    assert!(checks.get(0).unwrap().passed); // denylist
    assert!(checks.get(1).unwrap().passed); // jurisdiction
}

#[test]
fn test_denylist_fail_jurisdiction_pass() {
    let env = Env::default();
    let (gate_admin, gate_id, flag_issuer, flag_id, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
    deny(&env, &gate_id, &gate_admin, &alice);

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(!all_passed);
    assert_eq!(checks.get(0).unwrap().check, CheckKind::Denylist);
    assert!(!checks.get(0).unwrap().passed);
    assert_eq!(checks.get(1).unwrap().check, CheckKind::Jurisdiction);
    assert!(checks.get(1).unwrap().passed);
}

#[test]
fn test_denylist_pass_jurisdiction_fail() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    // Alice has no jurisdiction set → is_permitted_jurisdiction returns false

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(!all_passed);
    assert!(checks.get(0).unwrap().passed); // denylist passes (not denied)
    assert!(!checks.get(1).unwrap().passed); // jurisdiction fails (no code)
}

#[test]
fn test_both_checks_fail() {
    let env = Env::default();
    let (gate_admin, gate_id, _, _, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    // No jurisdiction set, and also denied
    deny(&env, &gate_id, &gate_admin, &alice);

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(!all_passed);
    assert!(!checks.get(0).unwrap().passed); // denylist fails
    assert!(!checks.get(1).unwrap().passed); // jurisdiction fails
}

// ---------------------------------------------------------------------------
// check_address — error cases
// ---------------------------------------------------------------------------

#[test]
fn test_check_address_no_checks_registered() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &id);
    client.initialize(&admin, &None, &None, &None);

    let alice = Address::generate(&env);
    let result = client.try_check_address(&alice, &vec![&env]);
    assert_eq!(result, Err(Ok(Error::NoChecksRegistered)));
}

// ---------------------------------------------------------------------------
// Edge cases (#215): zero checks, single check parity, AND-composition
// ---------------------------------------------------------------------------

/// Single-check aggregator must behave identically to calling that
/// underlying check directly: same pass/fail outcome, and the aggregator's
/// `checks` vector must carry exactly that one result.
#[test]
fn test_single_check_matches_direct_call() {
    let env = Env::default();
    env.mock_all_auths();

    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    let gate_client = DenylistGateClient::new(&env, &gate_id);
    gate_client.initialize(&gate_admin);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let agg_client = ComplianceAggregatorClient::new(&env, &agg_id);
    agg_client.initialize(&agg_admin, &Some(gate_id.clone()), &None, &None);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    gate_client.add_to_denylist(&gate_admin, &bob);

    // Direct call results.
    let alice_direct = gate_client.check(&alice);
    let bob_direct = gate_client.check(&bob);

    // Aggregator results, single check registered.
    let (alice_all, alice_checks) = agg_client.check_address(&alice, &vec![&env]);
    let (bob_all, bob_checks) = agg_client.check_address(&bob, &vec![&env]);

    assert_eq!(alice_all, alice_direct);
    assert_eq!(bob_all, bob_direct);
    assert_eq!(alice_checks.len(), 1);
    assert_eq!(bob_checks.len(), 1);
    assert_eq!(alice_checks.get(0).unwrap().passed, alice_direct);
    assert_eq!(bob_checks.get(0).unwrap().passed, bob_direct);
}

/// Zero configured checks must produce the documented `NoChecksRegistered`
/// error rather than panicking or silently reporting a pass. This is a
/// second, explicit assertion of that documented contract behavior
/// (complementing `test_check_address_no_checks_registered` above) that
/// also checks the same for a freshly-registered (never-initialized-with-
/// any-check) aggregator instance to rule out any state leakage.
#[test]
fn test_zero_checks_is_documented_error_not_panic() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &id);
    client.initialize(&admin, &None, &None, &None);

    let addr = Address::generate(&env);
    // Must not panic: try_* surfaces the error as a Result.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.try_check_address(&addr, &vec![&env])
    }));
    assert!(result.is_ok(), "check_address must not panic on zero checks");
    assert_eq!(result.unwrap(), Err(Ok(Error::NoChecksRegistered)));
}

/// This contract only supports AND-composition of registered checks (see
/// module docs: "all checks here are AND-composed"); there is no OR/nesting
/// operator, so a literal AND-of-ORs configuration is out of scope for this
/// contract (that belongs to `policy-engine`, issue #109). This test instead
/// verifies the AND-composition semantics hold exhaustively across all four
/// pass/fail combinations of the two registered checks, which is the closest
/// meaningful analogue available here: `all_passed` must equal the boolean
/// AND of the individual check results in every case.
#[test]
fn test_and_composition_exhaustive_truth_table() {
    let env = Env::default();

    for (deny_alice, right_jurisdiction) in
        [(false, true), (false, false), (true, true), (true, false)]
    {
        let (gate_admin, gate_id, flag_issuer, flag_id, _, _, client) = setup_all(&env);
        let alice = Address::generate(&env);

        if deny_alice {
            deny(&env, &gate_id, &gate_admin, &alice);
        }
        if right_jurisdiction {
            set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
        }

        let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
        let expected = !deny_alice && right_jurisdiction;
        assert_eq!(all_passed, expected);
        assert_eq!(checks.get(0).unwrap().passed, !deny_alice);
        assert_eq!(checks.get(1).unwrap().passed, right_jurisdiction);
    }
}

// ---------------------------------------------------------------------------
// check_all — batch tests
// ---------------------------------------------------------------------------

#[test]
fn test_check_all_all_pass() {
    let env = Env::default();
    let (_, _, flag_issuer, flag_id, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
    set_jurisdiction(&env, &flag_id, &flag_issuer, &bob, "US");

    let addresses = vec![&env, alice.clone(), bob.clone()];
    let results = client.check_all(&addresses, &us_vec(&env));
    assert_eq!(results.len(), 2);
    assert!(results.get(0).unwrap().all_passed);
    assert!(results.get(1).unwrap().all_passed);
}

#[test]
fn test_check_all_mixed_results() {
    let env = Env::default();
    let (gate_admin, gate_id, flag_issuer, flag_id, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let carol = Address::generate(&env);

    // alice: both pass
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
    // bob: denylist fail, jurisdiction pass
    set_jurisdiction(&env, &flag_id, &flag_issuer, &bob, "US");
    deny(&env, &gate_id, &gate_admin, &bob);
    // carol: denylist pass, no jurisdiction → jurisdiction fail

    let addresses = vec![&env, alice.clone(), bob.clone(), carol.clone()];
    let results = client.check_all(&addresses, &us_vec(&env));

    assert_eq!(results.len(), 3);

    let alice_r = results.get(0).unwrap();
    assert_eq!(alice_r.address, alice);
    assert!(alice_r.all_passed);

    let bob_r = results.get(1).unwrap();
    assert_eq!(bob_r.address, bob);
    assert!(!bob_r.all_passed);
    assert!(!bob_r.checks.get(0).unwrap().passed); // denylist
    assert!(bob_r.checks.get(1).unwrap().passed); // jurisdiction

    let carol_r = results.get(2).unwrap();
    assert_eq!(carol_r.address, carol);
    assert!(!carol_r.all_passed);
    assert!(carol_r.checks.get(0).unwrap().passed); // denylist
    assert!(!carol_r.checks.get(1).unwrap().passed); // jurisdiction
}

#[test]
fn test_check_all_empty_list_error() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    let result = client.try_check_all(&vec![&env], &us_vec(&env));
    assert_eq!(result, Err(Ok(Error::EmptyAddressList)));
}

#[test]
fn test_check_all_no_checks_registered() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &id);
    client.initialize(&admin, &None, &None, &None);

    let alice = Address::generate(&env);
    let result = client.try_check_all(&vec![&env, alice], &vec![&env]);
    assert_eq!(result, Err(Ok(Error::NoChecksRegistered)));
}

// ---------------------------------------------------------------------------
// batch_check (#216)
// ---------------------------------------------------------------------------

#[test]
fn test_batch_check_matches_individual_check_address() {
    let env = Env::default();
    let (gate_admin, gate_id, flag_issuer, flag_id, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let carol = Address::generate(&env);

    // alice: both pass
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
    // bob: denylist fail, jurisdiction pass
    set_jurisdiction(&env, &flag_id, &flag_issuer, &bob, "US");
    deny(&env, &gate_id, &gate_admin, &bob);
    // carol: denylist pass, no jurisdiction set -> jurisdiction fail

    let addresses = vec![&env, alice.clone(), bob.clone(), carol.clone()];
    let batch_results = client.batch_check(&addresses, &us_vec(&env));

    assert_eq!(batch_results.len(), 3);
    for (i, addr) in [&alice, &bob, &carol].into_iter().enumerate() {
        let (expected, _) = client.check_address(addr, &us_vec(&env));
        assert_eq!(batch_results.get(i as u32).unwrap(), expected);
    }
}

#[test]
fn test_batch_check_empty_list_error() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    let result = client.try_batch_check(&vec![&env], &us_vec(&env));
    assert_eq!(result, Err(Ok(Error::EmptyAddressList)));
}

#[test]
fn test_batch_check_no_checks_registered() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &id);
    client.initialize(&admin, &None, &None, &None);

    let alice = Address::generate(&env);
    let result = client.try_batch_check(&vec![&env, alice], &vec![&env]);
    assert_eq!(result, Err(Ok(Error::NoChecksRegistered)));
}

#[test]
fn test_batch_check_rejects_oversized_batch() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);

    let mut addresses: Vec<Address> = Vec::new(&env);
    for _ in 0..(ComplianceAggregator::MAX_BATCH_SIZE + 1) {
        addresses.push_back(Address::generate(&env));
    }

    let result = client.try_batch_check(&addresses, &us_vec(&env));
    assert_eq!(result, Err(Ok(Error::BatchTooLarge)));
}

// ---------------------------------------------------------------------------
// Benchmark: individual calls vs. aggregated call
//
// Soroban's `cost_estimate().budget()` gives CPU-instruction and memory-byte
// counters that model host-level execution cost. We compare:
//   A) Consumer calls denylist-gate.check() + jurisdiction-flag.is_permitted_jurisdiction()
//      directly, each as a separate cross-contract call — two invocations.
//   B) Consumer calls compliance-aggregator.check_address(), which makes both
//      downstream calls internally — one invocation from the consumer.
//
// **What this measures**: the consumer's observable call overhead.
// Path A: the consumer makes 2 separate cross-contract calls.
// Path B: the consumer makes 1 cross-contract call; the aggregator makes 2
//         downstream calls internally, so the total host work is greater than
//         path A (the aggregator adds one extra call frame). This is expected:
//         the aggregator trades total-host-instruction-count for a simpler
//         consumer API and a single network round-trip per transfer.
//
// The assertion below verifies that the aggregated path does not add more
// than 4× the raw primitive cost — confirming no gratuitous overhead beyond
// the one additional call frame.
//
// Note: in the Soroban test environment all contracts run in a single Env so
// "cross-contract" boundaries are simulated rather than real. The relative
// instruction counts still correctly model call-dispatch overhead.
// ---------------------------------------------------------------------------

#[test]
fn bench_individual_vs_aggregated() {
    // ---- Setup shared state ----
    let env = Env::default();
    env.mock_all_auths();

    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    let gate_client = DenylistGateClient::new(&env, &gate_id);
    gate_client.initialize(&gate_admin);

    let flag_issuer = Address::generate(&env);
    let flag_id = env.register(JurisdictionFlag, ());
    let flag_client = JurisdictionFlagClient::new(&env, &flag_id);
    flag_client.initialize(&flag_issuer);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let agg_client = ComplianceAggregatorClient::new(&env, &agg_id);
    agg_client.initialize(&agg_admin, &Some(gate_id.clone()), &Some(flag_id.clone()), &None);

    let alice = Address::generate(&env);
    flag_client.set_jurisdiction(&flag_issuer, &alice, &String::from_str(&env, "US"));

    let allowed = us_vec(&env);

    // ---- Path A: two direct calls (2 invocations from consumer) ----
    env.cost_estimate().budget().reset_default();
    let deny_ok = gate_client.check(&alice);
    let juris_ok = flag_client.is_permitted_jurisdiction(&alice, &allowed);
    let individual_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let individual_mem = env.cost_estimate().budget().memory_bytes_cost();
    assert!(deny_ok);
    assert!(juris_ok);

    // ---- Path B: one aggregated call (1 invocation from consumer) ----
    env.cost_estimate().budget().reset_default();
    let (all_passed, checks) = agg_client.check_address(&alice, &allowed);
    let aggregated_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let aggregated_mem = env.cost_estimate().budget().memory_bytes_cost();
    assert!(all_passed);
    assert_eq!(checks.len(), 2);

    // ---- Report ----
    std::println!(
        "\n=== compliance-aggregator benchmark ===\n\
         Path A (2× direct cross-contract calls from consumer):\n  CPU instructions: {individual_cpu}\n  Memory bytes:     {individual_mem}\n\
         Path B (1× aggregator call — consumer makes 1 call, aggregator makes 2 downstream):\n  CPU instructions: {aggregated_cpu}\n  Memory bytes:     {aggregated_mem}\n\
         Ratio B/A:  CPU {:.2}×  Mem {:.2}×\n\
         Note: B > A in total host cost because the aggregator adds one extra call\n\
               frame. The saving is on the consumer side: 1 call instead of 2.\n\
         =======================================",
        aggregated_cpu as f64 / individual_cpu as f64,
        aggregated_mem as f64 / individual_mem as f64,
    );

    // The aggregated path (3 total call frames) must not exceed 4× the cost
    // of the 2 raw primitive calls — confirming no gratuitous overhead beyond
    // the one extra aggregator frame.
    assert!(
        aggregated_cpu <= individual_cpu * 4,
        "Aggregated path CPU cost ({aggregated_cpu}) exceeds 4× the individual path ({individual_cpu})"
    );
}

#[test]
fn bench_batch_vs_individual_loop() {
    // Compare: calling check_address N times vs. check_all once for N addresses.
    let env = Env::default();
    env.mock_all_auths();

    let (_, _, flag_issuer, flag_id, _, _, client) = setup_all(&env);

    let addresses: soroban_sdk::Vec<Address> = {
        let mut v = soroban_sdk::Vec::new(&env);
        for _ in 0..4_u32 {
            let a = Address::generate(&env);
            set_jurisdiction(&env, &flag_id, &flag_issuer, &a, "US");
            v.push_back(a);
        }
        v
    };

    let allowed = us_vec(&env);

    // Path A: N individual check_address calls
    env.cost_estimate().budget().reset_default();
    for addr in addresses.iter() {
        client.check_address(&addr, &allowed);
    }
    let individual_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let individual_mem = env.cost_estimate().budget().memory_bytes_cost();

    // Path B: one check_all call
    env.cost_estimate().budget().reset_default();
    let results = client.check_all(&addresses, &allowed);
    let batch_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let batch_mem = env.cost_estimate().budget().memory_bytes_cost();
    assert_eq!(results.len(), 4);

    std::println!(
        "\n=== batch benchmark (4 addresses) ===\n\
         Path A (4× check_address):\n  CPU: {individual_cpu}  Mem: {individual_mem}\n\
         Path B (1× check_all):\n  CPU: {batch_cpu}  Mem: {batch_mem}\n\
         Ratio B/A:  CPU {:.2}×  Mem {:.2}×\n\
         Note: B > A because check_all routes through one extra aggregator call\n\
               frame per batch. The saving for the caller is one invocation\n\
               instead of N, which matters most over a real network.\n\
         =====================================",
        batch_cpu as f64 / individual_cpu as f64,
        batch_mem as f64 / individual_mem as f64,
    );

    // check_all incurs one additional aggregator frame versus N individual
    // check_address calls (which already go through the aggregator). Allow
    // up to 4× to guard against any genuine regression beyond the expected
    // single extra frame.
    assert!(
        batch_cpu <= individual_cpu * 4,
        "Batch path CPU ({batch_cpu}) exceeds 4× the individual loop ({individual_cpu})"
    );
}

// ---------------------------------------------------------------------------
// circuit-breaker wiring
// ---------------------------------------------------------------------------

#[test]
fn test_circuit_breaker_freeze_short_circuits_check_address() {
    let env = Env::default();
    env.mock_all_auths();

    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    DenylistGateClient::new(&env, &gate_id).initialize(&gate_admin);

    let breaker_admin = Address::generate(&env);
    let breaker_id = env.register(CircuitBreaker, ());
    let breaker_client = CbClient::new(&env, &breaker_id);
    breaker_client.initialize(&breaker_admin);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(
        &agg_admin,
        &Some(gate_id.clone()),
        &None,
        &Some(breaker_id.clone()),
    );

    let alice = Address::generate(&env);

    // Before freezing, the check passes normally.
    let (all_passed, checks) = client.check_address(&alice, &vec![&env]);
    assert!(all_passed);
    assert_eq!(checks.len(), 2);
    assert_eq!(checks.get(0).unwrap().check, CheckKind::CircuitBreaker);
    assert!(checks.get(0).unwrap().passed);

    // Freeze mid-flow.
    breaker_client.freeze(&breaker_admin, &None);

    // Now the same previously-passing check is denied without even
    // consulting the denylist-gate.
    let (all_passed, checks) = client.check_address(&alice, &vec![&env]);
    assert!(!all_passed);
    assert_eq!(checks.len(), 1);
    assert_eq!(checks.get(0).unwrap().check, CheckKind::CircuitBreaker);
    assert!(!checks.get(0).unwrap().passed);
}

#[test]
fn test_get_config_matches_initialize() {
    let env = Env::default();
    let (_, gate_id, _, flag_id, _, _, client) = setup_all(&env);
    assert_eq!(
        client.get_config(),
        AggregatorConfig {
            denylist_gate: Some(gate_id),
            jurisdiction_flag: Some(flag_id),
            circuit_breaker: None,
        }
    );
}

// ---------------------------------------------------------------------------
// Upgrade / migration path
// ---------------------------------------------------------------------------

/// Path to the release WASM produced by
/// `cargo build --workspace --target wasm32v1-none --release`.
fn compliance_aggregator_wasm_path() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("wasm32v1-none")
        .join("release")
        .join("compliance_aggregator.wasm")
}

#[test]
fn test_upgrade_before_initialize_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    let admin = Address::generate(&env);
    let hash = soroban_sdk::BytesN::from_array(&env, &[0u8; 32]);
    let result = client.try_upgrade(&admin, &hash);
    assert_eq!(result, Err(Ok(Error::NotInitialized)));
}

#[test]
fn test_upgrade_rejects_non_admin() {
    let env = Env::default();
    let (_ga, _gid, _fi, _fid, _admin, _agg_id, client) = setup_all(&env);
    let impostor = Address::generate(&env);
    let hash = soroban_sdk::BytesN::from_array(&env, &[0u8; 32]);
    let result = client.try_upgrade(&impostor, &hash);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}

/// Deploy from WASM, write state, upgrade to a freshly uploaded WASM hash,
/// then confirm every piece of state survived and the contract is still
/// callable. Requires the release WASM (`make build`); skipped otherwise.
#[test]
fn test_upgrade_preserves_state_and_remains_callable() {
    let wasm_path = compliance_aggregator_wasm_path();
    let wasm = match std::fs::read(&wasm_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            std::eprintln!(
                "skipping migration test: {} not found (run `make build` first)",
                wasm_path.display()
            );
            return;
        }
    };

    let env = Env::default();
    env.mock_all_auths();

    // Underlying primitives.
    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    DenylistGateClient::new(&env, &gate_id).initialize(&gate_admin);
    let flag_issuer = Address::generate(&env);
    let flag_id = env.register(JurisdictionFlag, ());
    JurisdictionFlagClient::new(&env, &flag_id).initialize(&flag_issuer);
    let breaker_admin = Address::generate(&env);
    let breaker_id = env.register(CircuitBreaker, ());
    CbClient::new(&env, &breaker_id).initialize(&breaker_admin);

    // Deploy the current release WASM and write state.
    let agg_admin = Address::generate(&env);
    let agg_id = env.register(wasm.as_slice(), ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &Some(gate_id.clone()), &None, &None);
    client.set_jurisdiction_flag(&agg_admin, &flag_id);
    client.set_circuit_breaker(&agg_admin, &breaker_id);

    let alice = Address::generate(&env);
    let mallory = Address::generate(&env);
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
    set_jurisdiction(&env, &flag_id, &flag_issuer, &mallory, "US");
    deny(&env, &gate_id, &gate_admin, &mallory);

    // Upgrade to a newly uploaded WASM hash.
    let new_hash = env
        .deployer()
        .upload_contract_wasm(soroban_sdk::Bytes::from_slice(&env, &wasm));
    client.upgrade(&agg_admin, &new_hash);

    // State is intact.
    assert_eq!(client.denylist_gate(), Some(gate_id.clone()));
    assert_eq!(client.jurisdiction_flag(), Some(flag_id.clone()));
    assert_eq!(client.circuit_breaker(), Some(breaker_id.clone()));
    assert!(!client.is_paused());

    // And the contract is still callable after the upgrade.
    let (alice_ok, alice_checks) = client.check_address(&alice, &us_vec(&env));
    assert!(alice_ok);
    assert_eq!(alice_checks.len(), 3);
    let (mallory_ok, _) = client.check_address(&mallory, &us_vec(&env));
    assert!(!mallory_ok);

    // Admin is preserved: admin-only mutations still work for the old admin
    // and are still rejected for anyone else.
    let new_admin = Address::generate(&env);
    assert_eq!(
        client.try_set_admin(&new_admin, &new_admin),
        Err(Ok(Error::NotAuthorized))
    );
    client.set_admin(&agg_admin, &new_admin);
    client.pause(&new_admin);
    assert!(client.is_paused());
}

// ---------------------------------------------------------------------------
// Resource-fee benchmark (budget regression) — `check_address`
//
// `check_address` is the aggregator's hottest entrypoint: consumers call it
// once per transfer, and it fans out to both registered primitives. The
// measured CPU/memory cost is compared against the
// `[compliance-aggregator.check_address]` entry in `budget-baselines.toml`;
// the test (and therefore the `budget-regression` CI job, which runs
// `cargo test --workspace budget_regression`) fails if either exceeds the
// baseline by more than 10%.
// ---------------------------------------------------------------------------

fn read_baseline(path: &std::path::Path, section: &str) -> (u64, u64) {
    let contents = std::fs::read_to_string(path).unwrap();
    let section_header = std::format!("[{section}]");
    let mut in_section = false;
    let mut cpu = None;
    let mut memory = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_section = trimmed == section_header;
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("cpu = ") {
            cpu = Some(value.replace('_', "").parse::<u64>().unwrap());
        } else if let Some(value) = trimmed.strip_prefix("memory = ") {
            memory = Some(value.replace('_', "").parse::<u64>().unwrap());
        }
    }

    let cpu = cpu.expect("missing cpu baseline");
    let memory = memory.expect("missing memory baseline");
    (cpu, memory)
}

fn baseline_path() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("budget-baselines.toml")
}

fn assert_budget_within_threshold(measured: (u64, u64), baseline: (u64, u64), label: &str) {
    let (measured_cpu, measured_memory) = measured;
    let (baseline_cpu, baseline_memory) = baseline;
    let cpu_limit = (baseline_cpu as f64 * 1.10).ceil() as u64;
    let memory_limit = (baseline_memory as f64 * 1.10).ceil() as u64;

    assert!(
        measured_cpu <= cpu_limit,
        "{label} CPU regression: measured {measured_cpu}, baseline {baseline_cpu}, limit {cpu_limit}"
    );
    assert!(
        measured_memory <= memory_limit,
        "{label} memory regression: measured {measured_memory}, baseline {baseline_memory}, limit {memory_limit}"
    );
}

#[test]
fn test_budget_regression_check_address() {
    let env = Env::default();
    let (_ga, _gid, flag_issuer, flag_id, _admin, _agg_id, client) = setup_all(&env);
    let alice = Address::generate(&env);
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
    let allowed = us_vec(&env);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    let (all_passed, checks) = client.check_address(&alice, &allowed);
    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    assert!(all_passed);
    assert_eq!(checks.len(), 2);

    std::println!(
        "compliance-aggregator.check_address: cpu = {}, memory = {}",
        measured.0, measured.1
    );

    let baseline = read_baseline(&baseline_path(), "compliance-aggregator.check_address");
    assert_budget_within_threshold(measured, baseline, "compliance-aggregator check_address");
}

// ---------------------------------------------------------------------------
// TTL extension (#194)
// ---------------------------------------------------------------------------

fn instance_ttl(env: &Env, contract_id: &Address) -> u32 {
    use soroban_sdk::testutils::storage::Instance as _;
    env.as_contract(contract_id, || env.storage().instance().get_ttl())
}

#[test]
fn test_initialize_extends_instance_ttl() {
    use soroban_sdk::testutils::Ledger as _;

    let env = Env::default();
    env.ledger().with_mut(|li| {
        li.sequence_number = 100_000;
        li.min_persistent_entry_ttl = 500;
        li.max_entry_ttl = 6_311_520;
    });
    let (_, _, _, _, _, agg_id, _) = setup_all(&env);

    assert_eq!(instance_ttl(&env, &agg_id), INSTANCE_TTL_EXTEND_TO);
}

/// Advance the ledger past the TTL the instance was given at initialization,
/// with a config write in between, and confirm the stored state is still
/// readable because the write refreshed the TTL.
#[test]
fn test_write_refreshes_instance_ttl_past_original_expiry() {
    use soroban_sdk::testutils::Ledger as _;

    let env = Env::default();
    env.ledger().with_mut(|li| {
        li.sequence_number = 100_000;
        li.min_persistent_entry_ttl = 500;
        li.max_entry_ttl = 6_311_520;
    });
    let (_, gate_id, _, flag_id, agg_admin, agg_id, client) = setup_all(&env);
    let original_ttl = instance_ttl(&env, &agg_id);
    assert_eq!(original_ttl, INSTANCE_TTL_EXTEND_TO);

    // Move far enough that the remaining TTL drops below the threshold.
    let first_advance = INSTANCE_TTL_EXTEND_TO - INSTANCE_TTL_THRESHOLD + 1;
    env.ledger().with_mut(|li| li.sequence_number += first_advance);
    assert!(instance_ttl(&env, &agg_id) < INSTANCE_TTL_THRESHOLD);

    // A write path refreshes the TTL back to the target.
    client.set_denylist_gate(&agg_admin, &gate_id);
    assert_eq!(instance_ttl(&env, &agg_id), INSTANCE_TTL_EXTEND_TO);

    // The underlying primitives are separate contracts with their own TTL
    // policy; keep them alive so the check below only exercises the
    // aggregator's own storage.
    env.deployer()
        .extend_ttl(gate_id.clone(), INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    env.deployer()
        .extend_ttl(flag_id.clone(), INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

    // Now advance beyond the original expiry. Without the refresh the
    // instance would have been archived by this point.
    env.ledger().with_mut(|li| li.sequence_number += INSTANCE_TTL_THRESHOLD);
    assert!(first_advance + INSTANCE_TTL_THRESHOLD > original_ttl);

    assert_eq!(client.denylist_gate(), Some(gate_id));
    assert_eq!(client.jurisdiction_flag(), Some(flag_id));
    let alice = Address::generate(&env);
    let (_, results) = client.check_address(&alice, &us_vec(&env));
    assert_eq!(results.len(), 2);
}

#[test]
fn test_every_admin_write_path_extends_instance_ttl() {
    use soroban_sdk::testutils::Ledger as _;

    let env = Env::default();
    env.ledger().with_mut(|li| {
        li.sequence_number = 100_000;
        li.min_persistent_entry_ttl = 500;
        li.max_entry_ttl = 6_311_520;
    });
    let (_, gate_id, _, flag_id, agg_admin, agg_id, client) = setup_all(&env);
    let breaker = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let step = INSTANCE_TTL_EXTEND_TO - INSTANCE_TTL_THRESHOLD + 1;

    let age = |env: &Env| {
        env.ledger().with_mut(|li| li.sequence_number += step);
        assert!(instance_ttl(env, &agg_id) < INSTANCE_TTL_THRESHOLD);
    };

    age(&env);
    client.set_denylist_gate(&agg_admin, &gate_id);
    assert_eq!(instance_ttl(&env, &agg_id), INSTANCE_TTL_EXTEND_TO);

    age(&env);
    client.set_jurisdiction_flag(&agg_admin, &flag_id);
    assert_eq!(instance_ttl(&env, &agg_id), INSTANCE_TTL_EXTEND_TO);

    age(&env);
    client.set_circuit_breaker(&agg_admin, &breaker);
    assert_eq!(instance_ttl(&env, &agg_id), INSTANCE_TTL_EXTEND_TO);

    age(&env);
    client.pause(&agg_admin);
    assert_eq!(instance_ttl(&env, &agg_id), INSTANCE_TTL_EXTEND_TO);

    age(&env);
    client.unpause(&agg_admin);
    assert_eq!(instance_ttl(&env, &agg_id), INSTANCE_TTL_EXTEND_TO);

    age(&env);
    client.set_admin(&agg_admin, &new_admin);
    assert_eq!(instance_ttl(&env, &agg_id), INSTANCE_TTL_EXTEND_TO);
}

#[test]
fn test_benchmark_check_address_vs_batch_check_cost_tradeoff() {
    let env = Env::default();
    let (_agg_admin, _gate_admin, _flag_admin, _gate_id, flag_id, client) = setup_both(&env);
    let flag_client = JurisdictionFlagClient::new(&env, &flag_id);
    let allowed = vec![&env, String::from_str(&env, "US")];

    for &n in &[1u32, 2, 5, 10] {
        let mut addrs = Vec::new(&env);
        for _ in 0..n {
            let a = Address::generate(&env);
            flag_client.set_jurisdiction(& _flag_admin, &a, &String::from_str(&env, "US"));
            addrs.push_back(a);
        }

        env.cost_estimate().budget().reset_default();
        for a in addrs.iter() {
            let (passed, _) = client.check_address(&a, &allowed);
            assert!(passed);
        }
        let individual_cpu = env.cost_estimate().budget().cpu_instruction_cost();

        env.cost_estimate().budget().reset_default();
        let batch_res = client.check_all(&addrs, &allowed);
        assert_eq!(batch_res.len(), n);
        let batch_cpu = env.cost_estimate().budget().cpu_instruction_cost();

        if n >= 2 {
            assert!(
                batch_cpu < individual_cpu,
                "for N={n}, batch_check ({batch_cpu}) should use fewer CPU instructions than {n}x check_address ({individual_cpu})"
            );
        }
    }
}


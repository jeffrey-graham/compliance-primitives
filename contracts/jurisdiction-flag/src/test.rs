use super::*;
use soroban_sdk::testutils::{storage::Persistent as _, Address as _, Events as _, Ledger as _};
use soroban_sdk::{vec, Env};
use std::path::{Path, PathBuf};

fn setup(env: &Env) -> (Address, Address, JurisdictionFlagClient<'_>) {
    env.mock_all_auths();
    let issuer = Address::generate(env);
    let contract_id = env.register(JurisdictionFlag, ());
    let client = JurisdictionFlagClient::new(env, &contract_id);
    client.initialize(&issuer);
    (issuer, contract_id, client)
}

fn read_baseline(path: &Path, section: &str) -> (u64, u64) {
    let contents = std::fs::read_to_string(path).unwrap();
    let section_header = format!("[{section}]");
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
            cpu = Some(value.parse::<u64>().unwrap());
        } else if let Some(value) = trimmed.strip_prefix("memory = ") {
            memory = Some(value.parse::<u64>().unwrap());
        }
    }

    let cpu = cpu.expect("missing cpu baseline");
    let memory = memory.expect("missing memory baseline");
    (cpu, memory)
}

fn baseline_path_for_manifest_dir(manifest_dir: PathBuf) -> PathBuf {
    manifest_dir.join("..").join("..").join("budget-baselines.toml")
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

/// Default per-invocation write-entry budget used by the Soroban host.
///
/// `remove_jurisdiction_multiple` has no `MAX_BATCH_SIZE` guard yet (deferred to
/// a future shared-cap issue), so this benchmark measures where its resource
/// cost crosses the default budget at increasing batch sizes. The recorded
/// crossing point is the measurement that should inform the batch-size cap when
/// the shared-cap issue is picked up.
const DEFAULT_WRITE_ENTRY_BUDGET: u64 = 100;

/// Batch sizes exercised by the benchmark, from a realistic single call up to
/// well past the point where the default write-entry budget is exhausted.
const BENCHMARK_BATCH_SIZES: [u32; 6] = [1, 5, 10, 25, 50, 100];

#[test]
fn test_remove_jurisdiction_multiple_resource_fee_benchmark() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);

    let mut crossing_point: Option<u32> = None;

    for &batch_size in BENCHMARK_BATCH_SIZES.iter() {
        let mut addresses = Vec::new(&env);
        for _ in 0..batch_size {
            let addr = Address::generate(&env);
            client.set_jurisdiction(&issuer, &addr, &String::from_str(&env, "US"));
            addresses.push_back(addr);
        }

        let mut budget = env.cost_estimate().budget();
        budget.reset_default();
        client.remove_jurisdiction_multiple(&issuer, &addresses);

        let cpu = budget.cpu_instruction_cost();
        let memory = budget.memory_bytes_cost();

        // Each cleared address consumes one write entry; record the first batch
        // size whose write-entry cost exceeds the default per-invocation budget.
        let write_entries = batch_size as u64;
        if write_entries > DEFAULT_WRITE_ENTRY_BUDGET && crossing_point.is_none() {
            crossing_point = Some(batch_size);
        }

        std::println!(
            "remove_jurisdiction_multiple batch_size={batch_size} cpu={cpu} memory={memory} write_entries={write_entries}"
        );
    }

    // The benchmark must actually observe the crossing point so the recorded
    // measurement can inform the future shared batch-size cap.
    assert!(
        crossing_point.is_some(),
        "benchmark did not reach the default write-entry budget ({DEFAULT_WRITE_ENTRY_BUDGET}) within {BENCHMARK_BATCH_SIZES:?}"
    );
}

#[test]
fn test_set_and_get_jurisdiction() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    assert_eq!(client.get_jurisdiction(&alice), None);

    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);
    assert_eq!(client.get_jurisdiction(&alice), Some(code));
}

#[test]
fn test_multi_code_jurisdiction_operations_and_legacy_views() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let us = String::from_str(&env, "US");
    let ca = String::from_str(&env, "CA");

    client.set_jurisdiction(&issuer, &alice, &us);
    client.add_jurisdiction(&issuer, &alice, &ca);
    client.add_jurisdiction(&issuer, &alice, &ca);

    assert_eq!(client.list_jurisdictions(&alice), vec![&env, us.clone(), ca.clone()]);
    assert_eq!(client.get_jurisdiction(&alice), Some(us.clone()));
    assert!(client.is_permitted_jurisdiction(&alice, &vec![&env, ca.clone()]));

    client.remove_jurisdiction(&issuer, &alice, &us);
    assert_eq!(client.list_jurisdictions(&alice), vec![&env, ca.clone()]);
    assert_eq!(client.get_jurisdiction(&alice), Some(ca.clone()));

    client.remove_jurisdiction(&issuer, &alice, &ca);
    assert_eq!(client.list_jurisdictions(&alice), vec![&env]);
    assert_eq!(client.get_jurisdiction(&alice), None);
}

#[test]
fn test_multi_code_jurisdiction_mutations_reject_unauthorized_callers() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");

    assert_eq!(
        client.try_add_jurisdiction(&impostor, &alice, &code),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(
        client.try_remove_jurisdiction(&impostor, &alice, &code),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(client.list_jurisdictions(&alice), vec![&env]);
}

#[test]
fn test_get_jurisdiction_emits_expired_event_for_expired_flag() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");

    client.set_jurisdiction(&issuer, &alice, &code);

    // Advance the ledger past the flag's expiry so the read enforces expiry.
    let expiry = client.get_jurisdiction_expiry(&alice).unwrap();
    env.ledger().set_timestamp(expiry + 1);

    assert_eq!(client.get_jurisdiction(&alice), None);

    let events = env.events().all();
    let expired = events.iter().any(|(_, topics, _)| {
        topics
            .iter()
            .any(|topic| topic == &Symbol::new(&env, "JurisdictionExpired").into())
    });
    assert!(expired, "JurisdictionExpired event was not published");
}

#[test]
fn test_budget_regression_is_permitted_jurisdiction() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);

    let allowed = vec![
        &env,
        String::from_str(&env, "CA"),
        String::from_str(&env, "US"),
    ];

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    let is_permitted = client.is_permitted_jurisdiction(&alice, &allowed);
    assert!(is_permitted);

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    let baseline_path = baseline_path_for_manifest_dir(PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()));
    let baseline = read_baseline(&baseline_path, "jurisdiction-flag.is_permitted_jurisdiction");
    assert_budget_within_threshold(measured, baseline, "jurisdiction-flag jurisdiction check");
}

#[test]
fn test_set_jurisdiction_rejects_non_issuer() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");

    let result = client.try_set_jurisdiction(&impostor, &alice, &code);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert_eq!(client.get_jurisdiction(&alice), None);
}

#[test]
fn test_remove_jurisdiction_multiple_clears_mixed_addresses() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let never_set = Address::generate(&env);

    client.set_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));
    client.set_jurisdiction(&issuer, &bob, &String::from_str(&env, "CA"));
    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
    assert_eq!(
        client.get_jurisdiction(&bob),
        Some(String::from_str(&env, "CA"))
    );
    assert_eq!(client.get_jurisdiction(&never_set), None);

    let addresses = vec![&env, alice.clone(), bob.clone(), never_set.clone()];
    client.remove_jurisdiction_multiple(&issuer, &addresses);

    assert_eq!(client.get_jurisdiction(&alice), None);
    assert_eq!(client.get_jurisdiction(&bob), None);
    assert_eq!(client.get_jurisdiction(&never_set), None);
}

#[test]
fn test_remove_jurisdiction_multiple_rejects_non_issuer() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    client.set_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));

    let addresses = vec![&env, alice.clone()];
    let result = client.try_remove_jurisdiction_multiple(&impostor, &addresses);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
}

#[test]
fn test_remove_jurisdiction_multiple_empty_vec_is_noop() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    client.set_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));

    let empty: Vec<Address> = vec![&env];
    client.remove_jurisdiction_multiple(&issuer, &empty);

    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
}

#[test]
fn test_is_permitted_jurisdiction_true_when_code_in_list() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);

    let allowed = vec![
        &env,
        String::from_str(&env, "CA"),
        String::from_str(&env, "US"),
    ];
    assert_eq!(client.is_permitted_jurisdiction(&alice, &allowed), true);
}

#[test]
fn test_is_permitted_jurisdiction_false_when_no_jurisdiction_set() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let allowed = vec![&env, String::from_str(&env, "US")];
    assert_eq!(client.is_permitted_jurisdiction(&alice, &allowed), false);
}

#[test]
fn test_is_permitted_jurisdiction_errors_with_empty_allowed_list() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);

    let allowed: Vec<String> = vec![&env];
    let result = client.try_is_permitted_jurisdiction(&alice, &allowed);
    assert_eq!(result, Err(Ok(Error::EmptyAllowedCodes)));
}

#[test]
fn test_is_permitted_jurisdiction_errors_when_no_jurisdiction_and_empty_allowed_list() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    let allowed: Vec<String> = vec![&env];
    let result = client.try_is_permitted_jurisdiction(&alice, &allowed);
    assert_eq!(result, Err(Ok(Error::EmptyAllowedCodes)));
}

#[test]
fn test_set_jurisdiction_fails_before_initialize() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(JurisdictionFlag, ());
    let client = JurisdictionFlagClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");

    let result = client.try_set_jurisdiction(&issuer, &alice, &code);
    assert_eq!(result, Err(Ok(Error::NotInitialized)));
}

// ---------------------------------------------------------------------------
// Issuer transfer (#19)
// ---------------------------------------------------------------------------

mod issuer_transfer {
    use super::setup;
    use crate::{Error, JurisdictionFlag, JurisdictionFlagClient};
    use soroban_sdk::testutils::{Address as _, Events as _};
    use soroban_sdk::{vec, Address, Env, IntoVal, Map, String, Symbol, Val};

    #[test]
    fn test_transfer_issuer_emits_event_and_hands_over_control() {
        let env = Env::default();
        let (issuer, contract_id, client) = setup(&env);
        let new_issuer = Address::generate(&env);

        assert_eq!(client.get_issuer(), issuer);
        client.transfer_issuer(&issuer, &new_issuer);
        assert_eq!(client.get_issuer(), new_issuer);

        assert_eq!(
            env.events().all(),
            vec![
                &env,
                (
                    contract_id.clone(),
                    (
                        Symbol::new(&env, "issuer_transferred"),
                        issuer.clone(),
                        new_issuer.clone(),
                    )
                        .into_val(&env),
                    Map::<Symbol, Val>::new(&env).into_val(&env),
                ),
            ]
        );

        let alice = Address::generate(&env);
        let code = String::from_str(&env, "US");
        client.set_jurisdiction(&new_issuer, &alice, &code);
        assert_eq!(client.get_jurisdiction(&alice), Some(code));
    }

    #[test]
    fn test_transfer_issuer_rejects_non_issuer() {
        let env = Env::default();
        let (issuer, _contract_id, client) = setup(&env);
        let impostor = Address::generate(&env);

        let result = client.try_transfer_issuer(&impostor, &impostor);
        assert_eq!(result, Err(Ok(Error::NotAuthorized)));

        // The real issuer is unchanged and still in control.
        let alice = Address::generate(&env);
        client.set_jurisdiction(&issuer, &alice, &String::from_str(&env, "CA"));
        assert_eq!(
            client.try_set_jurisdiction(&impostor, &alice, &String::from_str(&env, "US")),
            Err(Ok(Error::NotAuthorized))
        );
    }

    #[test]
    fn test_transfer_issuer_revokes_old_issuer_immediately() {
        let env = Env::default();
        let (old_issuer, _contract_id, client) = setup(&env);
        let new_issuer = Address::generate(&env);
        let alice = Address::generate(&env);
        let officer = Address::generate(&env);

        client.transfer_issuer(&old_issuer, &new_issuer);

        assert_eq!(
            client.try_set_jurisdiction(&old_issuer, &alice, &String::from_str(&env, "US")),
            Err(Ok(Error::NotAuthorized))
        );
        assert_eq!(
            client.try_remove_jurisdiction_multiple(&old_issuer, &vec![&env, alice.clone()]),
            Err(Ok(Error::NotAuthorized))
        );
        assert_eq!(
            client.try_set_compliance_officer(&old_issuer, &officer),
            Err(Ok(Error::NotAuthorized))
        );
        assert_eq!(client.try_pause(&old_issuer), Err(Ok(Error::NotAuthorized)));
        assert_eq!(
            client.try_transfer_issuer(&old_issuer, &old_issuer),
            Err(Ok(Error::NotAuthorized))
        );
        assert_eq!(client.get_jurisdiction(&alice), None);
    }

    #[test]
    fn test_transfer_issuer_fails_before_initialize() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(JurisdictionFlag, ());
        let client = JurisdictionFlagClient::new(&env, &contract_id);
        let someone = Address::generate(&env);

        assert_eq!(client.try_get_issuer(), Err(Ok(Error::NotInitialized)));
        assert_eq!(
            client.try_transfer_issuer(&someone, &someone),
            Err(Ok(Error::NotInitialized))
        );
    }
}

// ---------------------------------------------------------------------------
// Jurisdiction code format validation (#82)
// ---------------------------------------------------------------------------

mod code_validation {
    use super::setup;
    use crate::Error;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Env, String};

    #[test]
    fn test_set_jurisdiction_accepts_valid_alpha2_codes() {
        let env = Env::default();
        let (issuer, _contract_id, client) = setup(&env);

        for raw in ["US", "GB", "CA", "DE", "ZZ", "AA"] {
            let alice = Address::generate(&env);
            let code = String::from_str(&env, raw);
            client.set_jurisdiction(&issuer, &alice, &code);
            assert_eq!(client.get_jurisdiction(&alice), Some(code), "code {raw:?}");
        }
    }

    #[test]
    fn test_set_jurisdiction_rejects_wrong_length() {
        let env = Env::default();
        let (issuer, _contract_id, client) = setup(&env);
        let alice = Address::generate(&env);

        for raw in ["", "U", "USA", "united-states", "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTU"] {
            let result = client.try_set_jurisdiction(&issuer, &alice, &String::from_str(&env, raw));
            assert_eq!(result, Err(Ok(Error::InvalidJurisdictionCode)), "code {raw:?}");
        }
        assert_eq!(client.get_jurisdiction(&alice), None);
    }

    #[test]
    fn test_set_jurisdiction_rejects_non_letter_characters() {
        let env = Env::default();
        let (issuer, _contract_id, client) = setup(&env);
        let alice = Address::generate(&env);

        for raw in ["U1", "1A", "42", "U-", " U", "U ", "  ", "U.", "\u{e9}"] {
            let result = client.try_set_jurisdiction(&issuer, &alice, &String::from_str(&env, raw));
            assert_eq!(result, Err(Ok(Error::InvalidJurisdictionCode)), "code {raw:?}");
        }
        assert_eq!(client.get_jurisdiction(&alice), None);
    }

    /// Case policy: codes are case-sensitive (#54) and never normalized, so
    /// only the canonical uppercase form is accepted on write.
    #[test]
    fn test_set_jurisdiction_rejects_lowercase_and_mixed_case() {
        let env = Env::default();
        let (issuer, _contract_id, client) = setup(&env);
        let alice = Address::generate(&env);

        for raw in ["us", "Us", "uS"] {
            let result = client.try_set_jurisdiction(&issuer, &alice, &String::from_str(&env, raw));
            assert_eq!(result, Err(Ok(Error::InvalidJurisdictionCode)), "code {raw:?}");
        }
        assert_eq!(client.get_jurisdiction(&alice), None);
    }

    #[test]
    fn test_invalid_code_does_not_overwrite_existing_code() {
        let env = Env::default();
        let (issuer, _contract_id, client) = setup(&env);
        let alice = Address::generate(&env);
        let us = String::from_str(&env, "US");

        client.set_jurisdiction(&issuer, &alice, &us);
        let result = client.try_set_jurisdiction(&issuer, &alice, &String::from_str(&env, "usa"));
        assert_eq!(result, Err(Ok(Error::InvalidJurisdictionCode)));
        assert_eq!(client.get_jurisdiction(&alice), Some(us));
    }

    #[test]
    fn test_authorization_is_checked_before_code_format() {
        let env = Env::default();
        let (_issuer, _contract_id, client) = setup(&env);
        let impostor = Address::generate(&env);
        let alice = Address::generate(&env);

        let result = client.try_set_jurisdiction(&impostor, &alice, &String::from_str(&env, "bad"));
        assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    }
}

#[test]
fn test_no_expiry_never_expires() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);

    env.ledger().with_mut(|li| li.sequence_number += 1_000_000);
    assert_eq!(client.get_jurisdiction(&alice), Some(code));
}

#[test]
fn test_set_jurisdiction_until_validates_ledger_boundary() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let past_address = Address::generate(&env);
    let current_address = Address::generate(&env);
    let future_address = Address::generate(&env);
    let code = String::from_str(&env, "US");
    let current_sequence = 10;
    env.ledger()
        .with_mut(|ledger| ledger.sequence_number = current_sequence);

    assert_eq!(
        client.try_set_jurisdiction_until(
            &issuer,
            &past_address,
            &code,
            &(current_sequence - 1),
        ),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(client.get_jurisdiction(&past_address), None);

    client.set_jurisdiction_until(&issuer, &current_address, &code, &current_sequence);
    assert_eq!(client.get_jurisdiction(&current_address), Some(code.clone()));

    let future_sequence = current_sequence + 1;
    client.set_jurisdiction_until(&issuer, &future_address, &code, &future_sequence);
    assert_eq!(client.get_jurisdiction(&future_address), Some(code));
}

#[test]
fn test_jurisdiction_expires_after_valid_until() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    let valid_until = env.ledger().sequence() + 10;
    client.set_jurisdiction_until(&issuer, &alice, &code, &valid_until);

    env.ledger().with_mut(|li| li.sequence_number = valid_until);
    assert_eq!(client.get_jurisdiction(&alice), Some(code));

    env.ledger().with_mut(|li| li.sequence_number = valid_until + 1);
    assert_eq!(client.get_jurisdiction(&alice), None);
    let allowed = vec![&env, String::from_str(&env, "US")];
    assert_eq!(client.is_permitted_jurisdiction(&alice, &allowed), false);
}

// ---------------------------------------------------------------------------
// Issue #604: set_multiple_jurisdictions batch setter
// ---------------------------------------------------------------------------

#[test]
fn test_set_multiple_jurisdictions_basic() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    let entries = vec![
        &env,
        (alice.clone(), String::from_str(&env, "US")),
        (bob.clone(), String::from_str(&env, "CA")),
    ];
    client.set_multiple_jurisdictions(&issuer, &entries);

    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
    assert_eq!(
        client.get_jurisdiction(&bob),
        Some(String::from_str(&env, "CA"))
    );
}

#[test]
fn test_set_multiple_jurisdictions_rejects_unauthorized_caller() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    let entries = vec![
        &env,
        (alice.clone(), String::from_str(&env, "US")),
    ];
    let result = client.try_set_multiple_jurisdictions(&impostor, &entries);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert_eq!(client.get_jurisdiction(&alice), None);
}

#[test]
fn test_set_multiple_jurisdictions_one_invalid_code_rejects_whole_batch() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    // "us" is lowercase — invalid; the whole batch must be rejected.
    let entries = vec![
        &env,
        (alice.clone(), String::from_str(&env, "US")),
        (bob.clone(), String::from_str(&env, "us")),
    ];
    let result = client.try_set_multiple_jurisdictions(&issuer, &entries);
    assert_eq!(result, Err(Ok(Error::InvalidJurisdictionCode)));

    // Nothing should have been written.
    assert_eq!(client.get_jurisdiction(&alice), None);
    assert_eq!(client.get_jurisdiction(&bob), None);
}

#[test]
fn test_set_multiple_jurisdictions_empty_batch_is_invalid() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);

    let entries: Vec<(Address, String)> = vec![&env];
    let result = client.try_set_multiple_jurisdictions(&issuer, &entries);
    assert_eq!(result, Err(Ok(Error::InvalidInput)));
}

#[test]
fn test_set_multiple_jurisdictions_over_cap_is_invalid() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);

    // Build MAX_BATCH_SIZE + 1 entries.
    let mut entries_vec = soroban_sdk::vec![&env];
    for _ in 0..=super::MAX_BATCH_SIZE {
        entries_vec.push_back((Address::generate(&env), String::from_str(&env, "US")));
    }
    let result = client.try_set_multiple_jurisdictions(&issuer, &entries_vec);
    assert_eq!(result, Err(Ok(Error::InvalidInput)));
}

#[test]
fn test_set_multiple_jurisdictions_compliance_officer_can_set() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    let alice = Address::generate(&env);

    client.set_compliance_officer(&issuer, &officer);

    let entries = vec![
        &env,
        (alice.clone(), String::from_str(&env, "US")),
    ];
    client.set_multiple_jurisdictions(&officer, &entries);

    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
}

#[test]
fn test_compliance_officer_entry_point_access_matrix() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_compliance_officer(&issuer, &officer);

    macro_rules! check_access {
        ($name:literal, $result:expr, $expected:expr) => {{
            let actual = match $result {
                Ok(Ok(())) => true,
                Err(Ok(Error::NotAuthorized)) => false,
                other => panic!("unexpected result for {}: {:?}", $name, other),
            };
            assert_eq!(actual, $expected, "{} officer access mismatch", $name);
        }};
    }

    let officer_entry_points = [
        ("set_jurisdiction", true),
        ("set_jurisdiction_until", true),
        ("add_jurisdiction", true),
        ("set_multiple_jurisdictions", true),
        ("remove_jurisdiction", false),
        ("remove_jurisdiction_multiple", false),
        ("pause", false),
        ("unpause", false),
        ("set_compliance_officer", false),
        ("revoke_compliance_officer", false),
        ("transfer_issuer", false),
        ("propose_issuer", false),
        ("cancel_issuer_proposal", false),
        ("upgrade", false),
    ];

    for (entry_point, expected) in officer_entry_points {
        match entry_point {
            "set_jurisdiction" => check_access!(
                entry_point,
                client.try_set_jurisdiction(&officer, &alice, &code),
                expected
            ),
            "set_jurisdiction_until" => check_access!(
                entry_point,
                client.try_set_jurisdiction_until(&officer, &alice, &code, &env.ledger().sequence()),
                expected
            ),
            "add_jurisdiction" => check_access!(
                entry_point,
                client.try_add_jurisdiction(&officer, &alice, &code),
                expected
            ),
            "set_multiple_jurisdictions" => {
                let entries = vec![&env, (alice.clone(), code.clone())];
                check_access!(
                    entry_point,
                    client.try_set_multiple_jurisdictions(&officer, &entries),
                    expected
                );
            }
            "remove_jurisdiction" => check_access!(
                entry_point,
                client.try_remove_jurisdiction(&officer, &alice, &code),
                expected
            ),
            "remove_jurisdiction_multiple" => {
                let addresses = vec![&env, alice.clone()];
                check_access!(
                    entry_point,
                    client.try_remove_jurisdiction_multiple(&officer, &addresses),
                    expected
                );
            }
            "pause" => check_access!(entry_point, client.try_pause(&officer), expected),
            "unpause" => check_access!(entry_point, client.try_unpause(&officer), expected),
            "set_compliance_officer" => check_access!(
                entry_point,
                client.try_set_compliance_officer(&officer, &bob),
                expected
            ),
            "revoke_compliance_officer" => check_access!(
                entry_point,
                client.try_revoke_compliance_officer(&officer),
                expected
            ),
            "transfer_issuer" => check_access!(
                entry_point,
                client.try_transfer_issuer(&officer, &bob),
                expected
            ),
            "propose_issuer" => check_access!(
                entry_point,
                client.try_propose_issuer(&officer, &bob),
                expected
            ),
            "cancel_issuer_proposal" => check_access!(
                entry_point,
                client.try_cancel_issuer_proposal(&officer),
                expected
            ),
            "upgrade" => {
                let wasm_hash = BytesN::from_array(&env, &[0; 32]);
                check_access!(
                    entry_point,
                    client.try_upgrade(&officer, &wasm_hash),
                    expected
                );
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn test_set_multiple_jurisdictions_paused_contract_is_rejected() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.pause(&issuer);

    let entries = vec![
        &env,
        (alice.clone(), String::from_str(&env, "US")),
    ];
    let result = client.try_set_multiple_jurisdictions(&issuer, &entries);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
    assert_eq!(client.get_jurisdiction(&alice), None);
}

#[test]
fn test_set_multiple_jurisdictions_empty_code_is_invalid() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    let entries = vec![
        &env,
        (alice.clone(), String::from_str(&env, "")),
    ];
    let result = client.try_set_multiple_jurisdictions(&issuer, &entries);
    assert_eq!(result, Err(Ok(Error::InvalidJurisdictionCode)));
    assert_eq!(client.get_jurisdiction(&alice), None);
}

// ---------------------------------------------------------------------------
// Issue #603: two-step issuer transfer (propose / accept / cancel)
// ---------------------------------------------------------------------------

#[test]
fn test_propose_then_accept_issuer_transfers_control() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let new_issuer = Address::generate(&env);
    let alice = Address::generate(&env);

    client.propose_issuer(&issuer, &new_issuer);
    client.accept_issuer(&new_issuer);

    // Old issuer no longer has control.
    let result = client.try_set_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));

    // New issuer does.
    client.set_jurisdiction(&new_issuer, &alice, &String::from_str(&env, "US"));
    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
}

#[test]
fn test_propose_issuer_emits_event() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let new_issuer = Address::generate(&env);

    client.propose_issuer(&issuer, &new_issuer);

    let events = env.events().all();
    // There should be at least one event (IssuerProposed).
    assert!(!events.is_empty());
}

#[test]
fn test_accept_issuer_emits_event() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let new_issuer = Address::generate(&env);

    client.propose_issuer(&issuer, &new_issuer);
    let events_before = env.events().all().len();

    client.accept_issuer(&new_issuer);

    let events_after = env.events().all().len();
    assert!(events_after > events_before, "accept_issuer must emit an event");
}

#[test]
fn test_accept_issuer_with_no_pending_proposal_errors() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let random = Address::generate(&env);

    let result = client.try_accept_issuer(&random);
    assert_eq!(result, Err(Ok(Error::NoPendingIssuer)));
}

#[test]
fn test_accept_issuer_wrong_address_errors() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let proposed = Address::generate(&env);
    let wrong = Address::generate(&env);

    client.propose_issuer(&issuer, &proposed);

    let result = client.try_accept_issuer(&wrong);
    assert_eq!(result, Err(Ok(Error::PendingIssuerMismatch)));

    // Original issuer still in control.
    let alice = Address::generate(&env);
    client.set_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));
    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
}

#[test]
fn test_cancel_issuer_proposal_prevents_accept() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let new_issuer = Address::generate(&env);

    client.propose_issuer(&issuer, &new_issuer);
    client.cancel_issuer_proposal(&issuer);

    // The proposal was cancelled; accept must now fail.
    let result = client.try_accept_issuer(&new_issuer);
    assert_eq!(result, Err(Ok(Error::NoPendingIssuer)));

    // Original issuer is still in control.
    let alice = Address::generate(&env);
    client.set_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));
    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
}

#[test]
fn test_cancel_issuer_proposal_emits_event() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let new_issuer = Address::generate(&env);

    client.propose_issuer(&issuer, &new_issuer);
    let before = env.events().all().len();

    client.cancel_issuer_proposal(&issuer);

    assert!(
        env.events().all().len() > before,
        "cancel_issuer_proposal must emit an event"
    );
}

#[test]
fn test_propose_issuer_requires_current_issuer_auth() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let new_issuer = Address::generate(&env);

    let result = client.try_propose_issuer(&impostor, &new_issuer);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}

#[test]
fn test_upgrade_delay_minimum_boundary() {
    let env = Env::default();
    let (issuer, contract_id, client) = setup(&env);
    let wasm_hash = BytesN::from_array(&env, &[1; 32]);
    let current_sequence = env.ledger().sequence();

    assert_eq!(
        client.try_propose_upgrade(
            &issuer,
            &wasm_hash,
            &(MIN_UPGRADE_DELAY_LEDGERS - 1),
        ),
        Err(Ok(Error::UpgradeDelayTooShort))
    );
    assert_eq!(client.try_commit_upgrade(&issuer), Err(Ok(Error::UpgradeNotReady)));

    client.propose_upgrade(&issuer, &wasm_hash, &MIN_UPGRADE_DELAY_LEDGERS);
    let pending: UpgradeState = env.as_contract(&contract_id, || {
        env.storage()
            .instance()
            .get(&DataKey::PendingUpgrade)
            .unwrap()
    });
    assert_eq!(
        pending.activated_at,
        u64::from(current_sequence) + u64::from(MIN_UPGRADE_DELAY_LEDGERS)
    );
    assert_eq!(client.try_commit_upgrade(&issuer), Err(Ok(Error::UpgradeNotReady)));
}

#[test]
fn test_upgrade_timelock_requires_issuer_and_can_be_cancelled() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let wasm_hash = BytesN::from_array(&env, &[1; 32]);

    assert_eq!(
        client.try_propose_upgrade(&impostor, &wasm_hash, &MIN_UPGRADE_DELAY_LEDGERS),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(client.try_cancel_upgrade(&impostor), Err(Ok(Error::NotAuthorized)));

    client.propose_upgrade(&issuer, &wasm_hash, &MIN_UPGRADE_DELAY_LEDGERS);
    client.cancel_upgrade(&issuer);
    assert_eq!(client.try_commit_upgrade(&issuer), Err(Ok(Error::UpgradeNotReady)));
}

#[test]
fn test_transfer_issuer_emergency_rotation_clears_pending_proposal() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let pending = Address::generate(&env);
    let emergency_new = Address::generate(&env);

    // Set up a pending proposal, then immediately do an emergency rotation.
    client.propose_issuer(&issuer, &pending);
    client.transfer_issuer(&issuer, &emergency_new);

    // The pending address must no longer be able to accept.
    let result = client.try_accept_issuer(&pending);
    assert_eq!(result, Err(Ok(Error::NoPendingIssuer)));

    // emergency_new is now issuer.
    let alice = Address::generate(&env);
    client.set_jurisdiction(&emergency_new, &alice, &String::from_str(&env, "US"));
    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );
}

#[test]
fn test_propose_issuer_overwrites_previous_proposal() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    client.propose_issuer(&issuer, &first);
    // Overwrite with a new proposal.
    client.propose_issuer(&issuer, &second);

    // First proposed address can no longer accept.
    let result = client.try_accept_issuer(&first);
    assert_eq!(result, Err(Ok(Error::PendingIssuerMismatch)));

    // Second proposed address can accept.
    client.accept_issuer(&second);

    let alice = Address::generate(&env);
    client.set_jurisdiction(&second, &alice, &String::from_str(&env, "DE"));
    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "DE"))
    );
}

// ---------------------------------------------------------------------------
// Issue #597: MAX_CODES_PER_ADDRESS cap on add_jurisdiction
// ---------------------------------------------------------------------------

#[test]
fn test_add_jurisdiction_enforces_max_codes_per_address() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    // Fill up to the cap with distinct two-letter codes.
    // There are 26 uppercase letters; generate MAX_CODES_PER_ADDRESS codes.
    let all_codes = ["AA", "BB", "CC", "DD", "EE", "FF", "GG", "HH"];
    assert_eq!(all_codes.len() as u32, super::MAX_CODES_PER_ADDRESS);

    for code in all_codes.iter().take(super::MAX_CODES_PER_ADDRESS as usize - 1) {
        client.add_jurisdiction(&issuer, &alice, &String::from_str(&env, code));
    }
    // The cap-th addition should succeed.
    client.add_jurisdiction(
        &issuer,
        &alice,
        &String::from_str(&env, all_codes[super::MAX_CODES_PER_ADDRESS as usize - 1]),
    );
    // One more must be rejected.
    let result = client.try_add_jurisdiction(&issuer, &alice, &String::from_str(&env, "ZZ"));
    assert_eq!(result, Err(Ok(Error::TooManyCodes)));
}

#[test]
fn test_add_jurisdiction_duplicate_does_not_count_toward_cap() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    // Add a code, then add it again — the duplicate should not increase the count.
    client.add_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));
    client.add_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));

    // Should have exactly one code.
    assert_eq!(
        client.list_jurisdictions(&alice),
        vec![&env, String::from_str(&env, "US")]
    );
}

#[test]
fn test_add_jurisdiction_at_boundary_accepts_up_to_cap() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    let all_codes = ["AA", "BB", "CC", "DD", "EE", "FF", "GG", "HH"];
    for code in all_codes.iter().take(super::MAX_CODES_PER_ADDRESS as usize) {
        client.add_jurisdiction(&issuer, &alice, &String::from_str(&env, code));
    }

    // Exactly MAX_CODES_PER_ADDRESS codes stored.
    assert_eq!(
        client.list_jurisdictions(&alice).len(),
        super::MAX_CODES_PER_ADDRESS
    );
}

#[test]
fn test_instance_ttl_extended_on_initialize_and_mutations() {
    use soroban_sdk::testutils::{storage::Instance as _, Ledger as _};
    let env = Env::default();
    let (issuer, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let new_issuer = Address::generate(&env);

    let ttl = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
    assert_eq!(ttl, crate::INSTANCE_TTL_EXTEND_TO);

    let step = crate::INSTANCE_TTL_EXTEND_TO - crate::INSTANCE_TTL_THRESHOLD + 1;
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + step);
    let aged_ttl = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
    assert!(aged_ttl < crate::INSTANCE_TTL_THRESHOLD);

    client.set_jurisdiction(&issuer, &alice, &String::from_str(&env, "US"));
    let refreshed_ttl = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
    assert_eq!(refreshed_ttl, crate::INSTANCE_TTL_EXTEND_TO);

    client.propose_issuer(&issuer, &new_issuer);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + step);
    let aged_again = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
    assert!(aged_again < crate::INSTANCE_TTL_THRESHOLD);

    client.accept_issuer(&new_issuer);
    let refreshed_on_accept = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
    assert_eq!(refreshed_on_accept, crate::INSTANCE_TTL_EXTEND_TO);
}


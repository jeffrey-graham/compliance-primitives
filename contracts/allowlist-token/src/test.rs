use super::*;
use ed25519_dalek::SigningKey;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::testutils::ed25519::Sign;
use soroban_sdk::{contract, contractimpl, symbol_short, vec, Bytes, BytesN, Env, IntoVal, Map, Symbol, Val, Vec};
use std::path::{Path, PathBuf};

// ─── MockToken ───────────────────────────────────────────────────────────────

/// A minimal token double used only by these tests, so `allowlist-token`'s
/// unit tests don't depend on any particular real SEP-41 implementation.
#[contract]
struct MockToken;

#[contractimpl]
impl MockToken {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        env.storage().instance().set(&Symbol::new(&env, "last"), &(from, to, amount));
    }

    pub fn last_transfer(env: Env) -> Option<(Address, Address, i128)> {
        env.storage().instance().get(&Symbol::new(&env, "last"))
    }
}

// ─── Setup helper ────────────────────────────────────────────────────────────

fn setup(env: &Env) -> (Address, Address, Address, AllowlistTokenClient<'_>) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let token_id = env.register(MockToken, ());
    let contract_id = env.register(AllowlistToken, ());
    let client = AllowlistTokenClient::new(env, &contract_id);
    client.initialize(&admin, &token_id);
    (admin, token_id, contract_id, client)
}

// ─── Budget baseline helpers ─────────────────────────────────────────────────

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

// ─── Delegated-signature helpers ─────────────────────────────────────────────

fn delegated_message_bytes(env: &Env, target: &Address, nonce: u64, expiry: u64) -> Bytes {
    let mut message = Bytes::new(env);
    message.append(&Bytes::from_slice(env, b"allowlist-delegated-v1:"));
    let target_str = target.to_string().to_string();
    message.append(&Bytes::from_slice(env, target_str.as_bytes()));
    message.push_back(b':');
    message.append(&Bytes::from_slice(env, b"add_to_allowlist"));
    message.push_back(b':');
    let nonce_str = nonce.to_string();
    message.append(&Bytes::from_slice(env, nonce_str.as_bytes()));
    message.push_back(b':');
    let expiry_str = expiry.to_string();
    message.append(&Bytes::from_slice(env, expiry_str.as_bytes()));
    message
}

fn sign_delegated_action(
    env: &Env,
    signing_key: &SigningKey,
    target: &Address,
    nonce: u64,
    expiry: u64,
) -> BytesN<64> {
    let message = delegated_message_bytes(env, target, nonce, expiry);
    let sig = signing_key.sign(&message).unwrap();
    BytesN::from_array(env, &sig)
}

fn delegated_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ])
}

// ─── Existing unit tests ──────────────────────────────────────────────────────

#[test]
fn test_initialize_and_allowlist_roundtrip() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    assert!(!client.is_allowed(&alice));
    client.add_to_allowlist(&admin, &alice, &None);
    assert!(client.is_allowed(&alice));
    client.remove_from_allowlist(&admin, &alice);
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_multiple_allowlist_operations() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let addresses = vec![&env, alice.clone(), bob.clone()];

    client.add_multiple_to_allowlist(&admin, &addresses, &None);
    assert!(client.is_allowed(&alice));
    assert!(client.is_allowed(&bob));

    client.remove_multiple_from_allowlist(&admin, &addresses);
    assert!(!client.is_allowed(&alice));
    assert!(!client.is_allowed(&bob));
}

#[test]
fn test_multiple_allowlist_operations_reject_batches_over_limit() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let mut addresses = Vec::new(&env);
    for _ in 0..=MAX_BATCH_SIZE {
        addresses.push_back(Address::generate(&env));
    }

    assert_eq!(
        client.try_add_multiple_to_allowlist(&admin, &addresses, &None),
        Err(Ok(Error::BatchTooLarge))
    );
    assert_eq!(
        client.try_remove_multiple_from_allowlist(&admin, &addresses),
        Err(Ok(Error::BatchTooLarge))
    );
}

#[test]
fn test_multiple_allowlist_operations_reject_non_admin() {
    let env = Env::default();
    let (_admin, _token_id, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let addresses = vec![&env, Address::generate(&env)];

    assert_eq!(
        client.try_add_multiple_to_allowlist(&impostor, &addresses, &None),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(
        client.try_remove_multiple_from_allowlist(&impostor, &addresses),
        Err(Ok(Error::NotAuthorized))
    );
}

#[test]
fn test_transfer_forwards_to_underlying_token_when_both_allowlisted() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    client.add_to_allowlist(&admin, &bob, &None);

    let ok = client.transfer(&alice, &bob, &500);
    assert!(ok);

    let token_client = MockTokenClient::new(&env, &token_id);
    let last = token_client.last_transfer().unwrap();
    assert_eq!(last, (alice, bob, 500));
}

#[test]
fn test_budget_regression_allowlist_transfer() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    client.add_to_allowlist(&admin, &bob, &None);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    let ok = client.transfer(&alice, &bob, &500);
    assert!(ok);

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    let baseline_path = baseline_path_for_manifest_dir(PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()));
    let baseline = read_baseline(&baseline_path, "allowlist-token.transfer");
    assert_budget_within_threshold(measured, baseline, "allowlist-token transfer");
}

#[test]
fn test_budget_regression_allowlist_add_to_allowlist() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    client.add_to_allowlist(&admin, &alice, &None);

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    let baseline_path = baseline_path_for_manifest_dir(PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()));
    let baseline = read_baseline(&baseline_path, "allowlist-token.add_to_allowlist");
    assert_budget_within_threshold(measured, baseline, "allowlist-token add_to_allowlist");
}

#[test]
fn test_budget_regression_allowlist_add_to_allowlist_delegated() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = delegated_signing_key();
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 1, expiry);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    client.add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &signature);

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    let baseline_path = baseline_path_for_manifest_dir(PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()));
    let baseline = read_baseline(&baseline_path, "allowlist-token.add_to_allowlist_delegated");
    assert_budget_within_threshold(measured, baseline, "allowlist-token add_to_allowlist_delegated");
}

/// The delegated path (ed25519 verification plus nonce/pubkey storage access)
/// must cost more CPU than the direct-auth baseline it is compared against.
#[test]
fn test_delegated_add_costs_more_cpu_than_direct_add() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let signing_key = delegated_signing_key();
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &bob, 1, expiry);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    client.add_to_allowlist(&admin, &alice, &None);
    let direct_cpu = budget.cpu_instruction_cost();

    budget.reset_default();
    client.add_to_allowlist_delegated(&admin, &bob, &1u64, &expiry, &signature);
    let delegated_cpu = budget.cpu_instruction_cost();

    assert!(
        delegated_cpu > direct_cpu,
        "delegated add ({delegated_cpu} cpu) should cost more than direct add ({direct_cpu} cpu)"
    );
}

#[test]
fn test_transfer_blocked_when_recipient_not_allowlisted() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);

    let ok = client.transfer(&alice, &bob, &500);
    assert!(!ok);

    // `assert_events_eq` pretty-prints both the actual and expected events on
    // mismatch instead of a single-line raw XDR dump.
    compliance_test_trace::assert_events_eq(
        &env,
        &env.events().all(),
        &vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_add"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
            (
                contract_id.clone(),
                (symbol_short!("blocked"), alice.clone(), bob.clone()).into_val(&env),
                Map::<Symbol, Val>::from_array(&env, [(symbol_short!("amount"), 500i128.into_val(&env))])
                    .into_val(&env),
            ),
        ],
    );
}

#[test]
fn test_add_to_allowlist_rejects_non_admin() {
    let env = Env::default();
    let (_admin, _token_id, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    let result = client.try_add_to_allowlist(&impostor, &alice, &None);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_non_admin_allowlist_mutations_rejected_end_to_end() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    let add_result = client.try_add_to_allowlist(&impostor, &alice, &None);
    assert_eq!(add_result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_allowed(&alice));

    client.add_to_allowlist(&admin, &alice, &None);
    assert!(client.is_allowed(&alice));

    let remove_result = client.try_remove_from_allowlist(&impostor, &alice);
    assert_eq!(remove_result, Err(Ok(Error::NotAuthorized)));
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_pause_blocks_allowlist_mutations_but_allows_admin_rotation() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let next_admin = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice);
    client.pause(&admin);

    assert_eq!(
        client.try_add_to_allowlist(&admin, &Address::generate(&env)),
        Err(Ok(Error::ContractPaused))
    );
    assert_eq!(
        client.try_remove_from_allowlist(&admin, &alice),
        Err(Ok(Error::ContractPaused))
    );
    assert!(client.is_allowed(&alice));

    client.propose_admin(&admin, &next_admin);
    client.accept_admin(&next_admin);
    assert_eq!(client.get_admin(), next_admin);
}

#[test]
fn test_delegated_add_to_allowlist_succeeds() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 1, expiry);

    client.add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &signature);
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_delegated_add_to_allowlist_rejects_replay() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 1, expiry);

    client.add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &signature);
    let replay = client.try_add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &signature);
    assert_eq!(replay, Err(Ok(Error::InvalidNonce)));
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_delegated_add_to_allowlist_rejects_expired_signature() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    env.ledger().set_timestamp(100);
    let expiry = 99u64;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 1, expiry);

    let result = client.try_add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &signature);
    assert_eq!(result, Err(Ok(Error::ExpiredSignature)));
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_delegated_add_to_allowlist_rejects_non_admin_key() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let attacker_key = SigningKey::from_bytes(&[
        32u8, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
        54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &attacker_key, &alice, 1, expiry);

    let result = client.try_add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &signature);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_remove_from_allowlist_never_added_is_noop() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let never_added = Address::generate(&env);

    assert!(!client.is_allowed(&never_added));

    client.remove_from_allowlist(&admin, &never_added);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_remove"), never_added.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
    assert!(!client.is_allowed(&never_added));
}

#[test]
fn test_is_allowed_false_before_initialize() {
    let env = Env::default();
    let contract_id = env.register(AllowlistToken, ());
    let client = AllowlistTokenClient::new(&env, &contract_id);
    let alice = Address::generate(&env);

    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_get_admin_returns_initialized_admin() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);

    assert_eq!(client.get_admin(), admin);
}

#[test]
fn test_get_admin_tracks_admin_transfer() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let new_admin = Address::generate(&env);

    assert_eq!(client.get_admin(), admin);
    client.transfer_admin(&admin, &new_admin);
    assert_eq!(client.get_admin(), new_admin);
}

#[test]
fn test_get_admin_fails_before_initialize() {
    let env = Env::default();
    let contract_id = env.register(AllowlistToken, ());
    let client = AllowlistTokenClient::new(&env, &contract_id);

    let result = client.try_get_admin();
    assert_eq!(result, Err(Ok(Error::NotInitialized)));
}

#[test]
fn test_double_initialize_fails() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let result = client.try_initialize(&admin, &token_id);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn test_add_to_allowlist_emits_allow_add_event() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_add"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_remove_from_allowlist_emits_allow_remove_event() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    client.add_to_allowlist(&admin, &alice, &None);

    client.remove_from_allowlist(&admin, &alice);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_add"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_remove"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_add_to_allowlist_extends_persistent_ttl() {
    use soroban_sdk::testutils::storage::Persistent as _;
    use soroban_sdk::testutils::Ledger;

    let env = Env::default();
    env.ledger().with_mut(|li| {
        li.sequence_number = 100_000;
        li.min_persistent_entry_ttl = 500;
        li.max_entry_ttl = 6_311_520;
    });

    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);

    env.as_contract(&contract_id, || {
        let ttl = env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Allowed(alice.clone()));
        assert_eq!(
            ttl, ALLOWED_TTL_EXTEND_TO,
            "fresh allowlist write should bump TTL to ALLOWED_TTL_EXTEND_TO"
        );
    });

    // Advance far enough that remaining TTL falls below the threshold, then
    // re-add and confirm extension runs again.
    env.ledger().with_mut(|li| {
        li.sequence_number += ALLOWED_TTL_EXTEND_TO - ALLOWED_TTL_THRESHOLD + 1;
    });
    env.as_contract(&contract_id, || {
        let ttl = env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Allowed(alice.clone()));
        assert!(
            ttl < ALLOWED_TTL_THRESHOLD,
            "TTL should be below threshold after ledger bump, got {ttl}"
        );
    });

    client.add_to_allowlist(&admin, &alice, &None);
    env.as_contract(&contract_id, || {
        let ttl = env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Allowed(alice.clone()));
        assert_eq!(ttl, ALLOWED_TTL_EXTEND_TO);
    });
}

#[test]
fn test_transfers_keep_allowlist_entries_live_past_original_ttl() {
    use soroban_sdk::testutils::storage::Persistent as _;

    let env = Env::default();
    env.ledger().with_mut(|li| {
        li.sequence_number = 100_000;
        li.min_persistent_entry_ttl = 500;
        li.max_entry_ttl = 6_311_520;
    });

    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.add_to_allowlist(&admin, &alice);
    client.add_to_allowlist(&admin, &bob);

    let transfer_interval = ALLOWED_TTL_EXTEND_TO - ALLOWED_TTL_THRESHOLD + 1;
    for _ in 0..3 {
        env.ledger().with_mut(|li| li.sequence_number += transfer_interval);
        assert!(client.transfer(&alice, &bob, &1));
        env.as_contract(&contract_id, || {
            for address in [&alice, &bob] {
                let ttl = env
                    .storage()
                    .persistent()
                    .get_ttl(&DataKey::Allowed(address.clone()));
                assert_eq!(ttl, ALLOWED_TTL_EXTEND_TO);
            }
        });
    }

    assert!(client.is_allowed(&alice));
    assert!(client.is_allowed(&bob));
}

/// Property: after any sequence of add/remove on a fixed address pool,
/// `is_allowed(addr)` matches whether the last op touching `addr` was an add.
#[test]
fn prop_allowlist_add_remove_last_write_wins() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, TestRunner};

    #[derive(Clone, Debug)]
    enum Op {
        Add(usize),
        Remove(usize),
    }

    let mut runner = TestRunner::new(Config {
        cases: 64,
        max_shrink_iters: 100,
        ..Config::default()
    });

    runner
        .run(
            &(1usize..32).prop_flat_map(|len| {
                proptest::collection::vec(
                    (0usize..4).prop_flat_map(|addr_i| {
                        proptest::bool::ANY.prop_map(move |is_add| {
                            if is_add {
                                Op::Add(addr_i)
                            } else {
                                Op::Remove(addr_i)
                            }
                        })
                    }),
                    len,
                )
            }),
            |ops| {
                let env = Env::default();
                let (admin, _token_id, _contract_id, client) = setup(&env);
                let addresses: [Address; 4] = [
                    Address::generate(&env),
                    Address::generate(&env),
                    Address::generate(&env),
                    Address::generate(&env),
                ];
                let mut model = [false; 4];

                for op in &ops {
                    match *op {
                        Op::Add(i) => {
                            client.add_to_allowlist(&admin, &addresses[i], &None);
                            model[i] = true;
                        }
                        Op::Remove(i) => {
                            client.remove_from_allowlist(&admin, &addresses[i]);
                            model[i] = false;
                        }
                    }
                }

                for (i, address) in addresses.iter().enumerate() {
                    prop_assert_eq!(
                        client.is_allowed(address),
                        model[i],
                        "addr {} mismatch after {:?}",
                        i,
                        ops
                    );
                }
                Ok(())
            },
        )
        .unwrap();
}

// ─── Compliance officer (#357) ───────────────────────────────────────────────

#[test]
fn test_officer_can_remove_from_allowlist_after_assignment() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    client.set_compliance_officer(&admin, &officer);

    client.remove_from_allowlist(&officer, &alice);
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_officer_cannot_assign_or_revoke_officer_role() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    let other = Address::generate(&env);

    client.set_compliance_officer(&admin, &officer);

    assert_eq!(
        client.try_set_compliance_officer(&officer, &other),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(
        client.try_revoke_compliance_officer(&officer),
        Err(Ok(Error::NotAuthorized))
    );
}

#[test]
fn test_officer_cannot_add_to_allowlist() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    let alice = Address::generate(&env);

    client.set_compliance_officer(&admin, &officer);

    assert_eq!(
        client.try_add_to_allowlist(&officer, &alice, &None),
        Err(Ok(Error::NotAuthorized))
    );
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_revoked_officer_can_no_longer_remove_from_allowlist() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    client.set_compliance_officer(&admin, &officer);
    client.revoke_compliance_officer(&admin);

    assert_eq!(
        client.try_remove_from_allowlist(&officer, &alice),
        Err(Ok(Error::NotAuthorized))
    );
    assert!(client.is_allowed(&alice));
}

// ─── Pause / unpause / is_paused (#358) ──────────────────────────────────────

#[test]
fn test_transfer_blocked_while_paused_and_succeeds_after_unpause() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.add_to_allowlist(&admin, &alice, &None);
    client.add_to_allowlist(&admin, &bob, &None);

    assert!(!client.is_paused());
    client.pause(&admin);
    assert!(client.is_paused());
    assert_eq!(
        client.try_transfer(&alice, &bob, &10),
        Err(Ok(Error::ContractPaused))
    );

    client.unpause(&admin);
    assert!(!client.is_paused());
    assert!(client.transfer(&alice, &bob, &10));
    let token = MockTokenClient::new(&env, &token_id);
    assert_eq!(token.last_transfer(), Some((alice, bob, 10)));
}

/// Pause blocks add/remove so a paused contract's allowlist stays frozen.
/// Admin rotation and unpause remain available (regression test for #583).
#[test]
fn test_pause_blocks_add_to_allowlist() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let bob = Address::generate(&env);

    client.pause(&admin);

    assert_eq!(
        client.try_add_to_allowlist(&admin, &bob, &None),
        Err(Ok(Error::ContractPaused))
    );
    assert!(!client.is_allowed(&bob));
}

#[test]
fn test_pause_blocks_remove_from_allowlist() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    client.add_to_allowlist(&admin, &alice, &None);

    client.pause(&admin);

    assert_eq!(
        client.try_remove_from_allowlist(&admin, &alice),
        Err(Ok(Error::ContractPaused))
    );
    // Entry must still be there — the allowlist must stay frozen.
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_unpause_restores_allowlist_mutations() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let bob = Address::generate(&env);

    client.pause(&admin);
    client.unpause(&admin);

    // After unpause, mutations work again.
    client.add_to_allowlist(&admin, &bob, &None);
    assert!(client.is_allowed(&bob));
}

#[test]
fn test_admin_rotation_works_while_paused() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let new_admin = Address::generate(&env);

    client.pause(&admin);
    // propose_admin / accept_admin must succeed while paused so a compromised
    // key can always be rotated out.
    client.propose_admin(&admin, &new_admin);
    client.accept_admin(&new_admin);
    assert_eq!(client.get_admin(), new_admin);
}

#[test]
fn test_pause_and_unpause_reject_non_admin() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);

    assert_eq!(client.try_pause(&impostor), Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_paused());

    client.pause(&admin);
    assert_eq!(client.try_unpause(&impostor), Err(Ok(Error::NotAuthorized)));
    assert!(client.is_paused());
}

// ─── get_delegated_nonce (#359) ──────────────────────────────────────────────

#[test]
fn test_get_delegated_nonce_is_zero_before_any_delegated_call() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);

    assert_eq!(client.get_delegated_nonce(&admin), 0);
}

#[test]
fn test_instance_ttl_extended_on_initialize_and_mutations() {
    use soroban_sdk::testutils::{storage::Instance as _, Ledger as _};
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let new_admin = Address::generate(&env);

    let ttl = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
    assert_eq!(ttl, crate::INSTANCE_TTL_EXTEND_TO);

    let step = crate::INSTANCE_TTL_EXTEND_TO - crate::INSTANCE_TTL_THRESHOLD + 1;
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + step);
    let aged_ttl = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
    assert!(aged_ttl < crate::INSTANCE_TTL_THRESHOLD);

    client.add_to_allowlist(&admin, &alice, &None);
    let refreshed_ttl = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
    assert_eq!(refreshed_ttl, crate::INSTANCE_TTL_EXTEND_TO);

    client.propose_admin(&admin, &new_admin);
    env.ledger()
        .set_sequence_number(env.ledger().sequence() + step);
    let aged_again = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
    assert!(aged_again < crate::INSTANCE_TTL_THRESHOLD);

    client.accept_admin(&new_admin);
    let refreshed_on_accept = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
    assert_eq!(refreshed_on_accept, crate::INSTANCE_TTL_EXTEND_TO);
}

#[test]
fn test_get_delegated_nonce_returns_last_used_nonce() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = delegated_signing_key();
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 7, expiry);
    client.add_to_allowlist_delegated(&admin, &alice, &7u64, &expiry, &signature);

    assert_eq!(client.get_delegated_nonce(&admin), 7);
}

#[test]
fn test_proposal_lifecycle_events_include_payloads() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let proposed_admin = Address::generate(&env);
    let new_wasm = BytesN::from_array(&env, &[7; 32]);
    let activated_at = u64::from(env.ledger().sequence()) + 10;

    client.propose_admin(&admin, &proposed_admin);
    client.propose_upgrade(&admin, &new_wasm, &10);

    compliance_test_trace::assert_events_eq(
        &env,
        &env.events().all(),
        &vec![
            &env,
            (
                contract_id.clone(),
                (
                    Symbol::new(&env, "admin_proposed"),
                    admin.clone(),
                    proposed_admin.clone(),
                )
                    .into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
            (
                contract_id,
                (Symbol::new(&env, "upgrade_proposed"), admin.clone()).into_val(&env),
                Map::<Symbol, Val>::from_array(
                    &env,
                    [
                        (Symbol::new(&env, "activated_at"), activated_at.into_val(&env)),
                        (Symbol::new(&env, "new_wasm"), new_wasm.into_val(&env)),
                    ],
                )
                .into_val(&env),
            ),
        ],
    );
}

#[test]
fn test_upgrade_cancel_event_includes_admin() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let new_wasm = BytesN::from_array(&env, &[9; 32]);
    client.propose_upgrade(&admin, &new_wasm, &10);

    client.cancel_upgrade(&admin);

    let events = env.events().all();
    let (_, topics, data) = events.last().unwrap();
    assert_eq!(
        topics,
        (Symbol::new(&env, "upgrade_cancelled"), admin).into_val(&env)
    );
    assert_eq!(data, Map::<Symbol, Val>::new(&env).into_val(&env));
    assert_eq!(events.last().unwrap().0, contract_id);
}

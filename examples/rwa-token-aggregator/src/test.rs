use crate::{Error, RwaTokenAggregator, RwaTokenAggregatorClient};
use compliance_aggregator::{ComplianceAggregator, ComplianceAggregatorClient};
use denylist_gate::{DenylistGate, DenylistGateClient};
use jurisdiction_flag::{JurisdictionFlag, JurisdictionFlagClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, contracttype, vec, Address, Env, String};

/// Minimal circuit-breaker test fixture implementing `is_frozen() -> bool`
/// so the full 3-gate aggregator flow (`denylist-gate` + `jurisdiction-flag`
/// + `circuit-breaker`) can be exercised end-to-end.
#[contracttype]
#[derive(Clone)]
enum BreakerKey {
    Frozen,
}

#[contract]
pub struct TestCircuitBreaker;

#[contractimpl]
impl TestCircuitBreaker {
    pub fn set_frozen(env: Env, frozen: bool) {
        env.storage().instance().set(&BreakerKey::Frozen, &frozen);
    }

    pub fn is_frozen(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&BreakerKey::Frozen)
            .unwrap_or(false)
    }
}

struct TestFixture<'a> {
    admin: Address,
    alice: Address,
    bob: Address,
    denylist: DenylistGateClient<'a>,
    jurisdiction: JurisdictionFlagClient<'a>,
    breaker: TestCircuitBreakerClient<'a>,
    token: RwaTokenAggregatorClient<'a>,
}

fn setup(env: &Env) -> TestFixture<'_> {
    env.mock_all_auths();

    let admin = Address::generate(env);
    let alice = Address::generate(env);
    let bob = Address::generate(env);

    let denylist_id = env.register(DenylistGate, ());
    let denylist = DenylistGateClient::new(env, &denylist_id);
    denylist.initialize(&admin);

    let jurisdiction_id = env.register(JurisdictionFlag, ());
    let jurisdiction = JurisdictionFlagClient::new(env, &jurisdiction_id);
    jurisdiction.initialize(&admin);

    let breaker_id = env.register(TestCircuitBreaker, ());
    let breaker = TestCircuitBreakerClient::new(env, &breaker_id);
    breaker.set_frozen(&false);

    let agg_id = env.register(ComplianceAggregator, ());
    let agg = ComplianceAggregatorClient::new(env, &agg_id);
    agg.initialize(
        &admin,
        &Some(denylist_id),
        &Some(jurisdiction_id),
        &Some(breaker_id),
    );

    let token_id = env.register(RwaTokenAggregator, ());
    let token = RwaTokenAggregatorClient::new(env, &token_id);
    let allowed = vec![
        env,
        String::from_str(env, "US"),
        String::from_str(env, "CH"),
    ];
    token.initialize(&admin, &agg_id, &allowed);

    // Default: both Alice (US) and Bob (CH) are in permitted jurisdictions,
    // neither is denylisted, and Alice starts with 1,000 tokens.
    jurisdiction.set_jurisdiction(&admin, &alice, &String::from_str(env, "US"));
    jurisdiction.set_jurisdiction(&admin, &bob, &String::from_str(env, "CH"));
    token.mint(&admin, &alice, &1_000);

    TestFixture {
        admin,
        alice,
        bob,
        denylist,
        jurisdiction,
        breaker,
        token,
    }
}

#[test]
fn test_transfer_succeeds_when_all_three_aggregator_checks_pass() {
    let env = Env::default();
    let f = setup(&env);

    f.token.transfer(&f.alice, &f.bob, &400);
    assert_eq!(f.token.balance(&f.alice), 600);
    assert_eq!(f.token.balance(&f.bob), 400);
}

#[test]
fn test_transfer_blocked_when_sender_or_receiver_is_denylisted() {
    let env = Env::default();
    let f = setup(&env);

    f.denylist.add_to_denylist(&f.admin, &f.alice);
    assert_eq!(
        f.token.try_transfer(&f.alice, &f.bob, &100),
        Err(Ok(Error::SenderDenylisted))
    );

    f.denylist.remove_from_denylist(&f.admin, &f.alice);
    f.denylist.add_to_denylist(&f.admin, &f.bob);
    assert_eq!(
        f.token.try_transfer(&f.alice, &f.bob, &100),
        Err(Ok(Error::ReceiverDenylisted))
    );
}

#[test]
fn test_transfer_blocked_when_jurisdiction_not_permitted() {
    let env = Env::default();
    let f = setup(&env);

    f.jurisdiction
        .set_jurisdiction(&f.admin, &f.bob, &String::from_str(&env, "KP"));
    assert_eq!(
        f.token.try_transfer(&f.alice, &f.bob, &100),
        Err(Ok(Error::ReceiverJurisdictionBlocked))
    );

    f.jurisdiction
        .set_jurisdiction(&f.admin, &f.bob, &String::from_str(&env, "CH"));
    f.jurisdiction
        .set_jurisdiction(&f.admin, &f.alice, &String::from_str(&env, "IR"));
    assert_eq!(
        f.token.try_transfer(&f.alice, &f.bob, &100),
        Err(Ok(Error::SenderJurisdictionBlocked))
    );
}

#[test]
fn test_transfer_blocked_when_circuit_breaker_is_frozen_and_resumes_after_unfreeze() {
    let env = Env::default();
    let f = setup(&env);

    f.breaker.set_frozen(&true);
    assert_eq!(
        f.token.try_transfer(&f.alice, &f.bob, &250),
        Err(Ok(Error::EmergencyFrozen))
    );
    assert_eq!(f.token.balance(&f.alice), 1_000);
    assert_eq!(f.token.balance(&f.bob), 0);

    f.breaker.set_frozen(&false);
    f.token.transfer(&f.alice, &f.bob, &250);
    assert_eq!(f.token.balance(&f.alice), 750);
    assert_eq!(f.token.balance(&f.bob), 250);
}

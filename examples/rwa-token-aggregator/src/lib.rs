//! Worked example: an RWA token contract that delegates its entire transfer
//! compliance check (`denylist-gate`, `jurisdiction-flag`, and `circuit-breaker`)
//! to a single [`compliance-aggregator`] contract.
//!
//! ## Why route through `compliance-aggregator`?
//!
//! Compare this contract with [`examples/rwa-token`]:
//! - `examples/rwa-token` stores each primitive's contract ID directly in its
//!   own instance storage and orchestrates multiple cross-contract calls on
//!   every `transfer`.
//! - `rwa-token-aggregator` stores only **one** external compliance dependency —
//!   the deployed `compliance-aggregator` address — plus the token's permitted
//!   ISO-3166-1 alpha-2 jurisdiction codes.
//!
//! On every `transfer(from, to, amount)`, the token invokes
//! `compliance-aggregator.check_address` for `from` and `to`. Inside the
//! aggregator:
//! 1. If a `circuit-breaker` is registered and currently frozen, the aggregator
//!    short-circuits immediately (`(false, [CheckResult { check: CircuitBreaker, passed: false }])`).
//! 2. If `denylist-gate` is registered and the party is denylisted, the
//!    aggregator records `CheckKind::Denylist` with `passed: false`.
//! 3. If `jurisdiction-flag` is registered and the party's jurisdiction is not
//!    in `allowed_codes`, the aggregator records `CheckKind::Jurisdiction` with
//!    `passed: false`.
//!
//! This keeps the token contract lean and allows the compliance team to rotate
//! primitive addresses or wire in a `circuit-breaker` at the aggregator level
//! without redeploying or reconfiguring the token contract.

#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, Address,
    Env, String, Vec,
};

// ---------------------------------------------------------------------------
// Cross-contract interface for `compliance-aggregator`
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CheckKind {
    Denylist = 0,
    Jurisdiction = 1,
    CircuitBreaker = 2,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    pub check: CheckKind,
    pub passed: bool,
}

#[contractclient(name = "ComplianceAggregatorClient")]
pub trait ComplianceAggregatorInterface {
    fn check_address(
        env: Env,
        address: Address,
        allowed_jurisdictions: Vec<String>,
    ) -> (bool, Vec<CheckResult>);
}

// ---------------------------------------------------------------------------
// Storage & Errors
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Aggregator,
    AllowedJurisdictions,
    Balance(Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    InvalidAmount = 4,
    InsufficientBalance = 5,
    EmergencyFrozen = 6,
    SenderDenylisted = 7,
    ReceiverDenylisted = 8,
    SenderJurisdictionBlocked = 9,
    ReceiverJurisdictionBlocked = 10,
}

#[contractevent]
pub struct Transfer {
    #[topic]
    pub from: Address,
    #[topic]
    pub to: Address,
    pub amount: i128,
}

#[contract]
pub struct RwaTokenAggregator;

#[contractimpl]
impl RwaTokenAggregator {
    /// Initialize the RWA token with an `admin`, the `compliance-aggregator`
    /// contract address, and the initial list of permitted ISO-3166-1 alpha-2
    /// jurisdiction codes.
    pub fn initialize(
        env: Env,
        admin: Address,
        aggregator: Address,
        allowed_jurisdictions: Vec<String>,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::Aggregator, &aggregator);
        env.storage()
            .instance()
            .set(&DataKey::AllowedJurisdictions, &allowed_jurisdictions);
        Ok(())
    }

    /// Mint `amount` tokens to `to`. Admin-only.
    pub fn mint(env: Env, admin: Address, to: Address, amount: i128) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        let bal = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to), &(bal + amount));
        Ok(())
    }

    /// Transfer `amount` tokens from `from` to `to`, gated by a single
    /// `compliance-aggregator` instance that composes `circuit-breaker`,
    /// `denylist-gate`, and `jurisdiction-flag`.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<(), Error> {
        from.require_auth();
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let aggregator: Address = env
            .storage()
            .instance()
            .get(&DataKey::Aggregator)
            .ok_or(Error::NotInitialized)?;
        let allowed: Vec<String> = env
            .storage()
            .instance()
            .get(&DataKey::AllowedJurisdictions)
            .unwrap_or_else(|| Vec::new(&env));

        let agg_client = ComplianceAggregatorClient::new(&env, &aggregator);

        // 1. Check sender compliance via aggregator
        let (sender_passed, sender_checks) = agg_client.check_address(&from, &allowed);
        if !sender_passed {
            return Err(Self::map_failure(&sender_checks, true));
        }

        // 2. Check receiver compliance via aggregator
        let (receiver_passed, receiver_checks) = agg_client.check_address(&to, &allowed);
        if !receiver_passed {
            return Err(Self::map_failure(&receiver_checks, false));
        }

        // 3. Apply balance updates
        let from_bal = Self::balance(env.clone(), from.clone());
        if from_bal < amount {
            return Err(Error::InsufficientBalance);
        }
        let to_bal = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&DataKey::Balance(from.clone()), &(from_bal - amount));
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to.clone()), &(to_bal + amount));

        Transfer { from, to, amount }.publish(&env);
        Ok(())
    }

    /// Return the token balance of `account`.
    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if admin != *caller {
            return Err(Error::NotAuthorized);
        }
        Ok(())
    }

    fn map_failure(checks: &Vec<CheckResult>, is_sender: bool) -> Error {
        for item in checks.iter() {
            if !item.passed {
                match item.check {
                    CheckKind::CircuitBreaker => return Error::EmergencyFrozen,
                    CheckKind::Denylist => {
                        return if is_sender {
                            Error::SenderDenylisted
                        } else {
                            Error::ReceiverDenylisted
                        };
                    }
                    CheckKind::Jurisdiction => {
                        return if is_sender {
                            Error::SenderJurisdictionBlocked
                        } else {
                            Error::ReceiverJurisdictionBlocked
                        };
                    }
                }
            }
        }
        Error::NotAuthorized
    }
}

#[cfg(test)]
mod test;

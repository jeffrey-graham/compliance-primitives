# Examples

This directory contains example Soroban contracts (Rust) and off-chain
scripts showing how to compose and call the compliance-primitives.

Each example focuses on a specific composition pattern. Use the table below
to find the right starting point for your use case.

## Quick-reference table

| Example | Primitives demonstrated | Composition pattern |
| --- | --- | --- |
| [`allowlist-token-usage`](./allowlist-token-usage) | `allowlist-token` | Shell script invoking `allowlist-token` via the Stellar CLI, plus a Rust `walkthrough()` driving the same lifecycle through a generated client |
| [`circuit-breaker-policy-engine`](./circuit-breaker-policy-engine) | `circuit-breaker`, `policy-engine` | Circuit breaker checked as a fast-fail pre-guard before delegating to a `policy-engine` evaluation; shows priority ordering of emergency-stop vs. rule-based checks |
| [`compliance-integration-flow`](./compliance-integration-flow) | `jurisdiction-flag`, `policy-engine`, `compliance-aggregator`, `multisig-admin`, `circuit-breaker`, `audit-log` | Policy-based transfer flow with a circuit-breaker gate, multisig administration, and audit logging |
| [`denylist-gate-consumer`](./denylist-gate-consumer) | `denylist-gate`, `circuit-breaker` | Minimal token calling `denylist-gate.check` and `circuit-breaker.is_frozen` before every transfer; the simplest cross-contract composition pattern |
| [`denylist-gate-sep41`](./denylist-gate-sep41) | `denylist-gate` | Full SEP-41 token interface gated by a single `denylist-gate`; demonstrates how to wire compliance into a standard token without changing its public API |
| [`jurisdiction-denylist-consumer`](./jurisdiction-denylist-consumer) | `denylist-gate`, `jurisdiction-flag` | Token combining both a denylist gate and a jurisdiction check in one `transfer` path; shows AND-composition of two independent compliance gates |
| [`jurisdiction-flag-consumer`](./jurisdiction-flag-consumer) | `jurisdiction-flag` | Token enforcing per-address jurisdiction codes; shows `is_permitted_jurisdiction` as the sole transfer gate |
| [`js-client`](./js-client) | `denylist-gate` (any contract) | Off-chain TypeScript script calling a deployed contract's read-only function via `@stellar/stellar-sdk`; the only non-Rust example |
| [`multisig-aggregator`](./multisig-aggregator) | `multisig-admin`, `compliance-aggregator` | Uses a multisig as the admin of a compliance aggregator; shows M-of-N authorization controlling a batched compliance check |
| [`multisig-audit-trail`](./multisig-audit-trail) | `multisig-admin`, `audit-log` | Multisig-gated admin actions that write to the on-chain audit log; shows how administrative decisions can be both multi-authorized and auditable |
| [`pausable-consumer`](./pausable-consumer) | `pausable` | Contract embedding the `pausable` library directly at compile time; shows the pause/unpause pattern without requiring a cross-contract call |
| [`policy-engine-audit`](./policy-engine-audit) | `policy-engine`, `audit-log` | Policy evaluation results forwarded to the on-chain audit log; shows composing rule-based checks with an immutable compliance trail |
| [`rwa-compliance-flow`](./rwa-compliance-flow) | `allowlist-token`, `denylist-gate`, `jurisdiction-flag` | Integration test for the full compliance stack: all three primitives evaluated in series with specific per-gate error handling |
| [`rwa-token`](./rwa-token) | `allowlist-token`, `denylist-gate`, `jurisdiction-flag`, `circuit-breaker` | Reference RWA token composing all four core primitives in one `transfer` path; the most complete production-like example (testnet deployment available) |
| [`rwa-token-aggregator`](./rwa-token-aggregator) | `compliance-aggregator`, `denylist-gate`, `jurisdiction-flag`, `circuit-breaker` | RWA token delegating its entire transfer compliance gate (`denylist-gate` + `jurisdiction-flag` + `circuit-breaker`) to a single `compliance-aggregator` instance |

## Which example should I start with?

- **New to compliance-primitives?** Start with
  [`denylist-gate-consumer`](./denylist-gate-consumer) — it's the simplest
  cross-contract composition.
- **Building a SEP-41 token?** See
  [`denylist-gate-sep41`](./denylist-gate-sep41) for the full interface and
  [`rwa-token`](./rwa-token) for the production-like multi-gate version.
- **Need an emergency stop?** See
  [`circuit-breaker-policy-engine`](./circuit-breaker-policy-engine).
- **Need jurisdiction enforcement?** See
  [`jurisdiction-flag-consumer`](./jurisdiction-flag-consumer) or
  [`jurisdiction-denylist-consumer`](./jurisdiction-denylist-consumer).
- **Calling a contract from JavaScript/TypeScript?** See
  [`js-client`](./js-client).
- **Want the full RWA reference implementation?** See
  [`rwa-token`](./rwa-token) — it has a
  [TESTNET.md](./rwa-token/TESTNET.md) with a live testnet walkthrough.

## Running the Rust examples

Each Rust example is a standalone Soroban contract. From the repo root:

```sh
# Test a single example
cargo test -p denylist-gate-sep41

# Build a single example to wasm
cargo build -p rwa-token --target wasm32v1-none --release
```

See the root [README.md](../README.md) and [QUICKSTART.md](../QUICKSTART.md)
for the full build and testnet deployment workflow.

## Running the JS example

See [`js-client/README.md`](./js-client/README.md).

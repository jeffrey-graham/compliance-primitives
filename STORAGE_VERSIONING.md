# Storage-Layout Versioning Policy

This document states this project's semver/compatibility commitments around
on-chain storage layout as contracts gain upgrade support. Soroban's
`update_current_contract_wasm` (used by [`jurisdiction-flag`'s timelocked
upgrade functions](./contracts/jurisdiction-flag/UPGRADE.md), and by any primitive
that adds upgrade support after it) swaps contract *code* in place but never
touches contract *storage*. That means the new code must still be able to
make sense of whatever the old code already wrote — storage layout
compatibility isn't automatic, it's a commitment the code has to keep.

This applies to every `#[contracttype]` used as a storage key or a stored
value (most centrally each contract's `DataKey` enum), in any contract that
has, or later gains, an `upgrade()` entrypoint. A contract with no upgrade
path can change its storage layout freely at any version — a new deployment
starts with empty storage, so there's nothing to stay compatible with.

## Versioning scheme

All crates in this workspace currently share `workspace.package.version`
(`0.1.0` — pre-1.0). Per [SemVer](https://semver.org/), pre-1.0 gives no
compatibility guarantee between any two versions by convention alone — but
because these are deployed, stateful contracts rather than a library
consumers merely recompile against, this project commits to more than bare
SemVer implies even pre-1.0:

- **Pre-1.0 (`0.x`)**: a storage-layout change may ship in any `0.x` bump,
  but every such change **must** be called out explicitly in that
  contract's `UPGRADE.md` (see [Change categories](#change-categories)
  below for what counts) and in the PR description. Silent storage-layout
  changes are never acceptable, pre-1.0 or not.
- **Post-1.0**: a breaking storage-layout change requires a major version
  bump of the affected contract crate and a documented, tested migration
  path (see [Migration support](#migration-support)). A non-breaking
  storage-layout change may ship in a minor or patch bump.

Each contract crate is expected to eventually version independently (as
[`contracts/pausable`'s crates.io publishing
setup](./contracts/pausable/README.md) already anticipates for that crate)
rather than strictly following the shared workspace version — a contract's
storage-layout compatibility is a property of *that contract's* deployed
instances, not the workspace as a whole.

## Change categories

Soroban's `#[contracttype]` derive encodes each enum variant (including
`DataKey`-style storage-key enums) as an XDR vector whose first element is
the variant's **name**, not its declaration position or discriminant. Two
consequences that drive everything below:

- Reordering variants in the Rust source, or adding a new variant anywhere
  in the enum, does not change the storage key any existing variant maps
  to.
- Renaming a variant *does* change its storage key — stored data under the
  old name becomes permanently unreachable through the new code, silently.

### Non-breaking (no migration required)

- Adding a new `DataKey` variant (or any new key), as long as it doesn't
  collide with an existing key's encoded form.
- Reordering existing variants in the enum's source declaration.
- Adding a new optional field to a struct that has never yet been persisted
  to storage under a shipped contract version.
- Adding a new public function that reads or writes only newly-introduced
  keys.

### Breaking — requires a documented migration path (or is disallowed)

- **Renaming an existing, already-shipped `DataKey` variant** (or any
  storage-key-bearing type). Disallowed unless paired with a migration step
  that reads the old key and re-writes it under the new one before the old
  key is ever queried under the new name.
- **Changing the shape of an already-persisted stored value** (adding a
  required field to a struct instances of it already exist in storage for,
  changing a field's type, or changing how an enum used as a *value*
  encodes). Old stored values won't deserialize into the new shape.
  Disallowed unless the migration either transforms existing entries to the
  new shape or the code is written to tolerate both shapes (e.g. a `V1`/`V2`
  wrapper enum) until a migration pass has run.
- **Changing the meaning of an existing key's value in place** without
  changing its name or type (e.g. a `bool` that used to mean "paused" now
  meaning something else). This is a silent behavior change for existing
  deployments and is disallowed outright — introduce a new key instead.
- **Removing a `DataKey` variant** that shipped in a prior version and may
  still be populated in a live deployment. The orphaned entry keeps
  consuming TTL/rent and its data becomes permanently unreadable. Disallowed
  without a documented migration step that first clears or transforms any
  existing entries under that key.

If you're not sure which category a change falls into, treat it as breaking
and ask in the PR before merging — treating a breaking change as
non-breaking corrupts every live deployment on the old version, silently
and irreversibly.

## Migration support

Soroban has no automatic storage migration and no rollback: `upgrade()`
swaps code only, and once new code is running there is no way back to the
old code short of another `upgrade()` call. Per the [SPEC.md executive
summary](./SPEC.md#executive-summary), these are stateless gates with no
recovery mechanism — that principle extends to upgrades themselves.

For any breaking change (per the categories above):

1. **A migration path must be designed and tested before the upgrade ships**
   — as either a dedicated `migrate_*` function called once, manually, after
   `upgrade()` completes (this project's convention; see [Future
   Enhancements](./contracts/jurisdiction-flag/UPGRADE.md#future-enhancements)
   in `jurisdiction-flag`'s upgrade doc), or code that tolerates reading
   both the old and new shapes until a migration pass has run to
   completion.
2. **The migration path is documented in that contract's `UPGRADE.md`**
   (create one, following `jurisdiction-flag/UPGRADE.md`'s structure, if the
   contract doesn't have one yet), including the manual steps an issuer must
   run and in what order relative to `upgrade()` itself.
3. **No automatic, unattended migration.** Because a botched migration can
   corrupt live compliance state (e.g. silently un-denylisting an address),
   migrations run as an explicit, admin-authorized call the issuer
   triggers deliberately — never as code that runs implicitly inside
   `upgrade()` itself.

Issuers should read the target version's `UPGRADE.md` before calling
`upgrade()` and rehearse the full upgrade-plus-migration sequence on testnet
first, per the existing [testing guidance in
`UPGRADE.md`](./contracts/jurisdiction-flag/UPGRADE.md#testing-the-upgrade-path).

## For contributors

If your change touches a `DataKey` enum or any other `#[contracttype]` used
for storage in a contract that has (or is expected to gain) an `upgrade()`
entrypoint:

1. Classify the change using [Change categories](#change-categories) above.
2. If it's breaking, add or update that contract's `UPGRADE.md` with the
   migration steps, and call this out explicitly in your PR description.
3. Per [`CONTRIBUTING.md`](./CONTRIBUTING.md#complexity-labels-and-expected-pr-size),
   a breaking storage-layout change is `complexity: high` regardless of how
   small the code diff looks — it changes a compatibility commitment to
   every live deployment of that contract.

## Instance and Persistent Storage TTL Policy

Soroban does **not** automatically extend a contract's instance-storage TTL or
persistent-storage TTL when the contract is invoked. If a contract's instance
storage expires and is archived, `DataKey::Admin`, `DataKey::Issuer`, and
`DataKey::Paused` become unreadable until restored, which could either brick
administrative operations or cause fail-open reads if not guarded.

To prevent unintended archival, all stateful compliance primitives enforce a
uniform TTL extension policy on every state-mutating entrypoint:

| Constant | Value (ledgers) | Wall-clock (~5s/ledger) | Purpose |
| --- | --- | --- | --- |
| `INSTANCE_TTL_THRESHOLD` | `120_960` | ~7 days | Minimum remaining TTL below which `env.storage().instance().extend_ttl(...)` bumps the instance TTL |
| `INSTANCE_TTL_EXTEND_TO` | `1_555_200` | ~90 days | Target remaining TTL after an instance storage extension |

### Per-Contract Coverage

- **`allowlist-token`**: Calls `extend_instance_ttl` on `initialize`, `accept_admin`, `transfer`, and all admin/compliance-officer write paths (`set_delegated_admin_key`, `add_to_allowlist`, `add_multiple_to_allowlist`, `add_to_allowlist_delegated`, `remove_from_allowlist`, `remove_multiple_from_allowlist`, `pause`, `unpause`, `propose_admin`, `transfer_admin`, `set_compliance_officer`, `revoke_compliance_officer`, `propose_upgrade`, `commit_upgrade`, `cancel_upgrade`). Persistent `DataKey::Allowed(Address)` entries are likewise extended on write and on `transfer`.
- **`denylist-gate`**: Calls `extend_instance_ttl` on `initialize`, `accept_admin`, and all admin, compliance-officer, and multisig signer write paths (`add_to_denylist`, `remove_from_denylist`, `remove_multiple_from_denylist`, `pause`, `unpause`, `propose_admin`, `cancel_admin_proposal`, `transfer_admin`, `set_compliance_officer`, `revoke_compliance_officer`, `set_audit_log`, `clear_audit_log`, `initialize_multisig`, `add_signer`, `remove_signer`, `set_threshold`, `propose_upgrade`, `commit_upgrade`, `cancel_upgrade`). Persistent `DataKey::Denied(Address)` entries receive a long ~1-year TTL (`6_311_520` ledgers) on write so sanctioned addresses do not silently expire between administrative touches.
- **`jurisdiction-flag`**: Calls `extend_instance_ttl` on `initialize`, `accept_issuer`, and all issuer/compliance-officer write paths (`set_jurisdiction`, `set_multiple_jurisdictions`, `set_jurisdiction_until`, `add_jurisdiction`, `remove_jurisdiction`, `remove_jurisdiction_multiple`, `pause`, `unpause`, `propose_issuer`, `cancel_issuer_proposal`, `transfer_issuer`, `set_compliance_officer`, `revoke_compliance_officer`, `upgrade`), and extends persistent `DataKey::Jurisdictions(Address)` / `DataKey::ValidUntil(Address)` entries on both writes and active reads.
- **`circuit-breaker`, `compliance-aggregator`, `policy-engine`, & `multisig-admin`**: Call `extend_instance_ttl` (`120_960` / `1_555_200` ledgers) on `initialize` and every administrative configuration change.

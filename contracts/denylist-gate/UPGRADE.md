# Denylist-Gate Contract Upgrade Mechanism

## Overview

WASM upgrades are admin-controlled and timelocked. Every proposal submitted via
`propose_upgrade(admin, new_wasm_hash, delay_ledgers)` must wait at least
`MIN_UPGRADE_DELAY_LEDGERS` (`17,280` ledgers, approximately one day at five
seconds per ledger) before `commit_upgrade(admin)` can install the new Wasm, and
can be discarded beforehand via `cancel_upgrade(admin)`.

## Storage Compatibility

Soroban preserves instance and persistent storage when replacing Wasm. Admin,
pause, compliance-officer, audit-log, signer-set, and persistent `Denied(addr)`
entries survive across `commit_upgrade` as long as their keys and value types
remain compatible. See [`STORAGE_VERSIONING.md`](../../STORAGE_VERSIONING.md)
for the workspace-wide compatibility policy.

### Pre-1.0 (`0.1.0`) Storage Notes

- **`DataKey::PendingSignerAction(SignerAction)` (`#577`)**: Pending multisig
  signer-set approvals moved from `instance()` storage (`Vec<Address>`) to
  `persistent()` storage (`Vec<PendingApproval>` stamped with
  `created_at_ledger` and bounded by `APPROVAL_TTL_LEDGERS = 120_960`).
  - Because `instance()` and `persistent()` are separate Soroban storage tiers,
    reading persistent `PendingSignerAction` entries after an upgrade never
    deserializes legacy `Vec<Address>` values.
  - Any in-flight partial multisig votes collected prior to `commit_upgrade` do
    not carry over and must be re-submitted by signers after the upgrade.
  - `approve` and `revoke_approval` automatically remove any legacy
    `instance()` entry for the touched `SignerAction` key so pre-upgrade
    instance entries are cleaned up without deserializing the old value type.

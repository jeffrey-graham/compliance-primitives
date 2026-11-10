# denylist-gate

A standalone denylist that other contracts can call before allowing a transfer.

| Method | Purpose |
| --- | --- |
| `initialize(admin)` | Configure the administrator. |
| `get_admin() -> Address` | Read the configured administrator. |
| `add_to_denylist(admin, address)` | Deny an address. |
| `remove_from_denylist(admin, address)` | Clear an address. |
| `check(address) -> bool` | Return whether the address is clear to transact. |
| `revoke_approval(caller, action)` | Withdraw `caller`'s pending multisig approval for `action`. |
| `pending_approvals(action) -> Vec<Address>` | Return active, non-expired signer approvals for `action`. |

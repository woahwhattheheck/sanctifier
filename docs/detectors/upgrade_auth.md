# `upgrade_auth` — Upgrade authorization guard

| | |
| --- | --- |
| **Finding code** | [`S010`](../error-codes.md) |
| **Category** | upgrades |
| **Severity** | Error |
| **Source rule** | [`rules/upgrade_auth.rs`](../../tooling/sanctifier-core/src/rules/upgrade_auth.rs) |

## What it catches

Public functions that call `update_current_contract_wasm` without both an
administrator-shaped authorization check and nonce-shaped replay protection.

## Vulnerable example

```rust
pub fn upgrade(env: Env, wasm_hash: BytesN<32>) {
    env.deployer().update_current_contract_wasm(wasm_hash);
}
```

## The fix

Authenticate the administrator and validate and consume a nonce before the
upgrade call:

```rust
pub fn upgrade(env: Env, admin: Address, nonce: u64, wasm_hash: BytesN<32>) {
    admin.require_auth_for_args((nonce, wasm_hash.clone()));
    let current: u64 = env.storage().instance().get(&"upgrade_nonce").unwrap_or(0);
    assert_eq!(current, nonce);
    env.storage().instance().set(&"upgrade_nonce", &(current + 1));
    env.deployer().update_current_contract_wasm(wasm_hash);
}
```

## How Sanctifier detects it

The rule examines public free functions and public impl methods that reach the
upgrade primitive. It looks for `require_auth` or `require_auth_for_args`
alongside an admin/owner/authority/govern marker, plus a nonce-shaped identifier
or literal. Private helpers and functions without an upgrade call are ignored.

This is a structural, intraprocedural check. Guards hidden behind opaque helper
functions may not be recognized, and the rule does not prove nonce semantics.

## References

- [Finding Codes](../error-codes.md)
- Related: [`auth_gap`](auth_gap.md)
- Related: [`auth_replay`](auth_replay.md)

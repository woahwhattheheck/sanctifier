# `deprecated_sdk` — Deprecated Soroban SDK API usage

| | |
| --- | --- |
| **Finding code** | [`S014`](../error-codes.md) |
| **Category** | code_hygiene |
| **Severity** | Medium |
| **Source rule** | [`rules/deprecated_sdk.rs`](../../tooling/sanctifier-core/src/rules/deprecated_sdk.rs) |

## What it catches

Calls to public `soroban_sdk` APIs that the SDK itself marks deprecated. The
rule keeps the migration list in one table and reports the supported replacement
or migration guidance with each finding.

To keep the signal high without Rust type resolution, generic method names such
as `publish`, `deploy`, and `log` are only matched when their receiver is a
syntax-distinctive Soroban chain rooted at `env` or `self.env`.

## Maintained deprecation list

| Deprecated form | Migration |
| --- | --- |
| `Env::logger()` | `Env::logs()` |
| `Logs::log(..)` | `Logs::add(..)` or `log!` |
| `Events::publish(..)` | `#[contractevent]` plus `Events::publish_event(..)` |
| `Ledger::protocol_version()` | Remove protocol-version branching; the SDK no longer guarantees this value |
| `Deployer::update_current_contract_wasm(..)` | `Deployer::update_current_contract(..)` |
| `DeployerWithAddress::deploy(..)` | `DeployerWithAddress::deploy_contract(..)` |
| `Env::register_contract(..)` | `Env::register(..)` |
| `Prng::u64_in_range(..)` | `Prng::gen_range(..)` |
| `Symbol::short(..)` | `symbol_short!` |
| `String::from_slice(..)` | `String::from_str(..)` |
| `panic_error!(..)` | `panic_with_error!(..)` |
| `assert_in_contract!(..)` | `debug_assert_in_contract!(..)` for debug-only assertions |

The table is maintained from public `#[deprecated]` annotations in the upstream
`soroban-sdk`; updating the SDK deprecation surface should update this table and
the representative golden fixture together.

## Example

Deprecated:

```rust
pub fn legacy(env: Env) {
    env.events().publish((symbol_short!("old"),), 1_u32);
    env.prng().u64_in_range(1..=10);
}
```

Supported shape:

```rust
pub fn current(env: Env) {
    env.events().publish_event(&MyEvent { value: 1 });
    env.prng().gen_range(1..=10);
}
```

## Detection limits

This is source-level syntax analysis, not type inference. Calls routed through
renamed variables or aliases can be missed, and a user-defined `Env`, `Symbol`,
or `String` with the same surface can look like the SDK. The receiver checks
avoid flagging arbitrary user methods whose names happen to be `publish`,
`deploy`, or `log`.

## References

- [soroban-sdk Rust API](https://docs.rs/soroban-sdk/latest/soroban_sdk/)
- [Stellar rs-soroban-sdk](https://github.com/stellar/rs-soroban-sdk)

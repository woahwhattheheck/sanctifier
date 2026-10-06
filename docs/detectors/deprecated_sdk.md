# `deprecated_sdk` — Deprecated Soroban SDK API usage

| | |
| --- | --- |
| **Finding code** | [`S014`](../error-codes.md) |
| **Category** | code_hygiene |
| **Severity** | Medium |
| **Source rule** | [`rules/deprecated_sdk.rs`](../../tooling/sanctifier-core/src/rules/deprecated_sdk.rs) |

## What it catches

Calls to public `soroban_sdk` APIs that the repository's supported SDK baseline
marks deprecated. The rule keeps the migration list in one table and reports
the supported replacement with each finding.

## Maintained deprecation list

Sanctifier currently pins `soroban-sdk = 20.5.0`, so this detector is maintained
against the public `#[deprecated]` annotations in the upstream `v20.5.0` tag.
When the workspace SDK advances, this table and the representative golden fixture
should be refreshed against the new supported tag.

| Deprecated form | Migration |
| --- | --- |
| `Env::logger()` | `Env::logs()` |
| `Logs::log(..)` | `Logs::add(..)` or `log!` |
| `Prng::u64_in_range(..)` | `Prng::gen_range(..)` |
| `Symbol::short(..)` | `symbol_short!` |
| `String::from_slice(..)` | `String::from_str(..)` |
| `panic_error!(..)` | `panic_with_error!(..)` |

## Example

Deprecated:

```rust
pub fn legacy(env: Env) {
    env.logger();
    env.logs().log("legacy", &[]);
    env.prng().u64_in_range(1..=10);
}
```

Supported shape:

```rust
pub fn current(env: Env) {
    env.logs();
    env.logs().add("current", &[]);
    env.prng().gen_range(1..=10);
}
```

## Detection limits

This is source-level syntax analysis, not type inference. Env methods are matched
only on `env` or `self.env`, accessor methods are matched on direct chains such
as `env.logs().log(..)`, and associated calls are matched by the `Symbol` /
`String` path suffix. Renamed handles or imported aliases can therefore be
missed, while a user-defined type with the same explicit surface can look like
the SDK.

## References

- [soroban-sdk 20.5.0 source](https://github.com/stellar/rs-soroban-sdk/tree/v20.5.0/soroban-sdk)
- [soroban-sdk Rust API](https://docs.rs/soroban-sdk/20.5.0/soroban_sdk/)

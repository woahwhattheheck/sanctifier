# `unbounded_storage_loop` — Uncapped iteration over stored collections

| | |
| --- | --- |
| **Finding code** | [`SANCT_UNBOUNDED_LOOP`](../error-codes.md) |
| **Category** | denial_of_service |
| **Severity** | High (`Severity::Error`) |
| **Source rule** | [`rules/unbounded_storage_loop.rs`](../../tooling/sanctifier-core/src/rules/unbounded_storage_loop.rs) |

## What it catches

Public `#[contractimpl]` entrypoints that iterate an entire storage-sourced
`Vec` or `Map` without a visible hard bound or pagination. Storage data can
grow over time, so a call that worked initially may eventually exhaust a
Soroban execution budget and become unusable. This is separate from
[`unbounded_storage`](unbounded_storage.md), which flags unbounded *growth*
of an individual storage collection, and [`arg_dos`](arg_dos.md), which
examines iteration over caller-supplied *arguments*.

## Vulnerable example

```rust
#[contractimpl]
impl Payroll {
    pub fn pay_all(env: Env) {
        let holders: Vec<Address> = env.storage().persistent()
            .get(&DataKey::Holders).unwrap();

        // The per-invocation cost increases with every stored holder.
        for holder in holders.iter() {
            pay(&env, &holder);
        }
    }
}
```

## The fix

Use a fixed maximum size guard that *exits* before the loop, or paginate
processing into separately metered entrypoint calls. A visible bounded
iterator is another option when processing a prefix is semantically safe:

```rust
const MAX_PAGE_SIZE: u32 = 100;

#[contractimpl]
impl Payroll {
    pub fn pay_page(env: Env) {
        let holders: Vec<Address> = env.storage().persistent()
            .get(&DataKey::Holders).unwrap();

        // A fixed cap on one invocation; add a continuation cursor for
        // complete processing across transactions.
        for holder in holders.iter().take(MAX_PAGE_SIZE) {
            pay(&env, &holder);
        }
    }
}
```

## How Sanctifier detects it

The detector parses `#[contractimpl]` public functions, tracks local
collections read from persistent, instance, or temporary storage, and follows
simple aliases into `for` iteration and `while` length conditions. It
recognizes local fixed-bound `.take(..)` or `.min(..)` usage, as well as
size guards that exit the function and assertion-style fixed bounds. It
excludes `#[cfg(test)]` modules.

**Limitations:** this is conservative syntactic analysis, not an interprocedural
proof. A bound enforced in another function may need an explicit local guard
to avoid a false positive. Conversely, mutable aliases, helpers, or control
flow outside the supported patterns can escape detection. Review every
finding against the actual storage lifecycle and on-chain budget.

## References

- [Stellar — Soroban persistent storage](https://developers.stellar.org/docs/build/smart-contracts/state-management)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- Related: [`unbounded_storage`](unbounded_storage.md),
  [`arg_dos`](arg_dos.md),
  [`cross_contract_call_in_loop`](cross_contract_call_in_loop.md)

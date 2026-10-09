# Narrowing and sign-changing integer casts

**Finding code:** `SANCT_NARROWING_CAST`
**Severity:** Warning

## Risk

Using the Rust `as` operator to convert a signed amount to an unsigned amount,
or a wider integer to a narrower one, can silently wrap or truncate.
For example, a negative `i128` amount becomes a large `u64`, and a `u128`
balance may lose its high bits when converted to `u32`.

## Unsafe example

```rust
pub fn payout(amount: i128) -> u64 {
    amount as u64
}
```

## Preferred fix

```rust
pub fn payout(amount: i128) -> Result<u64, ContractError> {
    amount.try_into().map_err(|_| ContractError::InvalidAmount)
}
```

Handle conversion errors before using amounts for transfers, balances, or
storage updates. Do not replace a checked conversion with `unwrap()`.

## Detection boundaries

The rule checks literal integer casts on parameters, typed locals, inferred
cast-initialized locals and nested casts. The source type must be statically
known; unsupported expressions and target-dependent `usize`/`isize` widths
are not guessed. Compile-time integer literals proven to fit the target type
are ignored. This is a conservative syntactic check, not a full data-flow proof.

## Validation

The focused rule tests cover signed-to-unsigned truncation, unsigned narrowing,
safe widening and fitting integer literals. The reviewed insta golden snapshot
is inline in tooling/sanctifier-core/src/rules/narrowing_cast.rs.

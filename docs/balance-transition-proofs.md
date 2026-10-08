# Z3 token balance-transition proofs (issue #343)

The existing `sanctifier prove --invariant balance_non_negative` check describes an
**unchecked** subtraction. Issue #343 also requires a proof of the *guarded*
token state machine, plus a deliberate unsafe counterexample. The two paths
remain separate so existing invocations do not silently change meaning.

## Run the transition proofs

```sh
# Three separate UNSAT proofs: transfer, mint, and burn under valid guards
sanctifier prove --invariant balance_non_negative --transition all --no-save

# One machine-readable proof or proof certificate
sanctifier prove --invariant balance_non_negative --transition transfer --json

# Intentionally unsafe transition: SAT + concrete model; exit code 1
sanctifier prove --invariant balance_non_negative --transition transfer --unsafe-transfer --no-save
```

Select a single operation with `--transition transfer`, `mint`, or `burn`.
`--transition all` checks all three. An unchecked transition demo is supported
only for transfer; the CLI rejects other uses of `--unsafe-transfer`. Without
`--transition`, the original invariant behavior is preserved. Proof certificates
are saved under `.sanctifier/proofs/balance_non_negative_<operation>_<guard>.json`
unless `--no-save` is given.

## Model and limits

Z3 treats sender balance, receiver balance, amount and total supply as symbolic
integers constrained to the unsigned 64-bit **pre-state** range. Sender and
receiver represent distinct accounts; untouched accounts preserve their
non-negative pre-states.

* **Transfer:** sender decreases by amount; receiver increases. A valid
  transfer requires `amount <= sender_balance` and a receiver post-state
  within u64 bounds. Supply is unchanged.
* **Mint:** recipient and total supply increase by the same amount, with both
  post-states in u64 bounds.
* **Burn:** sender and total supply decrease by amount; valid operations
  require `amount <= sender_balance` and `amount <= total_supply`.

For each operation, Z3 asserts that **any** resulting modeled balance or
supply is negative. `UNSAT` therefore proves the transition preserves
non-negativity over **all** inputs satisfying those preconditions. `SAT`
returns a concrete model with pre-state values, call sequence and post-state.
Disabling the transfer spend guard yields an actual underflow witness.

This is a formal proof of the abstract transition equations and stated guards,
**not** proof that every Soroban contract implements those guards or that
physical u64 overflow wraps safely. Production contract equivalence requires
separate source-to-model verification. A Z3 `unknown` result (for example a
timeout) is reported as unknown, not falsely reported as proved. The shared
`configured_z3_config(DEFAULT_Z3_TIMEOUT_MS)` budget applies.

One focused test exercises all three UNSAT guarded transitions and the unsafe
SAT sender-underflow counterexample. No broad repository test suite is required.

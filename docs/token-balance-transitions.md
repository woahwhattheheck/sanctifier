# Token balance transition proofs (issue #343)

The SMT engine now checks **symbolic state transitions** for a token with two observed accounts, an arbitrary nonnegative number of other holders, and total supply. It proves nonnegativity of the *modeled* post-state (sender, recipient, supply), or provides a Z3 witness for a negative post-state.

## Run a checked transition

From the workspace with the Sanctifier CLI:

```sh
sanctifier prove --invariant balance_non_negative --balance-transition checked_transfer --no-save
sanctifier prove --invariant balance_non_negative --balance-transition checked_mint --no-save
sanctifier prove --invariant balance_non_negative --balance-transition checked_burn --no-save
```

These are intended to be UNSAT for the negated invariant and report **PROVED**. They enforce the debit-before-transfer/burn guard, cap positive credit at u64::MAX, and preserve an initially nonnegative total supply.

## Deliberately unsafe variants

```sh
sanctifier prove --invariant balance_non_negative --balance-transition unchecked_transfer --json --no-save
sanctifier prove --invariant balance_non_negative --balance-transition unchecked_burn --json --no-save
```

They intentionally omit the debit guard. The negation should be **SAT**; the CLI reports **VIOLATED**, prints a concrete assignment and returns exit code 1. The JSON report contains the pre/post balances, supply, amount and the violated assertion. With certificate saving enabled, each mode uses a different `balance_non_negative_<mode>.json` filename. Timeouts report **UNKNOWN**, not PROVED.

## Modeling boundary

- Initial sender and recipient balances, total supply and amount are symbolic nonnegative Z3 integers limited to the u64 domain. Total supply is at least the sum of the two observed balances.
- Transfer subtracts from sender and credits recipient without changing supply; mint credits recipient and total supply; burn debits sender and total supply.
- Nonnegative post-state is checked via the **negated** assertion, not assumed. Checked operations add required arithmetic guards; unsafe operations omit the debit guard so Z3 can exhibit the flaw.
- This verifies the transition equations shown in source. **It does not parse or prove a user-supplied contract, establish Soroban host authorization, prove absence of wraparound in arbitrary runtime code, or establish that an arbitrary token implementation enforces these guards.** Bind actual contract entrypoint semantics to these equations before making source-level claims.
- The previous plain `--invariant balance_non_negative` mode remains the original unchecked-transfer demonstration for backward compatibility. The new `--balance-transition` flag opts into explicit checked/unchecked operation models.

## Focused validation

A single targeted Rust test in `smt.rs` checks UNSAT for all three guarded cases and SAT with model for both deliberately unchecked cases:

```sh
cargo test -p sanctifier-core --features smt balance_transition_proofs::guarded_transitions_prove_and_missing_debit_guard_has_witness
```

Use the project’s existing system Z3 setup. This command is a reproducible focused check, **not a claim that the test was run or passed**.

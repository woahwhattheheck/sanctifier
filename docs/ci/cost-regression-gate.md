# Cost regression baseline gate

Issue #695: catch silent instruction/memory-estimate creep in pull requests.

The `sanctifier-cost-gate` binary consumes the existing `sanctifier_core::gas_estimator::GasEstimator` against actual Rust contract sources. It compares **per source file, public function and metric**, not one aggregate cost that can hide a regression in a single function. This estimator uses *heuristic static instruction and memory weights*, **not execution gas, network fees, budget limits or a deterministic Soroban VM measurement**. The gate is for relative changes within the same estimator version.

## Baseline and CI

An initial reviewed baseline is committed at `contracts/vulnerable-contract/cost-baseline.json`. The existing `.github/workflows/ci.yml` calls the gate against `contracts/vulnerable-contract/src/lib.rs` on pull requests and pushes to main. A cost regression beyond 10% in either metric exits nonzero, causing the CI job to fail. Protect the CI job as a required branch check if your GitHub repository does not already require it; a failing non-required check cannot independently block every possible merge.

From the repository root, run the **focused** gate (no test suite):

```bash
cargo run --manifest-path tooling/sanctifier-cli/Cargo.toml --bin sanctifier-cost-gate -- check \
  --root . \
  --source contracts/vulnerable-contract/src/lib.rs \
  --baseline contracts/vulnerable-contract/cost-baseline.json \
  --max-regression-percent 10
```

To deliberately approve a revised reference cost (after inspecting the source and reason), regenerate and review the diff:

```bash
cargo run --manifest-path tooling/sanctifier-cli/Cargo.toml --bin sanctifier-cost-gate -- record \
  --root . \
  --source contracts/vulnerable-contract/src/lib.rs \
  --baseline contracts/vulnerable-contract/cost-baseline.json
git diff -- contracts/vulnerable-contract/cost-baseline.json
```

For your own contract repo, track one or more actual contract sources with repeated `--source` arguments and commit the resulting JSON. Keep the same list in CI's `check` call. Run the check on every relevant pull request, **never** silently record or overwrite a baseline in CI; approval of cost drift belongs in review.

## Failure behavior

- A missing or malformed baseline, unsupported schema, missing source, unreadable file, source outside `--root`, or zero analyzed public functions **fails the job** rather than turning into a zero-cost pass.
- File+function keys are sorted for reproducible JSON; duplicate function names within one source file are rejected because the current estimator exposes names without an impl-type identifier.
- Added, removed or renamed public functions produce coverage failures until the new surface has been explicitly reviewed and rebaselined.
- Both instruction and memory estimates are compared using overflow-safe integer arithmetic. The cap is an integer 0–100%; exactly-at-threshold passes, above-threshold fails.
- An unchanged sample fixture passing CI **does not certify unrelated contracts**. Add their own tracked source/baseline paths to the gate before relying on it for their changes.

This command deliberately does not rerun the full project test suite or Kani proofs; those have separate existing CI jobs.

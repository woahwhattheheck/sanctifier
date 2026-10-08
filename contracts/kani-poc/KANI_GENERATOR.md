# Kani harness generator for issue 344

The generator scans real public entrypoints in #[contractimpl] blocks and writes editable Kani proof skeletons. It does not certify any program property.

## Command

Run at the repository root with a Rust toolchain:

    cargo run --no-default-features -p sanctifier-core --bin kani-harness-gen -- contracts/kani-poc/src/lib.rs kani_poc_contract contracts/kani-poc/tests/kani_generated_new.rs

Arguments: source Rust file, crate name, output path. Output is create-only so reruns cannot overwrite refined proofs. A representative generated example is in contracts/kani-poc/tests/kani_generated.rs.

## Supported parameters

The syn AST parser supports integer and bool symbolic values, Env, Address, Bytes, BytesN<N>, Symbol, String, and Vec<T> constructors. Unsupported signatures cause an explicit error rather than a partial result. Methods must be public members of top-level contractimpl blocks.

## Refinement checklist

1. Set meaningful preconditions with kani::assume in each generated function.
2. Add assertions about meaningful postconditions and state transitions.
3. For methods invoking Soroban Host, create and justify a pure Rust host/authorization/storage model; generation does not prove the Soroban host API. Address::generate depends on the SDK testutils feature, present as a dev-dependency in this example crate.
4. Check the generator with cargo test --no-default-features -p sanctifier-core kani_harness; check specific proofs with cargo kani and the appropriate test target when supported.

A generated #[kani::proof] with only TODO comments is not a verified property. The generated token example demonstrates three entrypoints, including an unguarded set_admin call whose safety is not implied by generation.

## Validation status

Two focused generator unit tests cover multiple entrypoint signatures and rejection of unsupported argument types. This execution environment lacks Rust, Cargo and Kani; those tests were authored but not run here. No passing build or proof result is claimed.

# Admin storage authorization proof (GrantFox #341)

## Threat and runtime boundary

The earlier demonstration contract exposed `set_admin(env, new_admin: Symbol)` as an unrestricted instance-storage write. Any caller could replace the administrator without authorizing that operation; initialization also never established an authenticated admin address.

The protected Soroban wrapper now uses **addresses, not symbolic labels**:

1. `initialize(env, initial_admin: Address)` requires a signature from `initial_admin`, then records the admin and the one-time initialized flag. An already initialized contract refuses another bootstrap attempt.
2. `set_admin(env, caller: Address, new_admin: Address)` reads the recorded administrator. It refuses any nonmatching `caller`, calls `caller.require_auth()`, and **only then** persists the replacement.
3. Admin-state mutation never happens in the pre-authorization branches. The stored administrator must be present; there is no unauthenticated first-update fallback.

This changes the proof-of-concept contract's public initialization and admin-update parameter types from `Symbol` to `Address`, and adds the authenticated `caller` argument to `set_admin`. It deliberately does not promise a binary-compatible migration for deployed instances that stored a `Symbol` admin; callers and migrations need to be updated deliberately before adoption.

**Bootstrap trust:** The deployer must control the first initialization call; `initial_admin.require_auth()` proves that the chosen admin consents, not that a specific predetermined deployer picked it. First-installer policy, contract upgrade governance, cross-contract auth delegation and the Soroban Host runtime are outside this isolated Kani proof. The real host wrapper separately enforces `Address::require_auth`.

## Pure Kani model and its limits

`admin_update_pure(stored_admin, claimed_caller, signature_verified, new_admin)` is a finite symbolic model of the two checks. The four variables are symbolic `u8`s / booleans so the proof explores every caller, stored administrator, replacement value and signature state within this abstract domain. A successful transition requires **both** identity equality and verified authorization. Identity alone is not an authenticated signature.

The harnesses in `src/lib.rs`:

| Harness | Expected evidence |
| --- | --- |
| `verify_only_authenticated_admin_can_write_admin_state` | Every unauthorized caller/signature state rejects and cannot return a changed admin; authorized callers can update |
| `verify_missing_require_auth_yields_counterexample` | Expected failing assertion (`#[kani::should_panic]`) demonstrates a forged claimed admin when the signature check is removed |
| `verify_missing_admin_identity_yields_counterexample` | Expected failing assertion demonstrates why merely accepting a signature without matching it to the stored admin is insufficient |

The negative controls are `#[cfg(kani)]` and cannot become production entrypoints. The tests do **not** prove the Soroban `Env` or host storage semantics; they prove only the pure transition that the wrapper is designed to enforce.

## Focused proof commands

From the repository root with a functional Rust, Soroban SDK and Kani setup:

```sh
cargo kani --manifest-path contracts/kani-poc/Cargo.toml --harness verify_only_authenticated_admin_can_write_admin_state
cargo kani --manifest-path contracts/kani-poc/Cargo.toml --harness verify_missing_require_auth_yields_counterexample
cargo kani --manifest-path contracts/kani-poc/Cargo.toml --harness verify_missing_admin_identity_yields_counterexample
```

For a quick ordinary model check, restrict the optional unit run to:

```sh
cargo test --manifest-path contracts/kani-poc/Cargo.toml admin_pure_
```

The commands are instructions, **not execution receipts**. They were not run during this source-publication handoff; no Kani PASS, hosted workflow success, or repository-wide test result is claimed. Maintainer acceptance should include a real Kani run and an actual Soroban Host unauthorized-call integration check.

**Coordination:** Sanctifier #339 has a separate original-author initialization transition PR that touches this same example file. When integrating #339 and #341, retain #339's `initialize_transition`/two-call proof while keeping the initial-admin signature and storage initialization above. Never replace #339's proof or claim that abstract unit-model checking alone proves a deployed contract.

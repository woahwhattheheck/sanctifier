# Kani administrator-write proof model (#341)

This crate uses a small pure Rust authorization/storage transition model to
exercise the permission invariant separately from the Soroban Host API.
HostAuthorization represents a Host-validated signing principal (or no
signature) independently from requested arguments. The stored predecessor
administrator is the only principal permitted to change protected state.

## Three focused proof harnesses

* only_stored_admin_may_write_admin_storage: all symbolic predecessor admins,
  policies, present/absent signatures, signers, and requested values. A
  rejected invocation must leave BOTH protected storage fields unchanged.
* valid_admin_signature_can_change_storage: non-vacuity of the model. Genuine
  admin signatures can perform administrator rotation.
* missing_require_auth_exposes_unauthorized_write: deliberately bypasses the
  host check; the expected Kani should_panic result must exhibit a
  counterexample (otherwise the proof is not credible).

From the workspace root, with Rust and Kani installed and set up:

    cargo kani -p kani-poc-contract --harness only_stored_admin_may_write_admin_storage
    cargo kani -p kani-poc-contract --harness valid_admin_signature_can_change_storage
    cargo kani -p kani-poc-contract --harness missing_require_auth_exposes_unauthorized_write

The negative harness SHOULD find an expected counterexample. Two ordinary
Rust tests also document rejection, rotation/revocation and the buggy variant.

## Critical trust boundary

The pure Rust model is not proof of the actual Soroban host, cryptographic
authorization, instance storage or the deployed TokenContract implementation.
The pre-existing demo TokenContract::set_admin in src/lib.rs still writes an
unprotected Symbol; it is NOT secured by these abstract proofs and must not
be deployed as an access-controlled administrator setter.

A real contract needs a persisted administrator Address, an explicit secure
initialization policy, a call to stored_admin.require_auth() BEFORE writing,
and separate Soroban-host integration verification. This model proves the
bounded authorization policy only, including the missing-check regression.

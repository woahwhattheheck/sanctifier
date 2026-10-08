# Centralization — admin powers

The centralization detector is an **inventory of privileged control**, not a
proof that a protected operation can be exploited. Auditors should be able to
answer: "What could a contract administrator do unilaterally?"

## Use

Run the existing CLI against a Soroban contract or workspace:

```sh
sanctifier analyze path/to/soroban-project
sanctifier analyze path/to/soroban-project --format json
```

The text scan prints a dedicated **Centralization — admin powers** section,
listing the entrypoint, controlling signer/role, action(s), location, severity
and suggested risk-reduction controls.

JSON output keeps the existing scan schema and adds:

- `centralization.total_powers` and `centralization.powers` for structured reporting.
- `centralization.markdown` for the deterministic Markdown section.
- `findings.centralization` for CI consumers alongside the existing finding codes.
- `summary.centralization_powers` for dashboard/count consumers.

Findings use code `SANCT_CENTRALIZATION`, registered in
`finding_codes.rs`. Baseline and inline ignore processing use this code.

## Detection semantics

The analyzer looks for public Rust functions/methods with an explicit
administrator/governance/guardian/authority/multisig signer or role assertion
(including `require_auth` and privileged `require_role(Role::Admin)`).
It then classifies capabilities by function and call names:

| Power | Example | Risk |
| --- | --- | --- |
| Contract upgrade | `update_current_contract_wasm` | High |
| Token mint | `mint` | High |
| Treasury drain | `sweep`, `emergency_withdraw` | High |
| Pause/freeze | `pause` | Moderate |
| Fee control | `set_fee` | Moderate |
| Role/ownership changes | `grant_role`, `set_admin` | Moderate |
| Configuration changes | `set_oracle`, `set_config` | Moderate |
| Other explicitly privileged entrypoints | `read_audit` | Informational |

An ordinary `from.require_auth()` on a user transfer/allowance does not
by itself imply contract centralization; unguarded admin-like mutations belong
to the existing auth-gap findings. A signed owner action with a privileged
operation remains visible.

This is conservative static analysis: indirect/cross-file role checks,
nonstandard role names, aliases and dynamically computed authority can evade
detection; a name collision can cause a false positive. Findings are not an
exploitability verdict. Run actual permission and ownership review before
claiming a function is safe or dangerous.

## Focused example and reproducibility

The module's focused regressions cover Vault upgrades, Token mint and pause,
role-based fee setting, emergency withdrawal, a privileged getter, and safe
negative cases for user transfer/approve and ungated mint. A committed report
snapshot lives at
`tooling/sanctifier-core/tests/fixtures/centralization-report.md`,
with an exact string assertion in the centralization detector's test module.

No full workspace test suite or live-chain exploit is needed to generate the
report. The scanner counts high-impact powers in its high-risk result, leaving
legacy finding categories unchanged.

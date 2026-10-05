# CLI exit codes and analysis summary

Sanctifier exposes a small, documented process-code contract for shell scripts and CI.

| Exit code | Meaning |
| --- | --- |
| `0` | The command completed successfully. Text-mode `analyze` keeps its existing report-only behavior, so findings do not by themselves change this code. |
| `1` | An operational error occurred or a command's explicit gate failed. Existing examples include high/critical findings from `analyze --format json`, `diff --fail-on-new` detecting regressions, `verify --strict` failing an invariant, and WASM error findings. |
| `2` | The command line is invalid. Clap uses this for unknown options and missing or invalid arguments. |

## Text analysis summary

After a completed text-mode `sanctifier analyze` run, stdout ends with one uncolored, machine-readable line:

```text
SANCTIFIER_SUMMARY exit_code=0 total_findings=<n> suppressed_findings=<n> has_critical=<true|false> has_high=<true|false>
```

Every field after `SANCTIFIER_SUMMARY` is a whitespace-delimited `key=value` token whose value contains no spaces. The `exit_code` field is the process code for that completed text-mode scan.

Operational failures that stop analysis before a report is produced do not emit a completion summary.

## JSON analysis summary

JSON mode remains one valid JSON document. Its existing `summary` object now includes:

- `exit_code`
- `total_findings`
- `suppressed_findings`
- `has_critical`
- `has_high`

The JSON `exit_code` matches the process code used by the existing JSON high/critical finding gate.

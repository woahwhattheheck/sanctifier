# GitLab CI: Sanctifier Code Quality and SARIF

This integration addresses [Sanctifier issue #707](https://github.com/Centurylong/sanctifier/issues/707). It scans a checked-out Soroban contract, emits GitLab Code Quality JSON for findings with a real source position, and retains all findings (including ones without a trustworthy source position) in a downloadable SARIF 2.1.0 artifact.

## Add the job to a GitLab project

Place a copy of [gitlab.yml](gitlab.yml) at ci/sanctifier.gitlab-ci.yml in your **Soroban application** repository, then add this copy-paste snippet to its root .gitlab-ci.yml:

    include:
      - local: ci/sanctifier.gitlab-ci.yml

For a new project, the vendored file contributes a security stage. For a project with an existing stages array, include security in that array; GitLab needs all declared job stages. Keep the rest of your pipeline unchanged. The template uses an official Rust container, Python 3, the repository's own scanner, and the bundled stdlib converter; there is no GitLab token requirement.

In the included job, set SANCTIFIER_SCAN_PATH to the directory containing a Soroban Cargo.toml. It defaults to ".", so a single-crate project works as-is. In a workspace, for example:

    sanctifier_security:
      variables:
        SANCTIFIER_SCAN_PATH: "contracts/token"

Set SANCTIFIER_SOURCE_URL and SANCTIFIER_REF only when intentionally testing a specific reviewed Sanctifier source revision. Defaults are https://github.com/Centurylong/sanctifier.git and main. Before this contribution lands upstream, use the original contributor's branch for a reproducible trial:

    sanctifier_security:
      variables:
        SANCTIFIER_SOURCE_URL: "https://github.com/woahwhattheheck/sanctifier.git"
        SANCTIFIER_REF: "feat/grantfox707-gitlab-ci-report-20261007"

Return to the upstream source and a reviewed release tag/commit after merge. A GitLab runner compiles and runs code from this source URL; restrict changes to trusted maintainers. If your existing pipeline uses a different job name, merge the variable settings into the included sanctifier_security job rather than defining a second scan.

## Artifacts and failure behavior

- gl-code-quality-report.json: registered with GitLab's native artifacts:reports:codequality integration; entries have real repo-relative .rs file paths, positive line numbers, stable SHA-256 fingerprints and GitLab severities.
- sanctifier.sarif: SARIF 2.1.0 under artifacts:paths for download/forwarding. GitLab does **not** automatically treat a SARIF file as its SAST report; use its SARIF-specific integrations if needed.
- sanctifier-report.json: the original analyzer JSON, including any unlocated findings.

The scanner emits structured JSON even when critical/high findings cause exit status 1. The job converts and uploads reports using artifacts:when:always, **then returns the scan's original nonzero status**. Invalid JSON or a converter error fails the job. Missing locations are omitted from Code Quality rather than inventing paths or lines, but those findings remain in SARIF. Findings without a source position therefore will not appear as inline Code Quality annotations.

No credentials are needed to generate these reports. GitLab report ingestion and rendering depend on the GitLab version/tier and runner configuration; a downloaded artifact alone is not proof of UI integration.

## Focused example-project smoke

From this source repository, with a compiled or installed Sanctifier CLI available:

    python3 scripts/smoke-sanctifier-gitlab-report.py --cli sanctifier

This scans the existing Soroban example contracts/sep41-token-invariants; it accepts analyzer exit 0 or 1 (findings) but rejects malformed/non-JSON output, then invokes the **same converter** as the GitLab job and checks output shape plus every reported file location. For a fast, dependency-free converter check without a compiled CLI:

    python3 scripts/smoke-sanctifier-gitlab-report.py --fixture

The fixture mode explicitly uses a **synthetic, real-schema example report**, with one located and one unlocated finding; it verifies both report channels and does **not** establish that the Rust CLI or hosted GitLab pipeline ran. The full GitLab job must be tried on a project runner for end-to-end acceptance. Keep execution focused on this example rather than running the repository's general test suites.

## Troubleshooting

- Invalid Soroban project: confirm SANCTIFIER_SCAN_PATH points at the contract's Cargo.toml and that it declares soroban-sdk.
- No annotations but SARIF findings: inspect whether analyzer entries actually contain file:line positions; the converter deliberately refuses fabricated locations.
- Compiler/build error: use the pinned Rust image/toolchain and inspect runner logs; avoid treating the missing report as a clean scan.
- Missing Code Quality UI: inspect gl-code-quality-report.json as a job artifact and confirm GitLab supports the Code Quality report format on the selected instance.

# Bitbucket Cloud Pipelines + Code Insights

**Issue:** [#710](https://github.com/Centurylong/sanctifier/issues/710).
This integration reports the **real** output of Sanctifier's
sanctifier analyze --format json command as one Code Insights report per
commit, with file/line annotations on changed lines in pull requests.

## Copy-paste setup

1. Enable Bitbucket Cloud Pipelines for a repository containing a Soroban Rust
   contract (with a soroban-sdk dependency).
2. Copy [the example pipeline](../../examples/bitbucket/bitbucket-pipelines.yml)
   to that repository's root as bitbucket-pipelines.yml. Copy
   [the publisher](../../scripts/bitbucket_code_insights.py) into that
   repository's scripts/ directory.
3. Set the Bitbucket repository variable SANCTIFIER_PROJECT_PATH to the
   contract directory containing Cargo.toml, e.g. contracts/token. If omitted,
   the pipeline analyzes the repository root.
4. Create a pull request. The pipeline installs Sanctifier, runs its JSON
   analysis, publishes a commit-level Security report and up to 1,000
   annotations, then retains the scanner's failure exit code. The raw JSON
   remains downloadable as a pipeline artifact.

The copy-ready source is in
[examples/bitbucket/bitbucket-pipelines.yml](../../examples/bitbucket/bitbucket-pipelines.yml):

~~~yaml
image: rust:1.85.0-bookworm

pipelines:
  pull-requests:
    "**":
      - step:
          name: Sanctifier security findings
          script:
            - apt-get update && apt-get install -y --no-install-recommends python3 clang libclang-dev libz3-dev libdbus-1-dev pkg-config
            - git clone --depth 1 https://github.com/Centurylong/sanctifier.git /tmp/sanctifier-src
            - cargo install --locked --path /tmp/sanctifier-src/tooling/sanctifier-cli
            - |
              SANCTIFIER_PROJECT_PATH="${SANCTIFIER_PROJECT_PATH:-.}"
              scan_status=0
              sanctifier analyze "$SANCTIFIER_PROJECT_PATH" --format json > sanctifier-report.json || scan_status=$?
              # Publish through the native Code Insights auth proxy, then
              # preserve the scanner status without hiding upload failures.
              python3 scripts/bitbucket_code_insights.py --report sanctifier-report.json --repo-root "$BITBUCKET_CLONE_DIR" --scan-root "$SANCTIFIER_PROJECT_PATH" --scan-exit-code "$scan_status" --publish || exit $?
              exit "$scan_status"
          artifacts:
            - sanctifier-report.json
~~~

The image pins Rust 1.85.0 to match Sanctifier's supported CI toolchain and its
`ethnum` dependency. The installation includes native Z3, D-Bus, pkg-config,
and **Clang/libclang development libraries**, needed by the CLI's older
`z3-sys` bindgen build in this minimal container. It installs the CLI from
its actual nested package directory. Without `libclang-dev`, a fresh
`rust:1.85.0-bookworm` runner can fail before the security scan starts.
Python alone is insufficient in the base Rust container.

## Authentication and API behavior

Inside Bitbucket Cloud Pipelines, the helper uses the native localhost:29418
authentication proxy documented by Atlassian, with the report sent to the
fixed api.bitbucket.org host. **No app password or other copied credential is
required for this normal pipeline workflow.** Outside Pipelines, a scoped
BITBUCKET_CODE_INSIGHTS_TOKEN (a repository access token, not an Atlassian
user API token) can be used with the standard HTTPS Bearer Authorization header (never check the token into Git). The environment supplies
BITBUCKET_WORKSPACE, BITBUCKET_REPO_SLUG and BITBUCKET_COMMIT.

The helper calls the Cloud REST API, **not Bitbucket Data Center**:
- DELETE the prior report for the *same commit and report ID*, if it exists,
  clearing any stale annotations left by reruns.
- PUT the new commit report with result, count metrics and descriptive totals.
- POST sorted, deduplicated annotations in at most 100-item batches, respecting
  Bitbucket's 1,000-annotation report limit.

Report ID is stable: sanctifier-security. Finding IDs hash category, code,
location and description. Only findings with exact source files resolvable
*inside the checked-out repository* and positive line numbers become inline
annotations. Directory-scan unsafe-pattern and custom-rule records use the filename
prefix in their snippet together with their structured line number. Custom-rule
Error/Warning/Info severities map to HIGH/MEDIUM/LOW. Snippets without source
provenance remain locationless. This avoids invented source locations. All findings, including
locationless auth gaps or ledger warnings, remain counted in the report and
raw JSON artifact. The UI only displays inline annotations on lines changed
by the pull request; the full report remains available on the commit.

The publisher requires the `sanctifier-ci-v1` format and complete summary
counts and severity flags. It refuses malformed/failed scanner documents and does not post a
false green pass. Code Insights HTTP 429/502/503/504 responses get at most two
bounded retries (honoring numeric `Retry-After` values); authentication and
other permanent API errors fail immediately, and persistent transient errors
still fail the pipeline. A critical/high scanner summary flag or a nonzero
scan exit code results in FAILED; otherwise the report is PASSED. Annotation
severity does not redefine the scanner's exit policy.

Atlassian references:
- [Code Insights](https://support.atlassian.com/bitbucket-cloud/docs/code-insights/)
- [Reports API](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-reports/)
- [Pipeline variables](https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/)

## Single focused smoke and live acceptance

A preview that does not contact Bitbucket can be produced from the bundled
[example report](../../examples/bitbucket/sample-report.json):

~~~sh
python3 scripts/bitbucket_code_insights.py \
  --repo-root . \
  --scan-root contracts/my-contract \
  --report examples/bitbucket/sample-report.json \
  --scan-exit-code 1
~~~

That example must show a FAILED report with two total findings and one
file/line annotation for contracts/my-contract/src/lib.rs at line 5,
provided that example source file is present. No network or credentials are
used in preview mode.

For the requested **real example-repository smoke**, install the two files
in an accessible Bitbucket Cloud Soroban sample repository, push a PR with a
known finding on a changed source line, and confirm the Security report plus
inline annotation appears on that PR and that its pipeline fails. Remove the
finding and rerun on a new commit: it should show PASSED without the old
annotation. This end-to-end hosted smoke requires a real Bitbucket repository
and working Pipelines permissions; it must **not** be claimed as completed on
source publication alone.


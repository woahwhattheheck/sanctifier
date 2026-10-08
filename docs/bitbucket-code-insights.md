# Bitbucket Cloud Pipelines and Code Insights

Publish **real Sanctifier scan findings** as a Bitbucket Cloud Code Insights
security report with inline annotations on pull requests. No third-party Python
dependencies and, inside Bitbucket Pipelines, no extra credentials.

This integration is for **Bitbucket Cloud**, not Bitbucket Data Center (which
has a different REST API).

## Install in a Soroban repository

1. Copy [publish.py](../integrations/bitbucket-code-insights/publish.py) to
   your consuming repository as `.ci/sanctifier-bitbucket.py` and commit it.
2. Copy [bitbucket-pipelines.yml](../integrations/bitbucket-code-insights/bitbucket-pipelines.yml)
   to the consuming repository root as `bitbucket-pipelines.yml`.
3. Enable Pipelines in Bitbucket and open a pull request. The example builds
   Sanctifier in the CI container, runs JSON analysis, publishes a report with
   annotations wherever source paths and lines are known, and preserves the
   scanner's own exit code.

The example assumes the consuming repository root contains `Cargo.toml`.
For a monorepo, change `sanctifier analyze .` to analyze the contract
directory, but leave the publisher's `--root .` so annotation paths are
relative to the Bitbucket repository.

The pipeline installs Python 3, Z3, D-Bus development libraries, pkg-config,
and Sanctifier's Rust dependencies. It relies on the official Bitbucket
Pipelines Code Insights proxy at `localhost:29418` to authenticate;
**do not** store Bitbucket tokens in the pipeline file or repository.

## What the publisher does

It consumes genuine Sanctifier `analyze --format json` reports with
`metadata.format=sanctifier-ci-v1`:

- Converts entries under `findings` plus top-level
  `vulnerability_db_matches` into stable, de-duplicated annotations.
  Source file/line locations are resolved to repository-relative paths.
- Creates one `sanctifier-security` report on `BITBUCKET_COMMIT`
  with counts and a pass/fail result matching the scanner's high/critical policy.
- Replaces its **own** previous report on rerun so old annotations don't linger;
  other reporters' reports are never touched.
- Uploads up to 100 annotations per API request and up to Bitbucket Cloud's
  1,000-annotation limit. The report counts omitted findings. HTTP 429 and
  selected transient 5xx responses receive bounded retries.

Some detector findings lack a reliable source path/line: they still appear in
the report but cannot be tied to a diff line. Bitbucket only displays inline
annotations on modified lines. Even with no file/line annotations, the
security report and aggregate scan result remain available.

Sanctifier may exit nonzero after emitting JSON when high/critical findings
are detected. The pipeline captures that status, publishes the report, then
fails the step. Invalid/absent scan JSON also fails the publisher.

## Local preflight

With an actual scan result saved as `sanctifier.json`, inspect payloads
without accessing Bitbucket:

```bash
python3 .ci/sanctifier-bitbucket.py --input sanctifier.json --root . --dry-run
```

Outside Pipelines, supply a bearer **repository access token** with Code
Insights write permission (not an Atlassian user API token). Set:

```text
BITBUCKET_WORKSPACE=<workspace>
BITBUCKET_REPO_SLUG=<repository>
BITBUCKET_COMMIT=<source-commit-sha>
BITBUCKET_ACCESS_TOKEN=<repository-access-token>
```

Then call:

```bash
python3 .ci/sanctifier-bitbucket.py --input sanctifier.json --root . --auth-mode token
```

That mode uses HTTPS and `Authorization: Bearer`. User email/API-token
pairs may require Basic authentication and are not accepted by this mode.

## Live example-repo smoke acceptance

The issue explicitly requires a hosted smoke test. With an authorized
Bitbucket Cloud example repository, the reviewer should:

1. Open a pull request changing a line of Soroban Rust source containing an
   established Sanctifier finding.
2. Confirm the `Sanctifier security scan` report appears against that
   source commit with the expected finding count and report status.
3. Confirm the issue's code and file/line match the inline diff annotation.
4. Remove the finding and rerun the pipeline; confirm the earlier annotation
   disappears rather than remaining stale.

These are **future acceptance steps**, not a claim that the hosted Bitbucket
smoke has already run. That last criterion requires an authenticated example
repository and a real Pipelines execution.

## Atlassian references

- [Bitbucket Cloud Code Insights](https://support.atlassian.com/bitbucket-cloud/docs/code-insights/)
- [Reports and annotations REST API](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-reports/)
- [Bitbucket API permissions](https://support.atlassian.com/bitbucket-cloud/docs/api-token-permissions/)

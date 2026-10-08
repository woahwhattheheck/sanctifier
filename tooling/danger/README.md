# Sanctifier + Danger JS: PR findings (GrantFox issue #711)

Use the existing Sanctifier CLI to scan a Soroban project once and have Danger JS
post comments for findings on **added lines of changed Rust files**. This adapter
does not introduce another scanner, GitHub API client, credentials store or bot.

## Setup in a Soroban example repository

1. Install a version of the Sanctifier CLI that supports
   `sanctifier analyze <contract-path> --format json` and put it on PATH.
   The current CLI emits metadata.format = `sanctifier-ci-v1` and
   findings.* arrays. Use `analyze`, not `ci`: the latter prints a text
   banner before JSON.
2. In the consumer repository with a package.json, install Danger JS as
   a dev dependency (`npm install --save-dev danger`). Copy the adapter
   to `tooling/danger/sanctifier.cjs` in that repository.
3. Copy the following to the repository's root `Dangerfile.js`, editing
   projectPath to the checked-out Soroban project directory:

       const { runSanctifierDanger } = require('./tooling/danger/sanctifier.cjs');
       schedule(runSanctifierDanger({
         danger, warn, fail, message,
         projectPath: 'contracts/demo',
       }));

4. In a PR-triggered GitHub Actions workflow, install Sanctifier and
   project dependencies before invoking Danger. For example:

       name: Danger Soroban findings
       on:
         pull_request:
       permissions:
         contents: read
         pull-requests: write
         issues: write
       jobs:
         danger:
           runs-on: ubuntu-latest
           steps:
             - uses: actions/checkout@v4
             - uses: actions/setup-node@v4
               with:
                 node-version: '20'
             - run: npm ci
             # Install the trusted Sanctifier release for this project here.
             - run: sanctifier --version
             - run: npx danger ci
               env:
                 GITHUB_TOKEN: ${{ github.token }}

   GitHub may withhold write permissions on forked PRs. If so, do not
   move untrusted PR code to a privileged pull_request_target job;
   use a trusted artifact-reporting workflow or an appropriately configured
   repository automation identity instead.

## Behavior and limitations

- Danger obtains the PR file list and per-file diffs. The adapter parses
  added-line hunk positions and matches only those to CLI JSON locations.
- Finding codes and short descriptions appear as Danger inline warnings.
  At most 20 inline warnings are posted; a summary counts any remainder.
- The CLI's existing .sanctify-baseline.json suppresses known findings.
  Without a baseline, an issue on an added line is *potentially new*,
  not evidence that the entire repository is safe.
- Findings without a usable Rust path+line, findings outside added PR lines,
  and removed-file findings are intentionally not posted as new comments.
- Missing diffs, scan errors, malformed JSON and incompatible schemas
  cause a Danger failure instead of a false clean report.
- The adapter uses a bounded local execFileSync call (no shell),
  a 120-second timeout and an 8 MiB JSON output bound.
- Actual PR comments are posted by Danger when `danger ci` is run with
  a permitted provider identity; the adapter itself is offline.

## Focused smoke example

Run from a checkout with Node 20+ (no dependency install/network needed):

    node tooling/danger/smoke.cjs

The example injects one CLI-schema report and a two-added-line PR diff,
checks that only the newly added-line finding becomes a file/line warning,
and checks that an invalid scanner schema fails closed. This is an
offline smoke, not a live GitHub PR comment or a production contract scan.
Once reviewed, verify the full integration in a disposable example PR
where comment-write permissions are explicitly available.

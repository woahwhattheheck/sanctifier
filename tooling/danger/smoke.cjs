"use strict";

// One offline, bounded example-repo smoke test; no Danger token or network needed.
const assert = require("node:assert/strict");
const { addedLineNumbers, runSanctifierDanger } = require("./sanctifier.cjs");

async function main() {
  assert.deepEqual([...addedLineNumbers("@@ -2,0 +4,2 @@\n+new code\n+another\n")], [4, 5]);

  const reported = [];
  const failed = [];
  const infos = [];
  const exampleFile = "contracts/demo/src/lib.rs";
  const danger = {
    git: {
      modified_files: [exampleFile],
      created_files: [],
      diffForFile: async () => ({
        diff: "@@ -3,1 +3,3 @@\n context\n+panic!();\n+let x = 1;\n context\n",
      }),
    },
  };
  const report = {
    metadata: { format: "sanctifier-ci-v1" },
    findings: {
      panic_issues: [
        { code: "PANIC_USAGE", location: "contracts/demo/src/lib.rs:4", issue_type: "panic macro" },
        { code: "PANIC_USAGE", location: "contracts/demo/src/lib.rs:2", issue_type: "existing line" },
      ],
      auth_gaps: [],
    },
  };

  const common = {
    danger,
    projectPath: "contracts/demo",
    warn: (...args) => reported.push(args),
    fail: (reason) => failed.push(reason),
    message: (info) => infos.push(info),
  };
  const result = await runSanctifierDanger({ ...common, scan: () => JSON.stringify(report) });
  assert.equal(result.reported, 1);
  assert.deepEqual(reported[0], ["Sanctifier PANIC_USAGE: panic macro", exampleFile, 4]);
  assert.equal(failed.length, 0);

  await runSanctifierDanger({ ...common, scan: () => JSON.stringify({ findings: {} }) });
  assert.equal(failed.length, 1, "invalid scanner shape must fail closed");
  assert.equal(reported.length, 1, "invalid shape cannot report fake findings");
  process.stdout.write("Sanctifier Danger example smoke: PASS (diff, inline finding, failure gate)\n");
}

main().catch((err) => {
  process.stderr.write(String(err) + "\n");
  process.exitCode = 1;
});

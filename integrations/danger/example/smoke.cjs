"use strict";
const assert = require("node:assert/strict");
const report = require("./sample-report.json");
const { reportSanctifierFindings, collectFindings } = require("../sanctifier-danger.cjs");
const calls = { fail: [], warn: [], message: [], markdown: [] };
const actions = Object.fromEntries(Object.entries(calls).map(([key, entries]) => [key, (...args) => entries.push(args)]));
const result = reportSanctifierFindings(report, actions, {
  changedFiles: ["contracts/example/src/lib.rs"], maxAnnotations: 3
});
assert.deepEqual({ count: result.count, fail: result.fail, warn: result.warn, message: result.message, annotated: result.annotated }, { count: 3, fail: 1, warn: 1, message: 1, annotated: 3 });
assert.equal(calls.fail[0][1], "contracts/example/src/lib.rs");
assert.equal(calls.fail[0][2], 42);
assert.equal(calls.markdown.length, 1);
assert.match(calls.markdown[0][0], /baseline-suppressed/);
assert.throws(() => collectFindings({ metadata: { format: "unknown" }, findings: {} }), /successful Sanctifier/);
console.log("Sanctifier Danger example smoke: PASS (counts, inline anchors, baseline summary, malformed-report rejection)");

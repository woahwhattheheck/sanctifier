"use strict";

// Danger JS adapter for the existing Sanctifier "analyze --format json" contract.
// No network/API clients or tokens are needed here; Danger owns PR comment posting.
const path = require("node:path");
const { execFileSync } = require("node:child_process");

function addedLineNumbers(diff) {
  const added = new Set();
  let next = null;
  for (const line of String(diff || "").split(/\r?\n/)) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunk) {
      next = Number(hunk[1]);
      continue;
    }
    if (next === null || line.startsWith("+++") || line.startsWith("---")) continue;
    if (line.startsWith("+")) added.add(next++);
    else if (line.startsWith(" ")) next++;
  }
  return added;
}

function findLocation(finding) {
  for (const value of [finding.location, finding.file, finding.snippet, finding.function]) {
    if (typeof value !== "string") continue;
    const match = /((?:[A-Za-z]:)?[^\s:"'(),]+\.rs)(?::(?:line\s*)?(\d+))?/.exec(value);
    if (match) {
      const line = Number(match[2] || finding.line);
      return { file: match[1], line: Number.isSafeInteger(line) && line > 0 ? line : null };
    }
  }
  const line = Number(finding.line);
  return { file: null, line: Number.isSafeInteger(line) && line > 0 ? line : null };
}

function candidateFiles(raw, root, projectPath) {
  if (!raw) return [];
  const absolute = path.isAbsolute(raw);
  let relative = absolute ? path.relative(root, raw) : raw;
  relative = relative.replace(/\\/g, "/").replace(/^\.\//, "");
  if (!relative || relative === ".." || relative.startsWith("../") || path.isAbsolute(relative)) return [];
  const project = String(projectPath || ".").replace(/\\/g, "/").replace(/^\.\//, "");
  const names = [relative];
  if (project !== "." && project !== "") names.push(path.posix.normalize(path.posix.join(project, relative)));
  return names.filter((name) => name !== ".." && !name.startsWith("../"));
}

function findingsFromReport(report) {
  if (!report || report.metadata?.format !== "sanctifier-ci-v1" ||
      !report.findings || typeof report.findings !== "object" || Array.isArray(report.findings)) {
    throw new Error("Unrecognized Sanctifier JSON findings schema");
  }
  const result = [];
  for (const [category, records] of Object.entries(report.findings)) {
    if (!Array.isArray(records)) throw new Error("Invalid Sanctifier JSON finding list");
    for (const item of records) {
      if (!item || typeof item !== "object") continue;
      const loc = findLocation(item);
      const code = String(item.code || category).replace(/[\r\n]/g, " ").slice(0, 64);
      const explanation = String(item.message || item.description || item.issue_type ||
        item.rule_name || item.function_name || item.struct_name || category)
        .replace(/[\r\n\t]/g, " ").replace(/\s+/g, " ").slice(0, 220);
      result.push({ code, explanation, file: loc.file, line: loc.line });
    }
  }
  return result;
}

/**
 * Runs one source scan and comments only on finding locations introduced in this PR.
 * Existing .sanctify-baseline.json is respected by the CLI.
 * @param {object} options { danger, warn, fail, message, projectPath?, executable?, cwd? }
 */
async function runSanctifierDanger(options) {
  const { danger, warn, fail, message } = options;
  const root = path.resolve(options.cwd || process.cwd());
  const projectPath = options.projectPath || ".";
  const files = [...new Set([...(danger.git.modified_files || []), ...(danger.git.created_files || [])])]
    .map((file) => file.replace(/\\/g, "/"))
    .filter((file) => file.endsWith(".rs"));

  if (!files.length) {
    message("Sanctifier: no added or modified Rust files in this PR.");
    return { reported: 0, skipped: 0 };
  }

  const changed = new Map();
  try {
    for (const file of files) {
      const diff = await danger.git.diffForFile(file);
      if (typeof diff?.diff !== "string") {
        fail("Sanctifier: PR diff unavailable for " + file + "; findings were not evaluated.");
        return { reported: 0, skipped: 0, failed: true };
      }
      changed.set(file, addedLineNumbers(diff.diff));
    }
  } catch {
    fail("Sanctifier: could not read the PR diff; findings were not evaluated.");
    return { reported: 0, skipped: 0, failed: true };
  }

  let report;
  try {
    const output = options.scan
      ? await options.scan()
      : execFileSync(options.executable || "sanctifier",
          ["analyze", projectPath, "--format", "json"],
          { cwd: root, encoding: "utf8", timeout: 120000, maxBuffer: 8 * 1024 * 1024 });
    report = JSON.parse(output);
    // Invalid projects and scanner failures must not silently pass as zero findings.
    if (report.success === false) throw new Error("Scanner reported failure");
  } catch {
    fail("Sanctifier: JSON analysis failed or returned invalid data; findings were not evaluated.");
    return { reported: 0, skipped: 0, failed: true };
  }

  let findings;
  try {
    findings = findingsFromReport(report);
  } catch {
    fail("Sanctifier: incompatible JSON findings schema; findings were not evaluated.");
    return { reported: 0, skipped: 0, failed: true };
  }

  const selected = new Map();
  let skipped = 0;
  for (const finding of findings) {
    if (!finding.file || !finding.line) { skipped++; continue; }
    const file = candidateFiles(finding.file, root, projectPath)
      .find((name) => changed.get(name)?.has(finding.line));
    if (!file) { skipped++; continue; }
    const key = [file, finding.line, finding.code, finding.explanation].join("\0");
    selected.set(key, { ...finding, file });
  }

  const ordered = [...selected.values()].sort((a, b) =>
    a.file.localeCompare(b.file) || a.line - b.line ||
    a.code.localeCompare(b.code) || a.explanation.localeCompare(b.explanation));
  const max = 20;
  for (const finding of ordered.slice(0, max)) {
    warn("Sanctifier " + finding.code + ": " + finding.explanation, finding.file, finding.line);
  }
  if (ordered.length > max) message("Sanctifier: " + (ordered.length - max) + " additional added-line findings; see the scanner JSON artifact.");
  if (!ordered.length) message("Sanctifier: no findings on added PR lines (not a full-repository clean bill).");
  return { reported: Math.min(ordered.length, max), skipped, total: ordered.length };
}

module.exports = { addedLineNumbers, candidateFiles, findingsFromReport, runSanctifierDanger };

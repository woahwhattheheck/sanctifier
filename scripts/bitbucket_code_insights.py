#!/usr/bin/env python3
"""Publish Sanctifier JSON findings as Bitbucket Cloud Code Insights annotations.

Stdlib only. In Bitbucket Pipelines use the documented localhost:29418
authentication proxy; outside Pipelines set BITBUCKET_CODE_INSIGHTS_TOKEN.
Without --publish the command outputs deterministic preview payloads.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPORT_ID = "sanctifier-security"
MAX_ANNOTATIONS = 1000
BATCH_SIZE = 100
DEFAULT_SEVERITY = {
    "auth_gaps": "HIGH",
    "vulnerability_db_matches": "HIGH",
    "storage_collisions": "HIGH",
    "smt_issues": "HIGH",
    "upgrade_risks": "HIGH",
    "unsafe_patterns": "MEDIUM",
    "arithmetic_issues": "MEDIUM",
    "panic_issues": "MEDIUM",
    "unhandled_results": "MEDIUM",
    "event_issues": "MEDIUM",
    "custom_rules": "MEDIUM",
    "ledger_size_warnings": "MEDIUM",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def file_line(location: object, scan_root: Path, repo_root: Path):
    """Only attach annotations to source paths demonstrably inside the clone."""
    if not isinstance(location, str):
        return None
    match = re.fullmatch(r"(.+?):([1-9][0-9]*)(?::[0-9]+)?", location.strip())
    if not match:
        return None
    filename, line_str = match.groups()
    file_path = Path(filename)
    candidates = (
        [file_path] if file_path.is_absolute()
        else [repo_root / file_path, scan_root / file_path]
    )
    resolved_repo = repo_root.resolve()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            relative = resolved.relative_to(resolved_repo)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            return relative.as_posix(), int(line_str)
    return None


def finding_message(entry: dict, category: str) -> str:
    for key in ("message", "description", "suggestion", "issue_type",
                "pattern_type", "category", "function_name", "rule_name"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return " ".join(value.split())[:500]
    return category.replace("_", " ")


def make_payload(report: dict, scan_root: Path, repo_root: Path, scan_exit: int):
    if not isinstance(report, dict) or report.get("success") is False:
        raise ValueError("Sanctifier scan failed or returned an error document")
    metadata = report.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("format") != "sanctifier-ci-v1":
        raise ValueError("Expected Sanctifier sanctifier-ci-v1 report format")
    findings = report.get("findings")
    if not isinstance(findings, dict):
        raise ValueError("Expected Sanctifier analyze --format json findings object")
    # CLI v1 serializes known-vulnerability matches at the report root,
    # not inside the nested findings map. Preserve their real file:line.
    root_matches = report.get("vulnerability_db_matches", [])
    if isinstance(root_matches, list):
        findings = dict(findings)
        findings["vulnerability_db_matches"] = root_matches
    summary = report.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("Expected Sanctifier summary object; refusing false PASS")

    count = summary.get("total_findings")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise ValueError("Missing or invalid Sanctifier total_findings count")
    if any(not isinstance(summary.get(key), bool)
           for key in ("has_high", "has_critical")):
        raise ValueError("Missing or invalid Sanctifier severity summary")
    failed = bool(summary.get("has_high") or summary.get("has_critical") or scan_exit)

    annotations = []
    seen = set()
    for category, entries in sorted(findings.items()):
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            location = entry.get("location")
            if not location and entry.get("file") and entry.get("line"):
                location = str(entry["file"]) + ":" + str(entry["line"])
            if not location:
                # Directory scans prefix unsafe/custom-rule snippets with the
                # actual source filename; the structured line is authoritative.
                snippet = entry.get("snippet")
                line = entry.get("line")
                source = (re.match(r"^(.+?\.rs):", snippet)
                          if isinstance(snippet, str) else None)
                if (source and isinstance(line, int)
                        and not isinstance(line, bool) and line > 0):
                    location = source.group(1) + ":" + str(line)
            path_line = file_line(location, scan_root, repo_root)
            if path_line is None:
                continue  # still reflected in summary; never invent locations
            path, line = path_line
            code = str(entry.get("code") or entry.get("vuln_id")
                       or category)[:80]
            message = finding_message(entry, category)
            severity = str(entry.get("severity") or DEFAULT_SEVERITY.get(
                category, "MEDIUM")).upper()
            severity = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(
                severity, severity
            )
            if severity not in SEVERITY_ORDER:
                severity = "MEDIUM"
            external_id = "sanctifier-" + hashlib.sha256(
                (category + "\0" + code + "\0" + path + "\0" + str(line)
                 + "\0" + message).encode("utf-8")
            ).hexdigest()[:24]
            if external_id in seen:
                continue
            seen.add(external_id)
            annotations.append({
                "external_id": external_id,
                "annotation_type": "VULNERABILITY",
                "result": "FAILED",
                "severity": severity,
                "title": "Sanctifier " + code,
                "summary": message[:240],
                "details": category + ": " + message,
                "path": path,
                "line": line,
            })
    annotations.sort(key=lambda item: (
        SEVERITY_ORDER[item["severity"]], item["path"], item["line"],
        item["external_id"]
    ))
    omitted = max(0, len(annotations) - MAX_ANNOTATIONS)
    annotations = annotations[:MAX_ANNOTATIONS]
    details = (
        str(count) + " finding(s); " + str(len(annotations))
        + " source-location annotations."
        + (" " + str(omitted) + " further located findings omitted "
           "at Bitbucket's 1000-annotation limit." if omitted else "")
        + " Findings without exact file:line remain in the JSON artifact."
    )
    report_payload = {
        "title": "Sanctifier Soroban security scan",
        "details": details,
        "report_type": "SECURITY",
        "reporter": "Sanctifier",
        "result": "FAILED" if failed else "PASSED",
        "data": [
            {"title": "Findings", "type": "NUMBER", "value": count},
            {"title": "Line annotations", "type": "NUMBER",
             "value": len(annotations)},
        ],
    }
    return report_payload, annotations


def api_client():
    token = os.environ.get("BITBUCKET_CODE_INSIGHTS_TOKEN", "").strip()
    in_pipeline = bool(os.environ.get("BITBUCKET_BUILD_NUMBER"))
    if token:
        return urllib.request.build_opener(), "https", {
            "Authorization": "Bearer " + token
        }
    if in_pipeline:
        proxy = "http://localhost:29418"
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy})
        ), "http", {}
    raise ValueError(
        "Publishing requires Bitbucket Pipelines or "
        "BITBUCKET_CODE_INSIGHTS_TOKEN (repository write scope)"
    )


def publish(report_payload: dict, annotations: list[dict]):
    workspace = os.environ.get("BITBUCKET_WORKSPACE")
    repo = os.environ.get("BITBUCKET_REPO_SLUG")
    commit = os.environ.get("BITBUCKET_COMMIT")
    if not all((workspace, repo, commit)):
        raise ValueError("BITBUCKET_WORKSPACE, BITBUCKET_REPO_SLUG and "
                         "BITBUCKET_COMMIT are required to publish")
    opener, protocol, auth_headers = api_client()
    values = [urllib.parse.quote(item, safe="") for item in
              (workspace, repo, commit, REPORT_ID)]
    base = (protocol + "://api.bitbucket.org/2.0/repositories/"
            + values[0] + "/" + values[1] + "/commit/" + values[2]
            + "/reports/" + values[3])

    def request(method: str, url: str, payload=None, allow_missing=False):
        headers = {"Accept": "application/json", **auth_headers}
        data = None
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        # Bitbucket may temporarily throttle annotations during PR builds.
        # Retry only recognized transient HTTP responses; never retry 401/403
        # (credentials/scopes) or validation errors as if they were outages.
        for attempt in range(3):
            try:
                with opener.open(req, timeout=30) as response:
                    return response.status
            except urllib.error.HTTPError as error:
                if allow_missing and error.code == 404:
                    return 404
                if error.code in (429, 502, 503, 504) and attempt < 2:
                    retry_after = error.headers.get("Retry-After", "")
                    try:
                        delay = min(30, max(1, int(retry_after)))
                    except (ValueError, TypeError):
                        delay = 2 ** (attempt + 1)
                    time.sleep(delay)
                    continue
                raise RuntimeError(
                    "Bitbucket Code Insights " + method + " failed: HTTP "
                    + str(error.code) + " " + str(error.reason)
                ) from error
            except urllib.error.URLError as error:
                raise RuntimeError(
                    "Bitbucket Code Insights request failed: " + str(error.reason)
                ) from error

    # Re-run against the same commit must not leave stale old annotations.
    # Deleting the report also clears its annotations; then republish both.
    request("DELETE", base, allow_missing=True)
    request("PUT", base, report_payload)
    for start in range(0, len(annotations), BATCH_SIZE):
        request("POST", base + "/annotations",
                annotations[start:start + BATCH_SIZE])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--scan-root", type=Path)
    parser.add_argument("--scan-exit-code", type=int, default=0)
    parser.add_argument("--publish", action="store_true",
                        help="POST to Bitbucket (otherwise print preview)")
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        metadata = report.get("metadata") if isinstance(report, dict) else None
        if not isinstance(metadata, dict):
            raise ValueError("Expected Sanctifier report metadata object")
        scan_root = args.scan_root
        if scan_root is None:
            scan_root = Path(
                str(metadata.get("project_path", "."))
            )
        if not scan_root.is_absolute():
            scan_root = args.repo_root / scan_root
        result, annotations = make_payload(
            report, scan_root, args.repo_root, args.scan_exit_code
        )
        if args.publish:
            publish(result, annotations)
            print("Published Sanctifier Code Insights: "
                  + str(len(annotations)) + " annotation(s)")
        else:
            print(json.dumps({"report": result, "annotations": annotations},
                             indent=2))
    except (ValueError, OSError, RuntimeError, json.JSONDecodeError) as error:
        print("Sanctifier Code Insights: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


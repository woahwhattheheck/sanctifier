#!/usr/bin/env python3
"""Publish a Sanctifier JSON scan as Bitbucket Cloud Code Insights.

Uses the documented Pipelines localhost proxy (no stored credentials) by
default, or a repository-scoped API token outside Pipelines. No dependencies.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib import error, parse, request

REPORT_ID = "sanctifier-security"
MAX_ANNOTATIONS = 1000
BATCH_SIZE = 100
LOCATION_RE = re.compile(r"(?P<path>(?:[^\s:]+/)*[^\s:]+\.rs):(?P<line>\d+)(?::\d+)?")
SECURITY = {"auth_gaps", "storage_collisions", "upgrade_risks", "vulnerability_db_matches"}
SEVERITY = {
    "auth_gaps": "HIGH",
    "storage_collisions": "HIGH",
    "upgrade_risks": "HIGH",
    "smt_issues": "HIGH",
    "ledger_size_warnings": "MEDIUM",
    "arithmetic_issues": "MEDIUM",
    "panic_issues": "MEDIUM",
    "unsafe_patterns": "MEDIUM",
    "event_issues": "LOW",
    "unhandled_results": "MEDIUM",
    "custom_rules": "MEDIUM",
    "vulnerability_db_matches": "HIGH",
}


def find_source(item: dict, root: Path) -> tuple[str | None, int | None]:
    """Return a repo-relative Rust file/line, never a host-absolute path."""
    line = item.get("line")
    if type(line) is not int or line < 1:
        line = None
    raw = str(item.get("file") or item.get("path") or item.get("location") or item.get("snippet") or "")
    match = LOCATION_RE.search(raw)
    if match:
        raw = match.group("path")
        line = line or int(match.group("line"))
    elif not raw.endswith(".rs"):
        return None, None

    source = Path(raw)
    if source.is_absolute():
        try:
            source = source.resolve().relative_to(root.resolve())
        except ValueError:
            return None, None
    else:
        source = Path(os.path.normpath(str(source)))
        if source.parts and source.parts[0] == "..":
            return None, None
    return source.as_posix(), line


def normalize_findings(scan: dict, root: Path) -> list[dict]:
    groups = scan.get("findings", {})
    if not isinstance(groups, dict):
        raise ValueError("Invalid Sanctifier report: findings must be an object")
    # The CLI reports vulnerability DB matches at top level, outside findings.
    groups = dict(groups)
    groups["vulnerability_db_matches"] = scan.get("vulnerability_db_matches", [])
    result: dict[str, dict] = {}
    for group, items in groups.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            code = str(item.get("code") or group)
            message = next(
                (str(item[k]) for k in ("message", "description", "suggestion", "snippet",
                                        "function", "function_name", "key_value", "struct_name")
                 if item.get(k) is not None),
                group.replace("_", " "),
            ).replace("\n", " ").strip()
            path, line = find_source(item, root)
            sev = str(item.get("severity") or "").upper()
            if sev == "ERROR":
                sev = "HIGH"
            elif sev == "WARNING":
                sev = "MEDIUM"
            elif sev == "INFO":
                sev = "LOW"
            if sev not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                sev = SEVERITY.get(group, "MEDIUM")
            summary = f"[{code}] {message}"[:240]
            key = json.dumps([group, code, path, line, summary], ensure_ascii=False)
            external_id = "sanctifier-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
            annotation = {
                "external_id": external_id,
                "annotation_type": "VULNERABILITY" if group in SECURITY else "BUG",
                "result": "FAILED",
                "severity": sev,
                "summary": summary,
            }
            if path:
                annotation["path"] = path
            if line:
                annotation["line"] = line
            result[external_id] = annotation
    # Stable ordering and IDs across identical reruns; cap at Bitbucket limit.
    return sorted(result.values(), key=lambda a: (a.get("path", ""), a.get("line", 0), a["external_id"]))


def make_payload(scan: dict, root: Path) -> tuple[dict, list[dict]]:
    if scan.get("metadata", {}).get("format") != "sanctifier-ci-v1":
        raise ValueError("Input is not a Sanctifier analyze --format json report")
    summary = scan.get("summary", {})
    annotations = normalize_findings(scan, root)
    total = summary.get("total_findings", len(annotations))
    if type(total) is not int or total < 0:
        raise ValueError("Invalid Sanctifier finding count")
    high = bool(summary.get("has_high") or summary.get("has_critical"))
    included = annotations[:MAX_ANNOTATIONS]
    omitted = max(0, len(annotations) - len(included))
    report = {
        "title": "Sanctifier security scan",
        "reporter": "Sanctifier",
        "report_type": "SECURITY",
        "result": "FAILED" if high else "PASSED",
        "details": f"{total} findings; {len(included)} annotations; {omitted} omitted by Bitbucket limit. Critical/high findings fail the scan.",
        "data": [
            {"title": "Findings", "type": "NUMBER", "value": total},
            {"title": "Annotations", "type": "NUMBER", "value": len(included)},
            {"title": "Omitted", "type": "NUMBER", "value": omitted},
        ],
    }
    return report, included


def post_json(opener: request.OpenerDirector, method: str, url: str, payload: object | None,
              token: str | None, not_found_ok: bool = False) -> None:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for attempt in range(3):
        req = request.Request(url, data=body, headers=headers, method=method)
        try:
            with opener.open(req, timeout=25) as response:
                if response.status >= 300:
                    raise RuntimeError(f"Bitbucket Code Insights HTTP {response.status} for {method}")
            return
        except error.HTTPError as exc:
            if not_found_ok and exc.code == 404:
                return
            if exc.code not in {429, 502, 503, 504} or attempt == 2:
                raise RuntimeError(f"Bitbucket Code Insights HTTP {exc.code} for {method}") from exc
            retry_after = exc.headers.get("Retry-After", "")
            try:
                backoff = min(30, max(1, int(retry_after)))
            except ValueError:
                backoff = 2 ** (attempt + 1)
            time.sleep(backoff)
        except error.URLError as exc:
            raise RuntimeError(f"Bitbucket Code Insights connection failed: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="sanctifier analyze --format json output")
    parser.add_argument("--root", default=".", type=Path, help="root of Bitbucket repository")
    parser.add_argument("--report-id", default=REPORT_ID)
    parser.add_argument("--auth-mode", choices=("pipeline", "token"), default="pipeline")
    parser.add_argument("--dry-run", action="store_true", help="render report and annotations without network")
    args = parser.parse_args()

    scan = json.loads(args.input.read_text(encoding="utf-8"))
    report, annotations = make_payload(scan, args.root)
    if args.dry_run:
        print(json.dumps({"report": report, "annotations": annotations}, indent=2))
        return 0

    workspace = os.environ.get("BITBUCKET_WORKSPACE") or os.environ.get("BITBUCKET_REPO_OWNER")
    repository = os.environ.get("BITBUCKET_REPO_SLUG")
    commit = os.environ.get("BITBUCKET_COMMIT")
    if not all((workspace, repository, commit)):
        raise ValueError("BITBUCKET_WORKSPACE, BITBUCKET_REPO_SLUG and BITBUCKET_COMMIT required")
    token = os.environ.get("BITBUCKET_API_TOKEN") if args.auth_mode == "token" else None
    if args.auth_mode == "token" and not token:
        raise ValueError("BITBUCKET_API_TOKEN is required outside Pipelines")
    if args.auth_mode == "pipeline":
        # Atlassian's Pipelines proxy adds the authorization header automatically.
        base = "http://api.bitbucket.org/2.0"
        opener = request.build_opener(request.ProxyHandler({"http": "http://localhost:29418"}))
    else:
        base = "https://api.bitbucket.org/2.0"
        opener = request.build_opener(request.ProxyHandler({}))

    def q(v: str) -> str:
        return parse.quote(v, safe="")

    url = f"{base}/repositories/{q(workspace)}/{q(repository)}/commit/{q(commit)}/reports/{q(args.report_id)}"
    # Replace, rather than append stale annotations on subsequent pipeline reruns.
    post_json(opener, "DELETE", url, None, token, not_found_ok=True)
    post_json(opener, "PUT", url, report, token)
    for offset in range(0, len(annotations), BATCH_SIZE):
        post_json(opener, "POST", url + "/annotations", annotations[offset:offset + BATCH_SIZE], token)
    print(f"Published {len(annotations)} Sanctifier Code Insights annotations for {commit}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"sanctifier-bitbucket: {exc}", file=sys.stderr)
        sys.exit(2)

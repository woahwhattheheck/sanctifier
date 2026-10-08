#!/usr/bin/env python3
"""Convert Sanctifier's analyze --format json report to GitLab Code Quality and SARIF.

Uses only the Python standard library. Unlocated findings remain in SARIF,
but are not assigned invented file/line positions in GitLab Code Quality.
"""
from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import quote

SOURCE_LOCATION = re.compile(r"(?P<path>(?:[A-Za-z]:)?[^:\r\n]+?\.rs):(?:line\s*)?(?P<line>\d+)", re.I)
HIGH_GROUPS = {"auth_gaps", "panic_issues", "arithmetic_issues", "smt_issues"}
SEVERITIES = {
    "critical": "blocker", "blocker": "blocker",
    "high": "major", "error": "major", "major": "major",
    "medium": "minor", "warning": "minor", "minor": "minor",
    "low": "info", "info": "info", "informational": "info",
}


def path_in_repo(raw: str, root: Path, scan_root: str) -> str | None:
    """Accept locations only for existing regular files inside the checkout.

    Resolve symlinks and the optional scan-project prefix before exposing a
    location. Unknown or outside-root positions remain unlocated in SARIF.
    """
    path = raw.strip().replace("\\", "/")
    if not path.endswith(".rs"):
        return None

    root = root.resolve()
    if re.match(r"^[A-Za-z]:/", path):
        # A Windows drive path cannot be verified on a non-Windows runner.
        if sys.platform != "win32":
            return None
        candidates = [Path(path)]
    elif path.startswith("/"):
        candidates = [Path(path)]
    else:
        path = path.removeprefix("./")
        parts = PurePosixPath(path).parts
        if not parts or any(part in (".", "..") for part in parts):
            return None
        candidates = [root / path]
        scan = scan_root.strip().replace("\\", "/").strip("/")
        scan_parts = PurePosixPath(scan).parts
        if scan not in ("", ".") and all(part not in (".", "..") for part in scan_parts):
            if not path.startswith(scan + "/"):
                candidates.append(root / scan / path)

    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            relative = resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            continue
        if resolved.is_file():
            return relative.as_posix()
    return None


@lru_cache(maxsize=256)
def source_line_count(path: Path) -> int:
    """Read source lines once per file to avoid synthesizing impossible positions."""
    with path.open("rb") as stream:
        return sum(1 for _ in stream)


def verified_line(root: Path, relative: str, line: object) -> bool:
    """Booleans are not line numbers; the actual checked-out line must exist."""
    if type(line) is not int or line <= 0:
        return False
    try:
        return line <= source_line_count(root / relative)
    except OSError:
        return False


def source_location(item: dict, root: Path, scan_root: str) -> tuple[str, int] | None:
    for field in ("location", "file", "snippet", "function"):
        value = item.get(field)
        if not isinstance(value, str):
            continue
        match = SOURCE_LOCATION.search(value)
        if match:
            path = path_in_repo(match["path"], root, scan_root)
            if path:
                line = int(match["line"])
                if verified_line(root, path, line):
                    return path, line
        if value.strip().endswith(".rs") and type(item.get("line")) is int:
            path = path_in_repo(value, root, scan_root)
            if path and verified_line(root, path, item["line"]):
                return path, item["line"]
    return None


def iter_findings(report: dict):
    findings = report.get("findings")
    if not isinstance(findings, dict):
        raise ValueError("expected Sanctifier JSON with a 'findings' object")
    for group, entries in sorted(findings.items()):
        if not isinstance(entries, list):
            raise ValueError(f"findings.{group} must be an array")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"findings.{group} contains a non-object")
            yield group, entry
    # The analyzer places vulnerability DB matches at the top level, outside
    # 'findings', so a converter using only findings silently drops them.
    for match in report.get("vulnerability_db_matches", []):
        if not isinstance(match, dict):
            raise ValueError("vulnerability_db_matches contains a non-object")
        yield "vulnerability_db_matches", match


def convert(report: dict, root: Path) -> tuple[list[dict], dict]:
    metadata = report.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("format") != "sanctifier-ci-v1":
        raise ValueError("expected metadata.format='sanctifier-ci-v1', not an error/text report")
    scan_root = str(metadata.get("project_path") or ".")
    quality = []
    results = []
    rule_ids = set()
    seen = set()
    fingerprint_occurrences: dict[tuple[str, str, str], int] = {}

    for group, finding in iter_findings(report):
        code = str(finding.get("code") or finding.get("vuln_id") or "SANCTIFIER_" + group.upper())
        description = str(
            finding.get("message") or finding.get("description") or
            finding.get("suggestion") or finding.get("issue_type") or
            finding.get("function_name") or finding.get("function") or
            finding.get("rule_name") or group.replace("_", " ")
        )
        severity = SEVERITIES.get(str(finding.get("severity") or "").lower())
        severity = severity or ("major" if group in HIGH_GROUPS else "minor")
        location = source_location(finding, root, scan_root)
        identity = (code, description, location)
        if identity in seen:
            continue
        seen.add(identity)
        rule_ids.add(code)
        sarif_result = {
            "ruleId": code,
            "level": "error" if severity in ("blocker", "major") else
                     "warning" if severity == "minor" else "note",
            "message": {"text": description},
        }
        if location:
            path, line = location
            # GitLab compares Code Quality fingerprints across revisions. A
            # harmless line insertion must not report inherited debt as new.
            # Number identical findings in deterministic scan order so distinct
            # occurrences still retain distinct fingerprints.
            fingerprint_key = (code, path, description)
            occurrence = fingerprint_occurrences.get(fingerprint_key, 0)
            fingerprint_occurrences[fingerprint_key] = occurrence + 1
            fingerprint = hashlib.sha256(
                f"{code}\0{path}\0{description}\0{occurrence}".encode("utf-8")
            ).hexdigest()
            quality.append({
                "description": description,
                "check_name": code,
                "fingerprint": fingerprint,
                "severity": severity,
                "location": {"path": path, "lines": {"begin": line}},
            })
            sarif_result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(path, safe="/")},
                    "region": {"startLine": line},
                }
            }]
        results.append(sarif_result)

    quality.sort(key=lambda x: (x["location"]["path"], x["location"]["lines"]["begin"], x["check_name"], x["description"]))
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Sanctifier",
                "rules": [{"id": code, "shortDescription": {"text": code}} for code in sorted(rule_ids)],
            }},
            "results": results,
        }],
    }
    return quality, sarif


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="sanctifier analyze --format json output")
    parser.add_argument("--root", type=Path, default=Path("."), help="checked-out GitLab project root")
    parser.add_argument("--codequality", required=True, type=Path, help="GitLab Code Quality JSON output")
    parser.add_argument("--sarif", required=True, type=Path, help="SARIF 2.1.0 JSON output")
    args = parser.parse_args()
    try:
        report = json.loads(args.input.read_text(encoding="utf-8"))
        quality, sarif = convert(report, args.root.resolve())
        for target, payload in ((args.codequality, quality), (args.sarif, sarif)):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"sanctifier GitLab report conversion failed: {exc}", file=sys.stderr)
        return 2
    print(f"Converted {len(sarif['runs'][0]['results'])} findings: {len(quality)} located for GitLab Code Quality; SARIF includes unlocated findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

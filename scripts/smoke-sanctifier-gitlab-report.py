#!/usr/bin/env python3
"""Focused GitLab Code Quality/SARIF smoke using the existing SEP-41 example.

--fixture runs converter-only, using a synthetic report in the schema of
Sanctifier's analyze --format json output, including the location strings the
CLI writes for each detector; it does not run the Rust scanner.
Without --fixture, invoke an installed scanner against the real Soroban example.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


REPO = Path(__file__).resolve().parents[1]
EXAMPLE = "contracts/sep41-token-invariants"
CONVERTER = REPO / "scripts" / "sanctifier-gitlab-report.py"


def example_fixture() -> dict:
    return {
        "metadata": {"format": "sanctifier-ci-v1", "project_path": EXAMPLE},
        "findings": {
            "panic_issues": [
                {"code": "S002", "function_name": "initialize",
                 "issue_type": "panic!", "location": "src/lib.rs:63"},
                {"code": "S002", "function_name": "initialize",
                 "issue_type": "panic!", "location": "src/lib.rs:62"},
                {"code": "TEST_BAD_LINE", "issue_type": "outside existing source",
                 "location": "src/lib.rs:2147483647"},
                {"code": "TEST_BOOL_LINE", "issue_type": "boolean location",
                 "file": "src/lib.rs", "line": True},
                # The CLI reports panics by function only, with no line. The
                # repeated entry is an exact duplicate and must collapse.
                {"code": "S002", "function_name": "initialize",
                 "issue_type": "panic!", "location": f"{EXAMPLE}/src/lib.rs:initialize"},
                {"code": "S002", "function_name": "burn_from",
                 "issue_type": "panic!", "location": f"{EXAMPLE}/src/lib.rs:burn_from"},
                {"code": "S002", "function_name": "burn_from",
                 "issue_type": "panic!", "location": f"{EXAMPLE}/src/lib.rs:burn_from"},
            ],
            # Location strings exactly as `sanctifier analyze` writes them.
            "arithmetic_issues": [
                {"code": "S003", "function_name": "burn_from", "operation": "-",
                 "suggestion": "Use .checked_sub(rhs) or .saturating_sub(rhs) to handle underflow",
                 "location": f"{EXAMPLE}/src/lib.rs:burn_from:201"},
            ],
            "storage_collisions": [
                {"code": "S005", "key_value": "admin", "key_type": "storage::set (persistent)",
                 "location": f"{EXAMPLE}/src/lib.rs:storage-op:69",
                 "message": "Potential persistent storage key collision: value 'admin' is also used in: storage-op (line 104)"},
            ],
            "unsafe_patterns": [
                {"code": "S006", "pattern_type": "Panic", "line": 62,
                 "snippet": f'{EXAMPLE}/src/lib.rs:panic ! ("already initialized")'},
            ],
            "ledger_size_warnings": [
                {"code": "S004", "struct_name": "ExampleState",
                 "estimated_size": 65000, "limit": 64000, "level": "ExceedsLimit"}
            ],
        },
        "vulnerability_db_matches": [],
    }


def scan_example(cli: str) -> dict:
    result = subprocess.run(
        [cli, "analyze", EXAMPLE, "--format", "json"],
        cwd=REPO, text=True, capture_output=True, check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"analyzer failed unexpectedly ({result.returncode}): "
            + result.stderr[-1200:]
        )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"analyzer did not emit JSON: {result.stderr[-1000:]}") from exc
    if not isinstance(report, dict) or report.get("metadata", {}).get("format") != "sanctifier-ci-v1":
        raise RuntimeError("analyzer did not emit a Sanctifier CI report")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", default="sanctifier", help="installed Sanctifier command")
    parser.add_argument("--fixture", action="store_true", help="run converter only on a synthetic schema-accurate report")
    args = parser.parse_args()

    try:
        example_source = REPO / EXAMPLE / "src" / "lib.rs"
        if not example_source.is_file():
            raise RuntimeError(f"missing example project: {EXAMPLE}")
        with tempfile.TemporaryDirectory(prefix="sanctifier-gitlab-smoke-") as directory:
            workspace = Path(directory)
            report_root = REPO
            if args.fixture:
                # Run the synthetic fixture against an isolated checkout root so
                # location validation cannot accidentally trust the real source
                # repository outside the requested --root boundary.
                report_root = workspace / "checkout"
                fixture_source = report_root / EXAMPLE / "src" / "lib.rs"
                fixture_source.parent.mkdir(parents=True, exist_ok=True)
                fixture_source.write_bytes(example_source.read_bytes())

                outside_source = workspace / "outside.rs"
                outside_source.write_text("pub fn outside_checkout() {}\n", encoding="utf-8")
                escaping_link = report_root / EXAMPLE / "src" / "escape.rs"
                escaping_link.symlink_to(outside_source)

                report = example_fixture()
                report["findings"]["panic_issues"].extend([
                    {"code": "TEST_MISSING_FILE", "issue_type": "missing source",
                     "location": "src/missing.rs:1"},
                    {"code": "TEST_TRAVERSAL", "issue_type": "parent traversal",
                     "location": "../outside.rs:1"},
                    {"code": "TEST_ABSOLUTE_OUTSIDE", "issue_type": "outside checkout",
                     "file": str(outside_source), "line": 1},
                    {"code": "TEST_SYMLINK_ESCAPE", "issue_type": "escaping symlink",
                     "location": "src/escape.rs:1"},
                ])
            else:
                report = scan_example(args.cli)

            input_file = workspace / "analyzer.json"
            codequality_file = workspace / "codequality.json"
            sarif_file = workspace / "report.sarif"
            input_file.write_text(json.dumps(report), encoding="utf-8")
            converted = subprocess.run(
                [sys.executable, str(CONVERTER), "--input", str(input_file),
                 "--root", str(report_root), "--codequality", str(codequality_file),
                 "--sarif", str(sarif_file)],
                cwd=REPO, text=True, capture_output=True, check=False,
            )
            if converted.returncode != 0:
                raise RuntimeError(f"report converter failed: {converted.stderr.strip()}")
            quality = json.loads(codequality_file.read_text(encoding="utf-8"))
            sarif = json.loads(sarif_file.read_text(encoding="utf-8"))
            if not isinstance(quality, list) or sarif.get("version") != "2.1.0":
                raise RuntimeError("invalid output report structure")
            results = sarif["runs"][0]["results"]
            if not isinstance(results, list):
                raise RuntimeError("missing SARIF results")
            resolved_root = report_root.resolve()
            for entry in quality:
                position = entry["location"]
                source = (report_root / position["path"]).resolve()
                try:
                    source.relative_to(resolved_root)
                except ValueError as exc:
                    raise RuntimeError(f"Code Quality path escaped --root: {position}") from exc
                if not source.is_file() or position["lines"]["begin"] < 1:
                    raise RuntimeError(f"invalid source location: {position}")
                if len(entry["fingerprint"]) != 64:
                    raise RuntimeError("Code Quality entry lacks stable SHA-256 fingerprint")
            if args.fixture:
                if len(quality) != 5 or len(results) != 14:
                    raise RuntimeError("synthetic located/unlocated coverage changed")
                located = [entry for entry in results if "locations" in entry]
                if len(located) != 5:
                    raise RuntimeError("synthetic fixture must produce five located SARIF results")
                located_uris = {
                    entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    for entry in located
                }
                expected_uri = f"{EXAMPLE}/src/lib.rs"
                if located_uris != {expected_uri}:
                    raise RuntimeError(f"unexpected SARIF source locations: {sorted(located_uris)}")

                boundary_codes = {
                    "TEST_MISSING_FILE", "TEST_TRAVERSAL",
                    "TEST_ABSOLUTE_OUTSIDE", "TEST_SYMLINK_ESCAPE",
                }
                for code in boundary_codes:
                    matches = [entry for entry in results if entry.get("ruleId") == code]
                    if len(matches) != 1 or "locations" in matches[0]:
                        raise RuntimeError(f"{code} must appear exactly once and remain unlocated")
                if boundary_codes.intersection(entry["check_name"] for entry in quality):
                    raise RuntimeError("outside-checkout finding leaked into Code Quality")

                # The CLI's <file>.rs:<function>:<line> locations and line
                # fields with a <file>.rs: snippet must reach Code Quality.
                for code, line in {"S003": 201, "S005": 69, "S006": 62}.items():
                    lines = [entry["location"]["lines"]["begin"]
                             for entry in quality if entry["check_name"] == code]
                    if lines != [line]:
                        raise RuntimeError(f"{code} must reach Code Quality once at line {line}, got {lines}")
                # Panics reported by function name only have no line to
                # annotate. Each function keeps its own unlocated SARIF result
                # that names the analyzer's location; exact duplicates collapse.
                panic_references = sorted(
                    entry.get("properties", {}).get("analyzerLocation", "")
                    for entry in results if entry["ruleId"] == "S002" and "locations" not in entry
                )
                if panic_references != [f"{EXAMPLE}/src/lib.rs:burn_from", f"{EXAMPLE}/src/lib.rs:initialize"]:
                    raise RuntimeError(f"function-only panics must stay separate unlocated SARIF results: {panic_references}")

                fingerprints = {entry["fingerprint"] for entry in quality}
                if len(fingerprints) != len(quality):
                    raise RuntimeError("duplicate semantic findings require distinct fingerprints")

                # Shift only the source positions, not the finding identity.
                # The same inherited findings must not appear new in a GitLab MR.
                shifted_report = example_fixture()
                shifted_report["findings"]["panic_issues"].extend([
                    {"code": "TEST_MISSING_FILE", "issue_type": "missing source",
                     "location": "src/missing.rs:1"},
                    {"code": "TEST_TRAVERSAL", "issue_type": "parent traversal",
                     "location": "../outside.rs:1"},
                    {"code": "TEST_ABSOLUTE_OUTSIDE", "issue_type": "outside checkout",
                     "file": str(outside_source), "line": 1},
                    {"code": "TEST_SYMLINK_ESCAPE", "issue_type": "escaping symlink",
                     "location": "src/escape.rs:1"},
                ])
                shifts = {
                    "src/lib.rs:63": "src/lib.rs:61",
                    "src/lib.rs:62": "src/lib.rs:60",
                    f"{EXAMPLE}/src/lib.rs:burn_from:201": f"{EXAMPLE}/src/lib.rs:burn_from:199",
                    f"{EXAMPLE}/src/lib.rs:storage-op:69": f"{EXAMPLE}/src/lib.rs:storage-op:67",
                }
                for entries in shifted_report["findings"].values():
                    for entry in entries:
                        if entry.get("location") in shifts:
                            entry["location"] = shifts[entry["location"]]
                        elif entry.get("code") == "S006":
                            entry["line"] -= 2
                input_file.write_text(json.dumps(shifted_report), encoding="utf-8")
                shifted_result = subprocess.run(
                    [sys.executable, str(CONVERTER), "--input", str(input_file),
                     "--root", str(report_root), "--codequality", str(codequality_file),
                     "--sarif", str(sarif_file)],
                    cwd=REPO, text=True, capture_output=True, check=False,
                )
                if shifted_result.returncode != 0:
                    raise RuntimeError(f"shifted fixture conversion failed: {shifted_result.stderr.strip()}")
                shifted_quality = json.loads(codequality_file.read_text(encoding="utf-8"))
                if {entry["fingerprint"] for entry in shifted_quality} != fingerprints:
                    raise RuntimeError("source line shifts changed Code Quality fingerprints")

                # Distinct GitLab artifacts must never overwrite one another
                # or destroy the analyzer input when environment variables
                # accidentally resolve to the same destination.
                original_quality = codequality_file.read_bytes()
                overlap = subprocess.run(
                    [sys.executable, str(CONVERTER), "--input", str(input_file),
                     "--root", str(report_root), "--codequality", str(codequality_file),
                     "--sarif", str(codequality_file)],
                    cwd=REPO, text=True, capture_output=True, check=False,
                )
                if overlap.returncode != 2 or codequality_file.read_bytes() != original_quality:
                    raise RuntimeError("colliding report paths corrupted Code Quality")
                if "distinct paths" not in overlap.stderr:
                    raise RuntimeError("missing actionable collision diagnostic")

                original_input = input_file.read_bytes()
                overwrite = subprocess.run(
                    [sys.executable, str(CONVERTER), "--input", str(input_file),
                     "--root", str(report_root), "--codequality", str(input_file),
                     "--sarif", str(sarif_file)],
                    cwd=REPO, text=True, capture_output=True, check=False,
                )
                if overwrite.returncode != 2 or input_file.read_bytes() != original_input:
                    raise RuntimeError("report output corrupted analyzer input")
                if "must not overwrite --input" not in overwrite.stderr:
                    raise RuntimeError("missing actionable input-overwrite diagnostic")
            print(
                f"PASS ({'synthetic converter fixture' if args.fixture else 'real SEP-41 analyzer'}): "
                f"{len(quality)} located Code Quality entries, {len(results)} SARIF results"
            )
    except (OSError, ValueError, KeyError, IndexError, TypeError, RuntimeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Focused GitLab Code Quality/SARIF smoke using the existing SEP-41 example.

--fixture runs converter-only, using a synthetic report shaped exactly like
Sanctifier's analyze --format json output; it does not run the Rust scanner.
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
                {"code": "S003", "function_name": "initialize",
                 "issue_type": "panic!", "location": "src/lib.rs:63"},
                {"code": "TEST_BAD_LINE", "issue_type": "outside existing source",
                 "location": "src/lib.rs:2147483647"},
                {"code": "TEST_BOOL_LINE", "issue_type": "boolean location",
                 "file": "src/lib.rs", "line": True},
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
        if not (REPO / EXAMPLE / "src" / "lib.rs").is_file():
            raise RuntimeError(f"missing example project: {EXAMPLE}")
        report = example_fixture() if args.fixture else scan_example(args.cli)
        with tempfile.TemporaryDirectory(prefix="sanctifier-gitlab-smoke-") as directory:
            root = Path(directory)
            input_file = root / "analyzer.json"
            codequality_file = root / "codequality.json"
            sarif_file = root / "report.sarif"
            input_file.write_text(json.dumps(report), encoding="utf-8")
            converted = subprocess.run(
                [sys.executable, str(CONVERTER), "--input", str(input_file),
                 "--root", str(REPO), "--codequality", str(codequality_file),
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
            for entry in quality:
                position = entry["location"]
                source = REPO / position["path"]
                if not source.is_file() or position["lines"]["begin"] < 1:
                    raise RuntimeError(f"invalid source location: {position}")
                if len(entry["fingerprint"]) != 64:
                    raise RuntimeError("Code Quality entry lacks stable SHA-256 fingerprint")
            if args.fixture:
                if len(quality) != 1 or len(results) != 4:
                    raise RuntimeError("synthetic located/unlocated coverage changed")
                if sum("locations" in entry for entry in results) != 1:
                    raise RuntimeError("synthetic fixture must produce exactly one located SARIF result")
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

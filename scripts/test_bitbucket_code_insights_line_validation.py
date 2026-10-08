#!/usr/bin/env python3
"""Focused regression for Bitbucket Code Insights source-line validation."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("bitbucket_code_insights.py")
SPEC = importlib.util.spec_from_file_location("bitbucket_code_insights", MODULE_PATH)
bitbucket = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(bitbucket)


class BitbucketAnnotationLineValidationTest(unittest.TestCase):
    def test_impossible_source_line_is_not_annotated_but_remains_counted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            source = repo_root / "src" / "lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("first\nsecond\nthird\n", encoding="utf-8")

            report = {
                "metadata": {
                    "format": "sanctifier-ci-v1",
                    "project_path": ".",
                },
                "summary": {
                    "total_findings": 2,
                    "has_high": True,
                    "has_critical": False,
                },
                "findings": {
                    "panic_issues": [
                        {
                            "code": "S004",
                            "location": "src/lib.rs:2",
                            "message": "valid source line",
                        },
                        {
                            "code": "S004",
                            "location": "src/lib.rs:999999",
                            "message": "impossible source line",
                        },
                    ]
                },
            }

            bitbucket.source_line_count.cache_clear()
            report_payload, annotations = bitbucket.make_payload(
                report, repo_root, repo_root, 1
            )

            self.assertEqual(2, report_payload["data"][0]["value"])
            self.assertEqual(1, report_payload["data"][1]["value"])
            self.assertEqual(1, len(annotations))
            self.assertEqual("src/lib.rs", annotations[0]["path"])
            self.assertEqual(2, annotations[0]["line"])
            self.assertNotIn("999999", str(annotations))


if __name__ == "__main__":
    unittest.main()

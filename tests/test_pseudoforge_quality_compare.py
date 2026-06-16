from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.pseudoforge_quality_compare import compare_quality_reports, main, render_compare_markdown


class PseudoForgeQualityCompareTests(unittest.TestCase):
    def test_compare_quality_reports_marks_directional_deltas(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "old.json"
            new_path = Path(temp_dir) / "new.json"
            old_path.write_text(
                json.dumps(
                    {
                        "corpus_root": "old",
                        "totals": {
                            "summaries": 2,
                            "warnings": 10,
                            "applied_renames": 3,
                        },
                        "rename_stats": {"apply_rate": 30.0},
                        "body_text_stats": {"generic_identifier_tokens": 100},
                    }
                ),
                encoding="utf-8",
            )
            new_path.write_text(
                json.dumps(
                    {
                        "corpus_root": "new",
                        "totals": {
                            "summaries": 2,
                            "warnings": 4,
                            "applied_renames": 8,
                        },
                        "rename_stats": {"apply_rate": 80.0},
                        "body_text_stats": {"generic_identifier_tokens": 120},
                    }
                ),
                encoding="utf-8",
            )

            report = compare_quality_reports(old_path, new_path)
            metrics = {item["name"]: item for item in report["metrics"]}

            self.assertTrue(report["same_function_count"])
            self.assertEqual(-6, metrics["warnings"]["delta"])
            self.assertEqual("improved", metrics["warnings"]["status"])
            self.assertEqual(5, metrics["applied_renames"]["delta"])
            self.assertEqual("improved", metrics["applied_renames"]["status"])
            self.assertEqual(20, metrics["body_generic_identifier_tokens"]["delta"])
            self.assertEqual("regressed", metrics["body_generic_identifier_tokens"]["status"])
            self.assertIn("warnings", render_compare_markdown(report))

    def test_quality_compare_cli_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "old.json"
            new_path = Path(temp_dir) / "new.json"
            out_dir = Path(temp_dir) / "compare"
            payload = {
                "corpus_root": "sample",
                "totals": {"summaries": 1, "warnings": 1, "applied_renames": 1},
                "rename_stats": {"apply_rate": 100.0},
            }
            old_path.write_text(json.dumps(payload), encoding="utf-8")
            new_path.write_text(json.dumps(payload), encoding="utf-8")

            exit_code = main(
                [
                    "--old",
                    str(old_path),
                    "--new",
                    str(new_path),
                    "--out",
                    str(out_dir),
                    "--format",
                    "both",
                ]
            )

            self.assertEqual(0, exit_code)
            self.assertTrue((out_dir / "quality-compare.json").exists())
            self.assertTrue((out_dir / "quality-compare.md").exists())


if __name__ == "__main__":
    unittest.main()

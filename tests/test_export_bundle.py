from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.export_bundle import write_export_bundle
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import write_export_bundle as legacy_render_write_export_bundle


SAMPLE = """
__int64 __fastcall ExportBundleSample(int a1)
{
  int status;

  status = 0;
  if ( a1 )
  {
    status = -1073741823;
  }
  return status;
}
"""


class ExportBundleTests(unittest.TestCase):
    def test_write_export_bundle_includes_parity_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(SAMPLE, ea=0x140001000, source_path="sample.bin")
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

            for key in (
                "cleaned_pseudocode",
                "switch_outline",
                "rename_map",
                "flow_report",
                "rule_report",
                "raw_pseudocode",
                "warnings",
                "raw_vs_cleaned_diff",
                "summary",
            ):
                self.assertIn(key, artifacts)
                self.assertTrue(Path(artifacts[key]).exists(), key)

            self.assertEqual(Path(artifacts["raw_pseudocode"]).read_text(encoding="utf-8"), capture.pseudocode.rstrip() + "\n")
            diff_text = Path(artifacts["raw_vs_cleaned_diff"]).read_text(encoding="utf-8")
            self.assertTrue(diff_text.startswith("--- raw/ExportBundleSample.cpp\n"))
            self.assertIn("+++ cleaned/ExportBundleSample.cpp\n", diff_text)
            self.assertIsInstance(json.loads(Path(artifacts["warnings"]).read_text(encoding="utf-8")), list)

            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            self.assertEqual(summary["mode"], "ida_interactive")
            self.assertEqual(summary["function"], "ExportBundleSample")
            self.assertEqual(summary["function_ea"], "0x140001000")
            self.assertEqual(summary["source_path"], "sample.bin")
            self.assertIn("raw_vs_cleaned_diff", summary["artifacts"])
            self.assertEqual(artifacts["summary"], summary["artifacts"]["summary"])

    def test_write_export_bundle_allows_summary_suffix_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(SAMPLE, ea=0x140001000, source_path="sample.bin")
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_free_offline",
                summary_suffix="ida-free-summary",
            )

            summary_path = Path(artifacts["summary"])
            self.assertEqual("ExportBundleSample.ida-free-summary.json", summary_path.name)
            self.assertTrue(summary_path.exists())
            self.assertFalse((Path(temp_dir) / "ExportBundleSample.summary.json").exists())

    def test_legacy_render_export_import_remains_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(SAMPLE, ea=0x140001000, source_path="sample.bin")
            plan = build_clean_plan(capture)

            artifacts = legacy_render_write_export_bundle(temp_dir, capture, plan)

            self.assertTrue(Path(artifacts["cleaned_pseudocode"]).exists())
            self.assertTrue(Path(artifacts["summary"]).exists())


if __name__ == "__main__":
    unittest.main()

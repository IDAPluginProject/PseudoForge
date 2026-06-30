from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.claim_gap import render_world_class_gap_markdown, world_class_gap_report
from tests.test_claim_gate import _strong_report


class ClaimGapTests(unittest.TestCase):
    def test_world_class_gap_report_shows_missing_corpus_evidence(self) -> None:
        report = _strong_report()
        report["corpus_evidence"] = {
            "real_corpus_count": 2,
            "real_corpus_function_count": 85,
            "ground_truth_pair_count": 2,
            "qualified_ground_truth_pair_count": 2,
            "target_families": ["windows_user_pe", "linux_elf_user"],
        }

        gap = world_class_gap_report(report)
        metrics = {item["metric"]: item for item in gap["gaps"]}

        self.assertEqual("useful general assistant", gap["current_claim_level"])
        self.assertIn("corpus.real_corpus_function_count", metrics)
        self.assertEqual(915, metrics["corpus.real_corpus_function_count"]["missing"])
        self.assertIn("corpus.qualified_analyst_audit_count", metrics)
        self.assertFalse(gap["world_class_claim_allowed"])

    def test_world_class_gap_report_is_empty_for_full_evidence(self) -> None:
        report = _strong_report()
        report["accepted_observations"] = 45
        report["corpus_evidence"] = {
            "real_corpus_count": 5,
            "real_corpus_function_count": 1200,
            "ground_truth_pair_count": 300,
            "qualified_ground_truth_pair_count": 300,
            "ir_evidence_coverage": 0.75,
            "cross_function_contract_count": 50,
            "qualified_cross_function_contract_count": 50,
            "external_baseline_count": 2,
            "qualified_external_baseline_count": 2,
            "analyst_audit_count": 1,
            "qualified_analyst_audit_count": 1,
            "target_families": ["windows_user_pe", "linux_elf_user", "cxx_runtime", "uefi", "ue_cpp"],
        }

        gap = world_class_gap_report(report)
        markdown = render_world_class_gap_markdown(gap)

        self.assertEqual(0, gap["gap_count"])
        self.assertTrue(gap["world_class_claim_allowed"])
        self.assertIn("No world-class gaps remain.", markdown)

    def test_claim_gap_tool_writes_json_and_markdown(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"
            json_path = Path(temp_dir) / "gap.json"
            markdown_path = Path(temp_dir) / "gap.md"
            report_path.write_text(json.dumps(_strong_report()), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_claim_gap.py"),
                    str(report_path),
                    "--json-out",
                    str(json_path),
                    "--markdown-out",
                    str(markdown_path),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual("", completed.stderr)
            self.assertEqual(0, completed.returncode)
            gap = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")

        self.assertGreater(gap["gap_count"], 0)
        self.assertIn("PseudoForge World-Class Claim Gap", markdown)


if __name__ == "__main__":
    unittest.main()

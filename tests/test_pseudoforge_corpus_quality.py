from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.pseudoforge_corpus_quality import analyze_corpus, main


CLEANED = r"""
__int64 __fastcall Sample(__int64 a1)
{
  __int64 v1;

  v1 = *(_DWORD *)(a1 + 24LL);
  if ( v1 )
    goto LABEL_1;
  return -1073741811;
LABEL_1:
  return 0xC000000D;
}
"""


class PseudoForgeCorpusQualityTests(unittest.TestCase):
    def test_analyze_corpus_counts_warning_rename_rule_and_text_residue_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_quality_fixture(root)

            report = analyze_corpus(root)

            self.assertEqual("pseudoforge_corpus_quality_v1", report["schema"])
            self.assertEqual(1, report["totals"]["summaries"])
            self.assertEqual(1, report["totals"]["cleaned_files"])
            self.assertEqual(2, report["totals"]["warnings"])
            self.assertEqual(2, report["totals"]["applied_renames"])
            self.assertEqual(66.67, report["rename_stats"]["apply_rate"])
            self.assertEqual(2, report["rename_stats"]["by_source"]["llm"])
            self.assertEqual(1, report["rename_stats"]["applied_by_source"]["llm"])
            self.assertEqual(1, report["warning_stats"]["all_classes"]["llm_pascal_case"])
            self.assertEqual(1, report["warning_stats"]["all_classes"]["llm_pointer_bound"])
            self.assertEqual(2, report["rule_stats"]["rewrite_emissions"])
            self.assertEqual(1, report["rule_stats"]["rejected_emissions"])
            self.assertEqual(2, report["api_semantic_stats"]["diagnostics"])
            self.assertEqual(2, report["api_semantic_stats"]["rejections"])
            self.assertEqual(1, report["api_semantic_stats"]["functions_with_diagnostics"])
            self.assertEqual(1, report["api_semantic_stats"]["rejections_by_reason"]["large_dispatcher"])
            self.assertEqual(1, report["api_semantic_stats"]["rejections_by_reason"]["conflict_old"])
            self.assertEqual(1, report["api_semantic_stats"]["rejections_by_stage"]["api-argument"])
            self.assertEqual(1, report["api_semantic_stats"]["rejections_by_stage"]["api-out-param"])
            self.assertEqual(1, report["text_stats"]["offset_deref_patterns"])
            self.assertEqual(2, report["text_stats"]["label_tokens"])
            self.assertEqual(1, report["text_stats"]["decimal_status_like_literals"])
            self.assertEqual(1, report["text_stats"]["hex_status_like_literals"])

    def test_cli_writes_json_and_markdown_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            output_dir = Path(temp_dir) / "quality"
            _write_quality_fixture(root)
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--corpus-root",
                        str(root),
                        "--out",
                        str(output_dir),
                        "--format",
                        "both",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertTrue((output_dir / "corpus-quality.json").exists())
            self.assertTrue((output_dir / "corpus-quality.md").exists())
            self.assertIn("Wrote corpus quality report", stdout.getvalue())
            self.assertIn(
                "PseudoForge Corpus Quality Report",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "API Semantic Diagnostics",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )


def _write_quality_fixture(root: Path) -> None:
    function_dir = root / "functions" / "0000000140001000_Sample"
    function_dir.mkdir(parents=True)
    cleaned_path = function_dir / "Sample.cleaned.cpp"
    warnings_path = function_dir / "Sample.warnings.json"
    rename_map_path = function_dir / "Sample.rename-map.json"
    buffer_contracts_path = function_dir / "Sample.buffer-contracts.json"
    rule_report_path = function_dir / "Sample.rule-report.json"
    summary_path = function_dir / "Sample.ida-batch-summary.json"
    cleaned_path.write_text(CLEANED, encoding="utf-8")
    warnings_path.write_text(
        json.dumps(
            [
                "Skipped PascalCase LLM rename a1->PageTableBase",
                "Skipped pointer-bound rename v4->targetBuffer",
            ]
        ),
        encoding="utf-8",
    )
    rename_map_path.write_text(
        json.dumps(
            {
                "renames": [
                    {"old": "a1", "new": "PageTableBase", "source": "llm", "apply": False},
                    {"old": "v1", "new": "status", "source": "llm", "apply": True},
                    {"old": "v2", "new": "statusCode", "source": "kernel-status", "apply": True},
                ]
            }
        ),
        encoding="utf-8",
    )
    buffer_contracts_path.write_text(json.dumps([{"command_value": 0x90000000}]), encoding="utf-8")
    rule_report_path.write_text(
        json.dumps(
            {
                "matched_rules": [{"rule_id": "sample.rename"}, {"rule_id": "sample.flow"}],
                "rewrite_emissions": [{"kind": "flow"}, {"kind": "text_rewrite"}],
                "rejected_emissions": [{"reason": "conflict"}],
                "api_semantic_diagnostics": [
                    {
                        "stage": "api-argument",
                        "status": "rejected",
                        "reason": "large_dispatcher",
                        "old": "v7",
                        "new": "object",
                    },
                    {
                        "stage": "api-out-param",
                        "status": "rejected",
                        "reason": "conflict_old",
                        "old": "v8",
                        "new": "process",
                    },
                ],
                "validation_errors": [{"path": "rules.json", "error": "bad operator"}],
            }
        ),
        encoding="utf-8",
    )
    summary_path.write_text(
        json.dumps(
            {
                "mode": "ida_batch_export",
                "function": "Sample",
                "function_ea": "0x140001000",
                "rename_candidates": 3,
                "renames": 2,
                "flow_rewrites": 1,
                "buffer_contracts": 1,
                "warnings": 2,
                "rule_diagnostics": {"matched_rules": 2},
                "llm_status": "ok",
                "artifacts": {
                    "cleaned_pseudocode": "old/Sample.cleaned.cpp",
                    "warnings": "old/Sample.warnings.json",
                    "rename_map": "old/Sample.rename-map.json",
                    "buffer_contracts": "old/Sample.buffer-contracts.json",
                    "rule_report": "old/Sample.rule-report.json",
                    "summary": "old/Sample.ida-batch-summary.json",
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()

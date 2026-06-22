from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from tools.pseudoforge_cleanup_integrity import (
    analyze_cleanup_integrity,
    main,
    render_integrity_markdown,
)


BROKEN_CLEANED = r"""
__int64 __fastcall BrokenCleanup(__int64 argument0)
{
  // local variable allocation failed
  return BrokenHelper(
    argument0,
    {
    argument0 + 1;
}
"""


GOOD_CLEANED = r"""
__int64 __fastcall GoodCleanup(__int64 argument0)
{
  return GoodHelper(argument0, 1);
}
"""


class PseudoForgeCleanupIntegrityTests(unittest.TestCase):
    def test_broken_cleaned_output_reports_syntax_warning_and_stale_cache_issues(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140001000_BrokenCleanup"
            function_dir.mkdir(parents=True)
            cleaned_path = function_dir / "function.cleaned.cpp"
            warnings_path = function_dir / "function.warnings.json"
            summary_path = function_dir / "function.ida-batch-summary.json"
            cache_path = function_dir / "stale.llm-renames.json"
            cleaned_path.write_text(BROKEN_CLEANED.strip() + "\n", encoding="utf-8")
            warnings_path.write_text(
                json.dumps(
                    [
                        (
                            "Uninitialized local risk: skipped LLM rename v7->BufferLength: "
                            "v7 is declared but never assigned before use"
                        )
                    ],
                    indent=2,
                ),
                encoding="utf-8",
            )
            cache_path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_llm_candidate_cache_v1",
                        "function": "OtherFunction",
                        "function_ea": "0x14000FFFF",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "BrokenCleanup",
                        "function_ea": "0x140001000",
                        "llm_status": "fallback",
                        "artifacts": {
                            "cleaned_pseudocode": cleaned_path.name,
                            "warnings": warnings_path.name,
                            "llm_candidate_cache": cache_path.name,
                            "summary": summary_path.name,
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_cleanup_integrity(root, top=20)
            kinds = {item["kind"] for item in report["issues"]}
            markdown = render_integrity_markdown(report)

            self.assertEqual("pseudoforge_cleanup_integrity_v1", report["schema"])
            self.assertEqual(1, report["summary_count"])
            self.assertEqual(1, report["cleaned_file_count"])
            self.assertIn("standalone_brace_in_multiline_call", kinds)
            self.assertIn("unmatched_brace", kinds)
            self.assertIn("unmatched_paren", kinds)
            self.assertIn("local_variable_allocation_failed_comment", kinds)
            self.assertIn("declared_but_never_assigned_local_rename_warning", kinds)
            self.assertIn("stale_llm_candidate_cache_on_fallback", kinds)
            self.assertIn("PseudoForge Cleanup Integrity QA", markdown)
            self.assertIn("pseudoforge_corpus_quality.py", markdown)

    def test_warning_diagnostics_messages_are_scanned_when_warning_strings_are_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140001000_DiagnosticsOnly"
            function_dir.mkdir(parents=True)
            cleaned_path = function_dir / "function.cleaned.cpp"
            diagnostics_path = function_dir / "function.warning-diagnostics.json"
            summary_path = function_dir / "function.ida-batch-summary.json"
            cleaned_path.write_text(GOOD_CLEANED.strip() + "\n", encoding="utf-8")
            diagnostics_path.write_text(
                json.dumps(
                    [
                        {
                            "kind": "unassigned_local_live_in_register",
                            "message": (
                                "Uninitialized local risk: skipped LLM rename v7->BufferLength: "
                                "v7 is declared but never assigned before use"
                            ),
                            "symbol": "v7",
                            "usage": "call argument to Helper",
                            "usage_class": "call_argument",
                            "register": "r8d",
                            "register_class": "abi_argument",
                            "candidate_action": "parameter_gap_candidate",
                            "confidence": 0.78,
                            "source": "validation.unassigned_local_usage",
                        }
                    ],
                    indent=2,
                ),
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "DiagnosticsOnly",
                        "function_ea": "0x140001000",
                        "llm_status": "disabled",
                        "artifacts": {
                            "cleaned_pseudocode": cleaned_path.name,
                            "warning_diagnostics": diagnostics_path.name,
                            "summary": summary_path.name,
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_cleanup_integrity(root, top=20)

            kinds = {item["kind"] for item in report["issues"]}
            self.assertIn("declared_but_never_assigned_local_rename_warning", kinds)

    def test_main_writes_json_and_markdown_and_can_fail_on_issues(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140001000_BrokenCleanup"
            report_dir = root / "report"
            function_dir.mkdir(parents=True)
            cleaned_path = function_dir / "function.cleaned.cpp"
            summary_path = function_dir / "function.ida-batch-summary.json"
            cleaned_path.write_text(BROKEN_CLEANED.strip() + "\n", encoding="utf-8")
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "BrokenCleanup",
                        "function_ea": "0x140001000",
                        "llm_status": "disabled",
                        "artifacts": {
                            "cleaned_pseudocode": cleaned_path.name,
                            "summary": summary_path.name,
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            exit_code = main(
                [
                    "--corpus-root",
                    str(root),
                    "--out",
                    str(report_dir),
                    "--format",
                    "both",
                    "--fail-on-issues",
                ]
            )

            self.assertEqual(1, exit_code)
            self.assertTrue((report_dir / "cleanup-integrity.json").exists())
            self.assertTrue((report_dir / "cleanup-integrity.md").exists())

    def test_cleaned_file_without_summary_can_be_scanned_directly(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cleaned_path = root / "GoodCleanup.cleaned.cpp"
            cleaned_path.write_text(GOOD_CLEANED.strip() + "\n", encoding="utf-8")

            report = analyze_cleanup_integrity(root)

            self.assertEqual(0, report["summary_count"])
            self.assertEqual(1, report["cleaned_file_count"])
            self.assertEqual(0, report["issue_count"])

    def test_generated_header_comment_sanitizer_prevents_comment_break_issues(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140001000_CommentSafe"
            function_dir.mkdir(parents=True)
            cleaned_path = function_dir / "function.cleaned.cpp"
            summary_path = function_dir / "function.ida-batch-summary.json"
            capture = FunctionCapture(
                ea=0x140001000,
                name="CommentSafe",
                pseudocode="\n".join(
                    [
                        "__int64 __fastcall CommentSafe(__int64 a1)",
                        "{",
                        "  return a1;",
                        "}",
                    ]
                ),
            )
            plan = CleanPlan(
                function_ea=capture.ea,
                function_name=capture.name,
                input_fingerprint="fp",
            )
            plan.comments.append(
                {
                    "kind": "domain_structure_identity",
                    "text": "profile type evidence mixed(_KPROCESS */_QWORD)",
                    "confidence": 0.84,
                    "profile_id": "mixed(_DWORD */_QWORD)",
                    "structure": "EPROCESS",
                }
            )
            rendered = render_cleaned_pseudocode(capture, plan)
            cleaned_path.write_text(rendered, encoding="utf-8")
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "CommentSafe",
                        "function_ea": "0x140001000",
                        "llm_status": "disabled",
                        "artifacts": {
                            "cleaned_pseudocode": cleaned_path.name,
                            "summary": summary_path.name,
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_cleanup_integrity(root, top=20)

            self.assertIn("mixed(_KPROCESS * /_QWORD)", rendered)
            self.assertIn("mixed(_DWORD * /_QWORD)", rendered)
            self.assertNotIn("*/_QWORD", rendered)
            self.assertEqual(0, report["issue_count"])


if __name__ == "__main__":
    unittest.main()

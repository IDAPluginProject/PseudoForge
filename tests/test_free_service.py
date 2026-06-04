import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ida_pseudoforge.free.service import (
    FreeAnalysisCancelled,
    FreeAnalysisError,
    FreeAnalysisOptions,
    analyze_text,
    build_run_payload,
    default_session_output_dir,
    loaded_ida_modules,
    load_free_analysis_deps,
    parse_case_value,
    save_result_bundle,
)


SAMPLE = r"""
__int64 __fastcall free_service_sample(__int64 a1)
{
  int v1;

  v1 = a1;
  return v1;
}
"""


class FreeAnalysisServiceTests(unittest.TestCase):
    def test_analyze_text_writes_ida_free_bundle_without_ida_modules(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            deps = load_free_analysis_deps()
            deps.configure_profile_dir("")
            output_dir = Path(temp_dir) / "out"

            result = analyze_text(
                "Copied from IDA Free\n\n%s\nEnd copy\n" % SAMPLE,
                output_dir=output_dir,
                input_label="clipboard.cpp",
                deps=deps,
            )

            self.assertEqual("ida_free_offline", result.payload["mode"])
            self.assertFalse(result.payload["ida_apis_used"])
            self.assertFalse(result.payload["idb_modified"])
            self.assertEqual("disabled", result.llm_status)
            self.assertIn("PseudoForge", result.cleaned_text)
            self.assertIn("free_service_sample", result.function)
            self.assertTrue(Path(result.artifacts["cleaned_pseudocode"]).exists())
            self.assertTrue(Path(result.artifacts["raw_pseudocode"]).exists())
            self.assertTrue(Path(result.artifacts["raw_vs_cleaned_diff"]).exists())
            self.assertTrue(Path(result.artifacts["summary"]).exists())
            self.assertFalse(loaded_ida_modules())

    def test_analyze_text_rejects_missing_function(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(FreeAnalysisError, "No function-like pseudocode"):
                analyze_text("No function here", output_dir=Path(temp_dir) / "out")

    def test_analyze_text_rejects_multiple_functions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            text = "%s\n%s" % (SAMPLE, SAMPLE.replace("free_service_sample", "second_sample"))

            with self.assertRaisesRegex(FreeAnalysisError, "Multiple function-like pseudocode"):
                analyze_text(text, output_dir=Path(temp_dir) / "out")

    def test_llm_failure_uses_deterministic_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            failing_provider = temp_path / "failing_provider.py"
            failing_provider.write_text(
                "import sys\nsys.stderr.write('provider failed')\nsys.exit(2)\n",
                encoding="utf-8",
            )
            options = FreeAnalysisOptions(
                llm_enabled=True,
                llm_provider="codex_cli",
                llm_command="python %s --output {output_file}" % failing_provider,
            )

            result = analyze_text(SAMPLE, output_dir=temp_path / "out", options=options)

            self.assertEqual("failed_fallback", result.llm_status)
            self.assertIn("LLM rename assist failed", result.warnings[0])
            self.assertTrue(Path(result.artifacts["cleaned_pseudocode"]).exists())

    def test_service_applies_profile_dir_from_options(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            deps = load_free_analysis_deps()
            deps.configure_profile_dir("")
            previous_profile_dir = deps.active_profile_root()
            profile_dir = str(Path(temp_dir) / "profiles")

            with mock.patch.object(deps, "configure_profile_dir", wraps=deps.configure_profile_dir) as mocked:
                result = analyze_text(
                    SAMPLE,
                    output_dir=Path(temp_dir) / "out",
                    options=FreeAnalysisOptions(profile_dir=profile_dir),
                    deps=deps,
                )

            self.assertEqual(str(Path(profile_dir)), result.payload["profile_root"])
            self.assertEqual(previous_profile_dir, deps.active_profile_root())
            self.assertEqual([mock.call(profile_dir), mock.call(previous_profile_dir)], mocked.call_args_list)

    def test_save_result_bundle_reuses_existing_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            result = analyze_text(SAMPLE, output_dir=temp_path / "initial")

            saved = save_result_bundle(result, temp_path / "saved")

            self.assertEqual(result.function, saved.function)
            self.assertEqual(result.llm_status, saved.llm_status)
            self.assertEqual(result.payload["profile_root"], saved.payload["profile_root"])
            self.assertEqual(result.payload["active_profiles"], saved.payload["active_profiles"])
            self.assertEqual(result.payload["profile_manifests"], saved.payload["profile_manifests"])
            self.assertTrue(Path(saved.artifacts["cleaned_pseudocode"]).exists())
            self.assertTrue(Path(saved.artifacts["summary"]).exists())
            summary = json.loads(Path(saved.artifacts["summary"]).read_text(encoding="utf-8"))
            self.assertEqual(result.function, summary["function"])
            self.assertEqual(result.payload["active_profiles"], summary["active_profiles"])

    def test_cancellation_is_checked_between_safe_phases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(FreeAnalysisCancelled):
                analyze_text(
                    SAMPLE,
                    output_dir=Path(temp_dir) / "out",
                    cancel_check=lambda: True,
                )

    def test_run_payload_and_case_parsing_helpers(self) -> None:
        payload = build_run_payload([{"function": "f"}], [{"input": "missing", "error": "no"}])

        self.assertEqual("ida_free_offline", payload["mode"])
        self.assertFalse(payload["ida_apis_used"])
        self.assertEqual(0x91234000, parse_case_value("0x91234000u"))
        self.assertIn("PseudoForge", str(default_session_output_dir("copied.cpp")))


if __name__ == "__main__":
    unittest.main()

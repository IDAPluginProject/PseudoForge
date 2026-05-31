import contextlib
import io
import json
import types
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.offline_input import OfflinePseudocodeError, normalize_copied_pseudocode
from ida_pseudoforge.models.provider_registry import PROVIDER_OPENAI_COMPATIBLE, PROVIDER_ORDER
from ida_pseudoforge.version import VERSION
from tools import pseudoforge_cli
from tools import pseudoforge_free_console
from tools import pseudoforge_free_cli


SAMPLE = r"""
__int64 __fastcall free_sample(__int64 a1)
{
  int v1;

  v1 = a1;
  return v1;
}
"""


class PseudoForgeFreeCliTests(unittest.TestCase):
    def test_free_cli_import_does_not_load_ida_modules(self):
        self.assertFalse(pseudoforge_free_cli.loaded_ida_modules())

    def test_free_cli_help_does_not_load_analysis_dependencies(self):
        original = pseudoforge_free_cli._load_deps
        called = False

        def fail_if_called():
            nonlocal called
            called = True
            raise RuntimeError("analysis deps loaded")

        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            pseudoforge_free_cli._load_deps = fail_if_called
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    pseudoforge_free_cli.main(["--help"])
        finally:
            pseudoforge_free_cli._load_deps = original

        self.assertEqual(raised.exception.code, 0)
        self.assertFalse(called)
        self.assertIn("usage:", stdout.getvalue())
        self.assertEqual("", stderr.getvalue())

    def test_free_cli_version_does_not_load_analysis_dependencies(self):
        original = pseudoforge_free_cli._load_deps
        called = False

        def fail_if_called():
            nonlocal called
            called = True
            raise RuntimeError("analysis deps loaded")

        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            pseudoforge_free_cli._load_deps = fail_if_called
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    pseudoforge_free_cli.main(["--version"])
        finally:
            pseudoforge_free_cli._load_deps = original

        self.assertEqual(raised.exception.code, 0)
        self.assertFalse(called)
        self.assertIn(VERSION, stdout.getvalue())
        self.assertEqual("", stderr.getvalue())

    def test_free_cli_static_provider_choices_match_registry(self):
        self.assertEqual(PROVIDER_OPENAI_COMPATIBLE, pseudoforge_free_cli._PROVIDER_OPENAI_COMPATIBLE)
        self.assertEqual(list(PROVIDER_ORDER), pseudoforge_free_cli._PROVIDER_ORDER)

    def test_free_console_status_and_artifact_order_are_stable(self):
        self.assertEqual("complete", pseudoforge_free_console.payload_status({"results": [{}], "failures": []}))
        self.assertEqual("partial", pseudoforge_free_console.payload_status({"results": [{}], "failures": [{}]}))
        self.assertEqual("failed", pseudoforge_free_console.payload_status({"results": [], "failures": [{}]}))
        ordered = pseudoforge_free_console.ordered_artifacts(
            {
                "warnings": "warnings.json",
                "cleaned_pseudocode": "cleaned.cpp",
                "extra": "extra.txt",
                "rename_map": "rename-map.json",
            }
        )
        self.assertEqual(
            [
                ("cleaned_pseudocode", "cleaned.cpp"),
                ("rename_map", "rename-map.json"),
                ("warnings", "warnings.json"),
                ("extra", "extra.txt"),
            ],
            ordered,
        )

    def test_free_cli_fails_closed_if_ida_module_is_loaded(self):
        original = sys_modules_get("idaapi")
        try:
            pseudoforge_free_cli.sys.modules["idaapi"] = types.ModuleType("idaapi")
            result = _run_free_cli(["missing.cpp", "--format", "json"])

            self.assertEqual(result.exit_code, 1)
            self.assertIn("IDA-only modules", result.stderr)
        finally:
            if original is None:
                pseudoforge_free_cli.sys.modules.pop("idaapi", None)
            else:
                pseudoforge_free_cli.sys.modules["idaapi"] = original

    def test_normalize_copied_pseudocode_accepts_single_function(self):
        normalized = normalize_copied_pseudocode(SAMPLE)

        self.assertTrue(normalized.startswith("__int64 __fastcall free_sample"))
        self.assertTrue(normalized.endswith("}\n"))

    def test_normalize_copied_pseudocode_trims_leading_and_trailing_text(self):
        copied = "IDA Free cloud output\n\n%s\nCopy finished\n" % SAMPLE

        normalized = normalize_copied_pseudocode(copied)

        self.assertTrue(normalized.startswith("__int64 __fastcall free_sample"))
        self.assertNotIn("IDA Free cloud output", normalized)
        self.assertNotIn("Copy finished", normalized)

    def test_normalize_copied_pseudocode_rejects_missing_function(self):
        with self.assertRaisesRegex(OfflinePseudocodeError, "No function-like pseudocode"):
            normalize_copied_pseudocode("IDA Free copied text without a function body")

    def test_normalize_copied_pseudocode_rejects_multiple_functions(self):
        with self.assertRaisesRegex(OfflinePseudocodeError, "Multiple function-like pseudocode"):
            normalize_copied_pseudocode("%s\n%s" % (SAMPLE, SAMPLE.replace("free_sample", "free_sample2")))

    def test_free_cli_writes_ida_free_artifacts_without_ida_modules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "copied.cpp"
            output_dir = temp_path / "out"
            input_path.write_text("Copied from IDA Free\n\n%s\nEnd copy\n" % SAMPLE, encoding="utf-8")

            result = _run_free_cli([str(input_path), "--out", str(output_dir), "--format", "json"])

            self.assertEqual(result.exit_code, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(VERSION, payload["pseudoforge_version"])
            self.assertFalse(payload["ida_apis_used"])
            self.assertFalse(payload["idb_modified"])
            self.assertFalse(payload["interactive_plugin_supported"])
            self.assertIn("Build clean plan", result.stderr)
            self.assertIn("profile_manifests", payload["results"][0])
            self.assertIsInstance(payload["results"][0]["profile_manifests"], list)
            artifacts = payload["results"][0]["artifacts"]
            for key in (
                "cleaned_pseudocode",
                "rename_map",
                "rule_report",
                "warnings",
                "raw_pseudocode",
                "raw_vs_cleaned_diff",
                "summary",
            ):
                self.assertIn(key, artifacts)
                self.assertTrue(Path(artifacts[key]).exists(), key)
            self.assertEqual("free_sample.ida-free-summary.json", Path(artifacts["summary"]).name)
            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            self.assertIn("profile_manifests", summary)
            self.assertIsInstance(summary["profile_manifests"], list)
            self.assertFalse((output_dir / "free_sample.summary.json").exists())
            self.assertFalse(pseudoforge_free_cli.loaded_ida_modules())

    def test_free_cli_text_mode_prints_progress_and_pretty_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "copied.cpp"
            output_dir = temp_path / "out"
            input_path.write_text(SAMPLE, encoding="utf-8")

            result = _run_free_cli([str(input_path), "--out", str(output_dir)])

            self.assertEqual(result.exit_code, 0, result.stderr)
            self.assertIn("PseudoForge IDA Free CLI", result.stdout)
            self.assertIn("Build clean plan", result.stdout)
            self.assertIn("PseudoForge IDA Free offline export complete", result.stdout)
            self.assertIn("Artifacts", result.stdout)
            self.assertIn("cleaned_pseudocode:", result.stdout)

    def test_free_cli_no_progress_suppresses_incremental_messages(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "copied.cpp"
            output_dir = temp_path / "out"
            input_path.write_text(SAMPLE, encoding="utf-8")

            result = _run_free_cli([str(input_path), "--out", str(output_dir), "--no-progress"])

            self.assertEqual(result.exit_code, 0, result.stderr)
            self.assertNotIn("Build clean plan", result.stdout)
            self.assertIn("PseudoForge IDA Free offline export complete", result.stdout)

    def test_free_cli_json_no_progress_keeps_stderr_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "copied.cpp"
            output_dir = temp_path / "out"
            input_path.write_text(SAMPLE, encoding="utf-8")

            result = _run_free_cli([str(input_path), "--out", str(output_dir), "--format", "json", "--no-progress"])

            self.assertEqual(result.exit_code, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["mode"], "ida_free_offline")
            self.assertEqual("", result.stderr)

    def test_free_cli_text_failure_summary_is_not_marked_complete(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "missing.cpp"

            result = _run_free_cli([str(missing_path), "--out", str(Path(temp_dir) / "out")])

            self.assertEqual(result.exit_code, 1)
            self.assertIn("PseudoForge IDA Free offline export failed", result.stdout)
            self.assertIn("Status: failed", result.stdout)
            self.assertIn("Input file could not be read", result.stderr)

    def test_free_cli_text_partial_summary_reports_partial_status(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "copied.cpp"
            missing_path = temp_path / "missing.cpp"
            output_dir = temp_path / "out"
            input_path.write_text(SAMPLE, encoding="utf-8")

            result = _run_free_cli([str(input_path), str(missing_path), "--out", str(output_dir), "--no-progress"])

            self.assertEqual(result.exit_code, 1)
            self.assertIn("PseudoForge IDA Free offline export completed with failures", result.stdout)
            self.assertIn("Status: partial", result.stdout)
            self.assertIn("Results: 1", result.stdout)
            self.assertIn("Failures: 1", result.stdout)
            self.assertIn("Input file could not be read", result.stderr)

    def test_free_cli_project_root_rules_are_honored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "copied.cpp"
            output_dir = temp_path / "out"
            project_root = temp_path / "project"
            rules_dir = project_root / "pseudoforge_rules"
            rules_dir.mkdir(parents=True)
            input_path.write_text(SAMPLE, encoding="utf-8")
            (rules_dir / "rename.json").write_text(json.dumps(_project_rename_rule()), encoding="utf-8")

            result = _run_free_cli(
                [
                    str(input_path),
                    "--out",
                    str(output_dir),
                    "--project-root",
                    str(project_root),
                    "--format",
                    "json",
                ]
            )

            self.assertEqual(result.exit_code, 0, result.stderr)
            payload = json.loads(result.stdout)
            rename_map_path = Path(payload["results"][0]["artifacts"]["rename_map"])
            plan = json.loads(rename_map_path.read_text(encoding="utf-8"))
            accepted = {item["old"]: item["new"] for item in plan["renames"] if item["apply"]}
            self.assertEqual(accepted["v1"], "projectInput")
            self.assertFalse(payload["results"][0]["rule_load_errors"])
            rule_report = json.loads(Path(payload["results"][0]["artifacts"]["rule_report"]).read_text(encoding="utf-8"))
            self.assertTrue(any(item["rule_id"] == "project.free.rename" for item in rule_report["matched_rules"]))

    def test_free_cli_invalid_rule_pack_is_reported_without_crashing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "copied.cpp"
            output_dir = temp_path / "out"
            rules_dir = temp_path / "rules"
            rules_dir.mkdir()
            input_path.write_text(SAMPLE, encoding="utf-8")
            (rules_dir / "broken.json").write_text("{not json", encoding="utf-8")

            result = _run_free_cli(
                [str(input_path), "--out", str(output_dir), "--rules", str(rules_dir), "--format", "json"]
            )

            self.assertEqual(result.exit_code, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["results"][0]["rule_load_errors"])

    def test_free_cli_llm_provider_failure_uses_deterministic_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "copied.cpp"
            output_dir = temp_path / "out"
            failing_provider = temp_path / "failing_provider.py"
            input_path.write_text(SAMPLE, encoding="utf-8")
            failing_provider.write_text(
                "import sys\nsys.stderr.write('provider failed')\nsys.exit(2)\n",
                encoding="utf-8",
            )

            result = _run_free_cli(
                [
                    str(input_path),
                    "--out",
                    str(output_dir),
                    "--llm",
                    "--llm-provider",
                    "codex_cli",
                    "--llm-command",
                    "python %s --output {output_file}" % failing_provider,
                    "--format",
                    "json",
                ]
            )

            self.assertEqual(result.exit_code, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["results"][0]["llm_status"], "failed_fallback")
            self.assertIn("LLM rename assist failed", payload["results"][0]["warnings"][0])

    def test_free_cli_reports_invalid_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "invalid.txt"
            input_path.write_text("No function here", encoding="utf-8")

            result = _run_free_cli([str(input_path), "--out", str(Path(temp_dir) / "out"), "--format", "json"])

            self.assertEqual(result.exit_code, 1)
            payload = json.loads(result.stdout)
            self.assertIn("No function-like pseudocode", payload["failures"][0]["error"])

    def test_free_cli_reports_missing_input_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "missing.cpp"

            result = _run_free_cli([str(missing_path), "--out", str(Path(temp_dir) / "out"), "--format", "json"])

            self.assertEqual(result.exit_code, 1)
            payload = json.loads(result.stdout)
            self.assertIn("Input file could not be read", payload["failures"][0]["error"])

    def test_free_cli_reports_output_directory_write_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "copied.cpp"
            output_file = temp_path / "not_a_directory"
            input_path.write_text(SAMPLE, encoding="utf-8")
            output_file.write_text("occupied", encoding="utf-8")

            result = _run_free_cli([str(input_path), "--out", str(output_file), "--format", "json"])

            self.assertEqual(result.exit_code, 1)
            self.assertIn("Output directory could not be written", result.stderr)

    def test_existing_cli_remains_compatible(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "sample.cpp"
            output_dir = temp_path / "existing"
            input_path.write_text(SAMPLE, encoding="utf-8")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = pseudoforge_cli.main([str(input_path), "--out", str(output_dir)])

            self.assertEqual(exit_code, 0)
            self.assertIn("PseudoForge export complete", stdout.getvalue())
            self.assertIn("Version: %s" % VERSION, stdout.getvalue())
            self.assertTrue(any(output_dir.glob("*.cleaned.cpp")))

    def test_existing_cli_reports_version(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                pseudoforge_cli.main(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn(VERSION, stdout.getvalue())
        self.assertEqual("", stderr.getvalue())


class _CliResult:
    def __init__(self, exit_code: int, stdout: str, stderr: str):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


def _run_free_cli(argv: list[str]) -> _CliResult:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exit_code = pseudoforge_free_cli.main(argv)
    return _CliResult(exit_code, stdout.getvalue(), stderr.getvalue())


def sys_modules_get(name: str):
    return pseudoforge_free_cli.sys.modules.get(name)


def _project_rename_rule() -> dict:
    return {
        "schema_version": 1,
        "id": "project.free.rules",
        "description": "Project local rule used by IDA Free CLI tests.",
        "rules": [
            {
                "id": "project.free.rename",
                "phase": "rename",
                "priority": 100,
                "confidence": 0.95,
                "scope": {"lvars_any": "v1"},
                "match": {"assignment_regex": r"(?P<dst>v1)\s*=\s*a1;"},
                "emit": {
                    "kind": "rename",
                    "rename_kind": "lvar",
                    "target": "$dst",
                    "new_name": "projectInput",
                },
                "enabled": True,
                "override_of": "",
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()

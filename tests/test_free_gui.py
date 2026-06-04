import os
import subprocess
import sys
import unittest
from dataclasses import dataclass

from ida_pseudoforge.config import LlmConfig, PseudoForgeConfig
from ida_pseudoforge.gui import free_app


@dataclass
class _Rename:
    old: str
    new: str
    source: str
    confidence: float
    apply: bool


class _Plan:
    def __init__(self) -> None:
        self.renames = [
            _Rename("v1", "inputValue", "rule", 0.95, True),
            _Rename("v2", "weakName", "llm", 0.50, False),
        ]
        self.rule_report = {"matched_rules": [{"rule_id": "test.rule"}]}


class FreeStudioGuiTests(unittest.TestCase):
    def test_missing_qt_message_is_actionable(self) -> None:
        self.assertIn("PySide6", free_app.missing_qt_message())
        self.assertIn("pip install PySide6", free_app.missing_qt_message())

    def test_format_helpers_are_ui_independent(self) -> None:
        plan = _Plan()

        self.assertIn("No warnings", free_app.format_warnings([]))
        self.assertIn("warning", free_app.format_warnings(["warning"]))
        self.assertIn("v1 -> inputValue", free_app.format_renames(plan))
        self.assertIn("Skipped renames: 1", free_app.format_renames(plan))
        self.assertIn("test.rule", free_app.format_rule_report(plan))
        self.assertLess(
            free_app.format_artifacts({"summary": "s.json", "cleaned_pseudocode": "c.cpp"}).find(
                "cleaned_pseudocode"
            ),
            free_app.format_artifacts({"summary": "s.json", "cleaned_pseudocode": "c.cpp"}).find("summary"),
        )

    def test_options_from_config_parses_runtime_settings(self) -> None:
        config = PseudoForgeConfig(
            llm=LlmConfig(
                enabled=True,
                provider="codex_cli",
                model="gpt-test",
                timeout_seconds=120,
                command_template="codex test",
            ),
            profile_dir=r"C:\profiles",
        )

        options = free_app.options_from_config(
            config,
            api_key="secret",
            project_root=r"F:\project",
            rule_dirs_text=r"C:\rules1;C:\rules2",
            buffer_case_text="0x10; 32u",
            buffer_contract_helper_depth=3,
        )

        self.assertTrue(options.llm_enabled)
        self.assertEqual("codex_cli", options.llm_provider)
        self.assertEqual("secret", options.llm_api_key)
        self.assertEqual([r"C:\rules1", r"C:\rules2"], options.rule_dirs)
        self.assertEqual([0x10, 32], options.buffer_contract_case_values)
        self.assertEqual(3, options.buffer_contract_helper_depth)

    def test_gui_entrypoint_reports_missing_pyside6_when_unavailable(self) -> None:
        if free_app.qt_available():
            self.skipTest("PySide6 is installed")

        result = subprocess.run(
            [sys.executable, "-B", r".\tools\pseudoforge_free_gui.py"],
            cwd=os.getcwd(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )

        self.assertEqual(1, result.returncode)
        self.assertIn("PySide6 is required", result.stderr)

    @unittest.skipUnless(free_app.qt_available(), "PySide6 is not installed")
    def test_window_can_be_constructed_when_qt_is_available(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = free_app.QtWidgets.QApplication.instance()
        if app is None:
            app = free_app.QtWidgets.QApplication([])
        window = free_app.FreeStudioWindow()

        self.assertIn("Free Studio", window.windowTitle())
        window.close()


if __name__ == "__main__":
    unittest.main()

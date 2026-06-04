import os
import subprocess
import sys
import time
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
    def _wait_for_qt(self, app, predicate, timeout_seconds: float = 3.0) -> None:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            app.processEvents()
            if predicate():
                return
            time.sleep(0.01)
        self.fail("Timed out waiting for Qt condition")

    def test_missing_qt_message_is_actionable(self) -> None:
        message = free_app.missing_qt_message()

        self.assertIn("PySide6", message)
        self.assertIn("Current Python", message)
        self.assertIn(sys.executable, message)
        self.assertIn("-m pip install PySide6", message)

    def test_free_studio_reports_ida_process_boundary(self) -> None:
        old_executable = free_app.sys.executable
        free_app.sys.executable = r"C:\IDA\ida.exe"
        try:
            self.assertTrue(free_app._running_inside_ida_process())
            message = free_app.missing_qt_message()
        finally:
            free_app.sys.executable = old_executable

        self.assertIn("must not be run inside IDA", message)
        self.assertIn("pseudoforge_free_gui.py", message)

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
                provider="openrouter",
                base_url="https://openrouter.ai/api/v1",
                model="openrouter/auto",
                timeout_seconds=120,
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
        self.assertEqual("openrouter", options.llm_provider)
        self.assertEqual("secret", options.llm_api_key)
        self.assertEqual([r"C:\rules1", r"C:\rules2"], options.rule_dirs)
        self.assertEqual([0x10, 32], options.buffer_contract_case_values)
        self.assertEqual(3, options.buffer_contract_helper_depth)

    def test_options_from_config_drops_api_key_for_local_and_cli_providers(self) -> None:
        for provider in ("ollama", "codex_cli"):
            with self.subTest(provider=provider):
                config = PseudoForgeConfig(
                    llm=LlmConfig(
                        enabled=True,
                        provider=provider,
                    )
                )

                options = free_app.options_from_config(config, api_key="stale-secret")

                self.assertEqual(provider, options.llm_provider)
                self.assertEqual("", options.llm_api_key)

    def test_provider_setting_capabilities_are_classified(self) -> None:
        self.assertTrue(free_app.provider_uses_http_settings("openai_compatible"))
        self.assertTrue(free_app.provider_uses_http_settings("openrouter"))
        self.assertTrue(free_app.provider_uses_http_settings("deepseek_api"))
        self.assertTrue(free_app.provider_uses_http_settings("ollama"))
        self.assertTrue(free_app.provider_uses_http_settings("lm_studio"))
        self.assertTrue(free_app.provider_uses_http_settings("vllm"))
        self.assertTrue(free_app.provider_uses_http_settings("llama_cpp"))
        self.assertFalse(free_app.provider_uses_http_settings("codex_cli"))
        self.assertFalse(free_app.provider_uses_http_settings("claude_cli"))
        self.assertTrue(free_app.provider_uses_api_key_settings("openai_compatible"))
        self.assertTrue(free_app.provider_uses_api_key_settings("openrouter"))
        self.assertTrue(free_app.provider_uses_api_key_settings("deepseek_api"))
        self.assertFalse(free_app.provider_uses_api_key_settings("ollama"))
        self.assertFalse(free_app.provider_uses_api_key_settings("lm_studio"))
        self.assertFalse(free_app.provider_uses_api_key_settings("vllm"))
        self.assertFalse(free_app.provider_uses_api_key_settings("llama_cpp"))
        self.assertTrue(free_app.provider_uses_cli_settings("codex_cli"))
        self.assertTrue(free_app.provider_uses_cli_settings("claude_cli"))
        self.assertFalse(free_app.provider_uses_cli_settings("openai_compatible"))
        self.assertFalse(free_app.provider_uses_cli_settings("ollama"))

    def test_model_discovery_timeout_respects_settings_with_bounded_range(self) -> None:
        self.assertEqual(5, free_app.model_discovery_timeout_seconds(1))
        self.assertEqual(60, free_app.model_discovery_timeout_seconds(60))
        self.assertEqual(60, free_app.model_discovery_timeout_seconds(600))

    def test_c_like_highlight_spans_mark_pseudocode_roles(self) -> None:
        line = "NTSTATUS status = STATUS_SUCCESS; return ExAllocatePool2(POOL_FLAG_PAGED, 0x28uLL, 'A'); // ok"

        roles = {role for _start, _length, role in free_app.c_like_highlight_spans(line)}

        self.assertIn("type", roles)
        self.assertIn("constant", roles)
        self.assertIn("keyword", roles)
        self.assertIn("function", roles)
        self.assertIn("number", roles)
        self.assertIn("char", roles)
        self.assertIn("comment", roles)

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
    def test_settings_dialog_disables_irrelevant_provider_fields(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = free_app.QtWidgets.QApplication.instance()
        if app is None:
            app = free_app.QtWidgets.QApplication([])
        config = PseudoForgeConfig(
            llm=LlmConfig(
                enabled=True,
                provider="codex_cli",
                base_url="https://stale.example/v1",
                model="gpt-5.5",
                command_template="codex exec -m {model} --output-last-message {output_file} -",
            )
        )
        free_app.set_provider_api_key(config, "codex_cli", "stale-key")
        dialog = free_app.LlmSettingsDialog(config, "stale-key", "", "", "", 2)

        self.assertFalse(dialog.base_url_edit.isEnabled())
        self.assertFalse(dialog.api_key_edit.isEnabled())
        self.assertTrue(dialog.command_edit.isEnabled())

        updated_config, api_key, *_ = dialog.updated_config()
        self.assertEqual("", api_key)
        self.assertEqual("", updated_config.llm.base_url)
        self.assertNotIn("codex_cli", updated_config.credentials)
        self.assertTrue(updated_config.llm.command_template)
        dialog.close()

    @unittest.skipUnless(free_app.qt_available(), "PySide6 is not installed")
    def test_settings_dialog_enables_http_provider_fields(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = free_app.QtWidgets.QApplication.instance()
        if app is None:
            app = free_app.QtWidgets.QApplication([])
        config = PseudoForgeConfig(
            llm=LlmConfig(
                enabled=True,
                provider="deepseek_api",
                base_url="https://api.deepseek.com",
                model="deepseek-v4-flash",
                command_template="stale cli command",
            )
        )
        free_app.set_provider_api_key(config, "deepseek_api", "deepseek-key")
        dialog = free_app.LlmSettingsDialog(config, "deepseek-key", "", "", "", 2)

        self.assertTrue(dialog.base_url_edit.isEnabled())
        self.assertTrue(dialog.api_key_edit.isEnabled())
        self.assertFalse(dialog.command_edit.isEnabled())

        updated_config, api_key, *_ = dialog.updated_config()
        self.assertEqual("deepseek-key", api_key)
        self.assertEqual("https://api.deepseek.com", updated_config.llm.base_url)
        self.assertEqual("", updated_config.llm.command_template)
        dialog.close()

    @unittest.skipUnless(free_app.qt_available(), "PySide6 is not installed")
    def test_settings_dialog_disables_local_http_api_key_field(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = free_app.QtWidgets.QApplication.instance()
        if app is None:
            app = free_app.QtWidgets.QApplication([])
        config = PseudoForgeConfig(
            llm=LlmConfig(
                enabled=True,
                provider="ollama",
                base_url="http://localhost:11434/v1",
                model="llama3.2",
                command_template="stale cli command",
            )
        )
        free_app.set_provider_api_key(config, "ollama", "stale-key")
        dialog = free_app.LlmSettingsDialog(config, "stale-key", "", "", "", 2)

        self.assertTrue(dialog.base_url_edit.isEnabled())
        self.assertFalse(dialog.api_key_edit.isEnabled())
        self.assertFalse(dialog.command_edit.isEnabled())

        updated_config, api_key, *_ = dialog.updated_config()
        self.assertEqual("", api_key)
        self.assertEqual("http://localhost:11434/v1", updated_config.llm.base_url)
        self.assertEqual("", updated_config.llm.command_template)
        self.assertNotIn("ollama", updated_config.credentials)
        dialog.close()

    @unittest.skipUnless(free_app.qt_available(), "PySide6 is not installed")
    def test_settings_dialog_auto_loads_local_http_models_after_base_url_change(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = free_app.QtWidgets.QApplication.instance()
        if app is None:
            app = free_app.QtWidgets.QApplication([])
        providers = (
            ("lm_studio", "http://127.0.0.1:1234/v1"),
            ("ollama", "http://127.0.0.1:11434/v1"),
            ("vllm", "http://127.0.0.1:8000/v1"),
            ("llama_cpp", "http://127.0.0.1:8080/v1"),
        )
        old_discover = free_app.discover_provider_models
        calls = []

        def fake_discover(provider, base_url="", api_key="", timeout_seconds=15):
            calls.append((provider, base_url, api_key, timeout_seconds))
            return free_app.ModelDiscoveryResult(
                models=["%s-live-model" % provider],
                source="%s/models" % base_url,
            )

        free_app.discover_provider_models = fake_discover
        try:
            for index, (provider, default_url) in enumerate(providers):
                with self.subTest(provider=provider):
                    custom_url = "http://127.0.0.1:%d/v1" % (19000 + index)
                    config = PseudoForgeConfig(
                        llm=LlmConfig(
                            enabled=True,
                            provider=provider,
                            base_url=default_url,
                            model="previous-model",
                        )
                    )
                    dialog = free_app.LlmSettingsDialog(config, "", "", "", "", 2)
                    try:
                        dialog.base_url_edit.setText(custom_url)
                        self._wait_for_qt(
                            app,
                            lambda provider=provider, custom_url=custom_url, dialog=dialog: (
                                any(
                                    call_provider == provider and call_base_url == custom_url
                                    for call_provider, call_base_url, _api_key, _timeout in calls
                                )
                                and dialog.model_combo.findText("%s-live-model" % provider) >= 0
                            ),
                        )
                        self.assertEqual("", dialog.api_key_edit.text())
                        self.assertFalse(dialog.api_key_edit.isEnabled())
                        self.assertIn((provider, custom_url, "", 60), calls)
                    finally:
                        dialog.close()
                        self._wait_for_qt(app, lambda dialog=dialog: not dialog._model_discovery_threads)
        finally:
            free_app.discover_provider_models = old_discover

    @unittest.skipUnless(free_app.qt_available(), "PySide6 is not installed")
    def test_settings_dialog_shows_model_discovery_fallback_status(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = free_app.QtWidgets.QApplication.instance()
        if app is None:
            app = free_app.QtWidgets.QApplication([])
        old_discover = free_app.discover_provider_models

        def fake_discover(provider, base_url="", api_key="", timeout_seconds=15):
            return free_app.ModelDiscoveryResult(
                models=["local-model"],
                source="static fallback",
                warning="static fallback: model catalog request failed: timed out",
            )

        free_app.discover_provider_models = fake_discover
        try:
            config = PseudoForgeConfig(
                llm=LlmConfig(
                    enabled=True,
                    provider="lm_studio",
                    base_url="http://192.168.1.28:1234/v1",
                    model="local-model",
                )
            )
            dialog = free_app.LlmSettingsDialog(config, "", "", "", "", 2)
            try:
                dialog._refresh_models_now()
                self._wait_for_qt(
                    app,
                    lambda dialog=dialog: "Fallback:" in dialog.model_status_label.text(),
                )
                self.assertIn("timed out", dialog.model_status_label.toolTip())
                self.assertTrue(dialog.refresh_models_button.isEnabled())
            finally:
                dialog.close()
                self._wait_for_qt(app, lambda dialog=dialog: not dialog._model_discovery_threads)
        finally:
            free_app.discover_provider_models = old_discover

    @unittest.skipUnless(free_app.qt_available(), "PySide6 is not installed")
    def test_window_can_be_constructed_when_qt_is_available(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = free_app.QtWidgets.QApplication.instance()
        if app is None:
            app = free_app.QtWidgets.QApplication([])
        window = free_app.FreeStudioWindow()

        self.assertIn("Free Studio", window.windowTitle())
        window.close()

    @unittest.skipUnless(free_app.qt_available(), "PySide6 is not installed")
    def test_window_attaches_syntax_highlighters_to_code_editors(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = free_app.QtWidgets.QApplication.instance()
        if app is None:
            app = free_app.QtWidgets.QApplication([])
        window = free_app.FreeStudioWindow()

        self.assertGreaterEqual(len(window._syntax_highlighters), 2)
        self.assertIsNotNone(window.raw_edit.document())
        self.assertIsNotNone(window.cleaned_edit.document())
        window.close()


if __name__ == "__main__":
    unittest.main()

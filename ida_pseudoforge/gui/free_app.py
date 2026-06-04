from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ida_pseudoforge.config import (
    LlmConfig,
    PseudoForgeConfig,
    get_provider_api_key,
    load_config,
    save_config,
    set_provider_api_key,
)
from ida_pseudoforge.free.service import (
    FreeAnalysisOptions,
    FreeAnalysisProgress,
    FreeAnalysisResult,
    analyze_text,
    default_session_output_dir,
    load_free_analysis_deps,
    parse_case_value,
    save_result_bundle,
)
from ida_pseudoforge.core.syntax_highlight import C_LIKE_HIGHLIGHT_PALETTE, c_like_highlight_spans
from ida_pseudoforge.models.model_discovery import ModelDiscoveryResult, discover_provider_models
from ida_pseudoforge.models.provider_registry import (
    PROVIDER_ORDER,
    normalize_provider,
    provider_defaults,
    provider_label,
    provider_model_options,
    provider_requires_api_key,
    provider_uses_cli_settings as registry_provider_uses_cli_settings,
    provider_uses_http_settings as registry_provider_uses_http_settings,
)
from ida_pseudoforge.version import plugin_title


def _running_inside_ida_process() -> bool:
    executable = Path(str(sys.executable or "")).name.lower()
    return executable in {"ida.exe", "ida64.exe", "idat.exe", "idat64.exe"}


if _running_inside_ida_process():
    QtCore = None
    QtGui = None
    QtWidgets = None
else:
    try:
        from PySide6 import QtCore, QtGui, QtWidgets
    except ImportError:
        QtCore = None
        QtGui = None
        QtWidgets = None


ARTIFACT_ORDER = (
    "cleaned_pseudocode",
    "switch_outline",
    "rename_map",
    "flow_report",
    "buffer_contract_report",
    "buffer_contracts",
    "buffer_structs",
    "rule_report",
    "raw_pseudocode",
    "raw_vs_cleaned_diff",
    "warnings",
    "summary",
)


def qt_available() -> bool:
    return QtWidgets is not None


def missing_qt_message() -> str:
    if _running_inside_ida_process():
        return (
            "PseudoForge Free Studio is a standalone PySide6 app and must not be run inside IDA. "
            "Launch it from an external Python process with: python -B .\\tools\\pseudoforge_free_gui.py"
        )
    return (
        "PySide6 is required for PseudoForge Free Studio. "
        "Current Python: %s. "
        "Install it into this interpreter with: \"%s\" -m pip install PySide6. "
        "If PySide6 is already installed in another Python, run Free Studio with that Python."
        % (sys.executable, sys.executable)
    )


def format_warnings(warnings: list[str]) -> str:
    if not warnings:
        return "No warnings."
    return "\n".join("- %s" % str(item) for item in warnings)


def format_renames(plan: Any) -> str:
    renames = list(getattr(plan, "renames", []) or [])
    accepted = [item for item in renames if getattr(item, "apply", False)]
    skipped = [item for item in renames if not getattr(item, "apply", False)]
    lines = ["Accepted renames: %d" % len(accepted)]
    for item in accepted:
        lines.append(
            "%s -> %s  source=%s confidence=%.2f"
            % (
                getattr(item, "old", ""),
                getattr(item, "new", ""),
                getattr(item, "source", ""),
                float(getattr(item, "confidence", 0.0) or 0.0),
            )
        )
    lines.append("")
    lines.append("Skipped renames: %d" % len(skipped))
    for item in skipped:
        lines.append(
            "%s -> %s  source=%s confidence=%.2f"
            % (
                getattr(item, "old", ""),
                getattr(item, "new", ""),
                getattr(item, "source", ""),
                float(getattr(item, "confidence", 0.0) or 0.0),
            )
        )
    return "\n".join(lines).rstrip()


def format_rule_report(plan: Any) -> str:
    return json.dumps(getattr(plan, "rule_report", {}) or {}, indent=2, ensure_ascii=True)


def format_artifacts(artifacts: dict[str, str]) -> str:
    if not artifacts:
        return "No artifacts."
    lines = []
    seen = set()
    for key in ARTIFACT_ORDER:
        if key in artifacts:
            lines.append("%s: %s" % (key, artifacts[key]))
            seen.add(key)
    for key in sorted(key for key in artifacts if key not in seen):
        lines.append("%s: %s" % (key, artifacts[key]))
    return "\n".join(lines)


def provider_uses_http_settings(provider: object) -> bool:
    return registry_provider_uses_http_settings(provider)


def provider_uses_api_key_settings(provider: object) -> bool:
    return provider_requires_api_key(provider)


def provider_uses_cli_settings(provider: object) -> bool:
    return registry_provider_uses_cli_settings(provider)


def model_discovery_timeout_seconds(timeout_seconds: int) -> int:
    return min(max(int(timeout_seconds), 5), 60)


def options_from_config(
    config: PseudoForgeConfig,
    api_key: str = "",
    project_root: str = "",
    rule_dirs_text: str = "",
    buffer_case_text: str = "",
    buffer_contract_helper_depth: int = 2,
) -> FreeAnalysisOptions:
    case_values = []
    for item in _split_setting_list(buffer_case_text):
        case_values.append(parse_case_value(item))
    return FreeAnalysisOptions(
        profile_dir=config.profile_dir,
        project_root=project_root,
        rule_dirs=_split_setting_list(rule_dirs_text),
        llm_enabled=bool(config.llm.enabled),
        llm_provider=config.llm.provider,
        llm_api_key=api_key if provider_uses_api_key_settings(config.llm.provider) else "",
        llm_base_url=config.llm.base_url,
        llm_model=config.llm.model,
        llm_command=config.llm.command_template,
        llm_timeout=config.llm.timeout_seconds,
        buffer_contract_case_values=case_values,
        buffer_contract_helper_depth=buffer_contract_helper_depth,
    )


def _split_setting_list(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").replace("\n", ";").split(";") if item.strip()]


if QtWidgets is not None:

    class AnalysisWorker(QtCore.QObject):
        progress = QtCore.Signal(object)
        completed = QtCore.Signal(object)
        failed = QtCore.Signal(str)
        cancelled = QtCore.Signal(str)

        def __init__(
            self,
            source_text: str,
            input_label: str,
            output_dir: Path,
            options: FreeAnalysisOptions,
        ) -> None:
            super().__init__()
            self._source_text = source_text
            self._input_label = input_label
            self._output_dir = output_dir
            self._options = options
            self._cancel_requested = False

        @QtCore.Slot()
        def run(self) -> None:
            try:
                deps = load_free_analysis_deps()
                result = analyze_text(
                    source_text=self._source_text,
                    output_dir=self._output_dir,
                    input_label=self._input_label,
                    source_path=self._input_label,
                    options=self._options,
                    deps=deps,
                    progress=self.progress.emit,
                    cancel_check=self._is_cancelled,
                )
                self.completed.emit(result)
            except Exception as exc:
                if self._cancel_requested:
                    self.cancelled.emit(str(exc))
                else:
                    self.failed.emit(str(exc))

        def cancel(self) -> None:
            self._cancel_requested = True

        def _is_cancelled(self) -> bool:
            return self._cancel_requested


    class ModelDiscoveryWorker(QtCore.QObject):
        completed = QtCore.Signal(int, str, str, object)

        def __init__(
            self,
            generation: int,
            provider: str,
            base_url: str,
            api_key: str,
            timeout_seconds: int,
        ) -> None:
            super().__init__()
            self._generation = generation
            self._provider = normalize_provider(provider)
            self._base_url = str(base_url or "").rstrip("/")
            self._api_key = api_key
            self._timeout_seconds = timeout_seconds

        @QtCore.Slot()
        def run(self) -> None:
            try:
                result = discover_provider_models(
                    self._provider,
                    base_url=self._base_url,
                    api_key=self._api_key,
                    timeout_seconds=self._timeout_seconds,
                )
            except Exception as exc:
                result = ModelDiscoveryResult(
                    models=list(provider_model_options(self._provider)),
                    source="static fallback",
                    warning="model discovery failed: %s" % exc,
                )
            self.completed.emit(self._generation, self._provider, self._base_url, result)


    class LlmSettingsDialog(QtWidgets.QDialog):
        def __init__(
            self,
            config: PseudoForgeConfig,
            api_key: str,
            project_root: str,
            rule_dirs_text: str,
            buffer_case_text: str,
            helper_depth: int,
            parent: QtWidgets.QWidget | None = None,
        ) -> None:
            super().__init__(parent)
            self.setWindowTitle("PseudoForge Free Studio Settings")
            self._config = config
            self._suppress_model_discovery = False
            self._model_discovery_generation = 0
            self._model_discovery_threads: list[tuple[QtCore.QThread, ModelDiscoveryWorker]] = []
            self._build_ui(api_key, project_root, rule_dirs_text, buffer_case_text, helper_depth)
            self._load_config_values()

        def updated_config(self) -> tuple[PseudoForgeConfig, str, str, str, str, int]:
            provider = normalize_provider(self.provider_combo.currentData())
            defaults = provider_defaults(provider)
            uses_http = provider_uses_http_settings(provider)
            uses_api_key = provider_uses_api_key_settings(provider)
            uses_cli = provider_uses_cli_settings(provider)
            config = self._config
            config.llm = LlmConfig(
                enabled=self.enable_llm_check.isChecked(),
                provider=provider,
                base_url=(self.base_url_edit.text().strip() or defaults.base_url) if uses_http else "",
                model=self.model_combo.currentText().strip() or defaults.model,
                timeout_seconds=self.timeout_spin.value(),
                command_template=(self.command_edit.text().strip() or defaults.command_template) if uses_cli else "",
            )
            config.profile_dir = self.profile_dir_edit.text().strip()
            api_key = self.api_key_edit.text() if uses_api_key else ""
            normalized = normalize_provider(provider)
            if api_key:
                set_provider_api_key(config, normalized, api_key)
            else:
                config.credentials.pop(normalized, None)
            return (
                config,
                api_key,
                self.project_root_edit.text().strip(),
                self.rules_edit.toPlainText().strip(),
                self.buffer_case_edit.text().strip(),
                self.helper_depth_spin.value(),
            )

        def _build_ui(
            self,
            api_key: str,
            project_root: str,
            rule_dirs_text: str,
            buffer_case_text: str,
            helper_depth: int,
        ) -> None:
            layout = QtWidgets.QFormLayout(self)
            self.enable_llm_check = QtWidgets.QCheckBox("Enable LLM rename assist")
            self.provider_combo = QtWidgets.QComboBox()
            for provider in PROVIDER_ORDER:
                self.provider_combo.addItem(provider_label(provider), provider)
            self.model_combo = QtWidgets.QComboBox()
            self.model_combo.setEditable(True)
            self.refresh_models_button = QtWidgets.QPushButton("Refresh")
            self.model_status_label = QtWidgets.QLabel("")
            self.model_status_label.setWordWrap(True)
            self.base_url_edit = QtWidgets.QLineEdit()
            self.api_key_edit = QtWidgets.QLineEdit(api_key)
            self.api_key_edit.setEchoMode(QtWidgets.QLineEdit.Password)
            self.command_edit = QtWidgets.QLineEdit()
            self.timeout_spin = QtWidgets.QSpinBox()
            self.timeout_spin.setRange(5, 600)
            self.profile_dir_edit = QtWidgets.QLineEdit()
            self.project_root_edit = QtWidgets.QLineEdit(project_root)
            self.rules_edit = QtWidgets.QPlainTextEdit(rule_dirs_text)
            self.rules_edit.setPlaceholderText("Optional rule directories separated by semicolon or newline")
            self.rules_edit.setMaximumHeight(80)
            self.buffer_case_edit = QtWidgets.QLineEdit(buffer_case_text)
            self.buffer_case_edit.setPlaceholderText("Optional case values, for example 0x91234000; 0x91234004")
            self.helper_depth_spin = QtWidgets.QSpinBox()
            self.helper_depth_spin.setRange(0, 8)
            self.helper_depth_spin.setValue(helper_depth)
            self._model_discovery_timer = QtCore.QTimer(self)
            self._model_discovery_timer.setSingleShot(True)
            self._model_discovery_timer.timeout.connect(self._refresh_models_for_current_provider)
            model_row = QtWidgets.QWidget()
            model_row_layout = QtWidgets.QHBoxLayout(model_row)
            model_row_layout.setContentsMargins(0, 0, 0, 0)
            model_row_layout.addWidget(self.model_combo, 1)
            model_row_layout.addWidget(self.refresh_models_button)

            layout.addRow(self.enable_llm_check)
            layout.addRow("Provider", self.provider_combo)
            layout.addRow("Model", model_row)
            layout.addRow("Model catalog", self.model_status_label)
            layout.addRow("Base URL", self.base_url_edit)
            layout.addRow("API key", self.api_key_edit)
            layout.addRow("CLI command", self.command_edit)
            layout.addRow("Timeout seconds", self.timeout_spin)
            layout.addRow("Profile dir", self.profile_dir_edit)
            layout.addRow("Project root", self.project_root_edit)
            layout.addRow("Rules dirs", self.rules_edit)
            layout.addRow("Buffer case filter", self.buffer_case_edit)
            layout.addRow("Helper depth", self.helper_depth_spin)

            buttons = QtWidgets.QDialogButtonBox(_dialog_button("Ok") | _dialog_button("Cancel"))
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            layout.addRow(buttons)
            self.provider_combo.currentIndexChanged.connect(self._provider_changed)
            self.base_url_edit.textChanged.connect(lambda *_: self._schedule_model_discovery())
            self.api_key_edit.textChanged.connect(lambda *_: self._schedule_model_discovery())
            self.refresh_models_button.clicked.connect(self._refresh_models_now)

        def _load_config_values(self) -> None:
            config = self._config
            provider = normalize_provider(config.llm.provider)
            self._suppress_model_discovery = True
            try:
                index = self.provider_combo.findData(provider)
                if index >= 0:
                    self.provider_combo.setCurrentIndex(index)
                self.enable_llm_check.setChecked(config.llm.enabled)
                self.timeout_spin.setValue(config.llm.timeout_seconds)
                self.profile_dir_edit.setText(config.profile_dir)
                self._provider_changed()
                self._set_model_options(provider_model_options(provider), config.llm.model)
                if provider_uses_http_settings(provider):
                    self._set_line_text(self.base_url_edit, config.llm.base_url)
                else:
                    self._set_line_text(self.base_url_edit, "")
                if provider_uses_cli_settings(provider):
                    self._set_line_text(self.command_edit, config.llm.command_template)
                else:
                    self._set_line_text(self.command_edit, "")
                self._sync_provider_fields(provider)
            finally:
                self._suppress_model_discovery = False
            self._schedule_model_discovery(0)

        def _provider_changed(self, *_: Any) -> None:
            provider = normalize_provider(self.provider_combo.currentData())
            defaults = provider_defaults(provider)
            self._set_model_options(provider_model_options(provider), defaults.model)
            self._set_line_text(self.base_url_edit, defaults.base_url)
            self._set_line_text(self.command_edit, defaults.command_template)
            self._set_line_text(self.api_key_edit, get_provider_api_key(self._config, provider))
            self._sync_provider_fields(provider)
            self._schedule_model_discovery(0)

        def _sync_provider_fields(self, provider: str) -> None:
            uses_http = provider_uses_http_settings(provider)
            uses_api_key = provider_uses_api_key_settings(provider)
            uses_cli = provider_uses_cli_settings(provider)
            self.base_url_edit.setEnabled(uses_http)
            self.api_key_edit.setEnabled(uses_api_key)
            self.command_edit.setEnabled(uses_cli)
            self.refresh_models_button.setEnabled(uses_http)
            if not uses_http:
                self._set_line_text(self.base_url_edit, "")
                self._set_model_discovery_status("Static provider model list.")
            if not uses_api_key:
                self._set_line_text(self.api_key_edit, "")
            if not uses_cli:
                self._set_line_text(self.command_edit, "")

        def _set_line_text(self, editor: QtWidgets.QLineEdit, value: str) -> None:
            previous = editor.blockSignals(True)
            try:
                editor.setText(value)
            finally:
                editor.blockSignals(previous)

        def _set_model_options(self, models: object, preferred_model: str = "") -> None:
            options = [str(item) for item in models if str(item)]
            preferred = str(preferred_model or "").strip()
            if preferred and preferred not in options:
                options.insert(0, preferred)
            previous = self.model_combo.blockSignals(True)
            try:
                self.model_combo.clear()
                self.model_combo.addItems(options)
                if preferred:
                    self.model_combo.setCurrentText(preferred)
                elif options:
                    self.model_combo.setCurrentIndex(0)
            finally:
                self.model_combo.blockSignals(previous)

        def _schedule_model_discovery(self, delay_ms: int = 300) -> None:
            if self._suppress_model_discovery:
                return
            provider = normalize_provider(self.provider_combo.currentData())
            if not provider_uses_http_settings(provider):
                self._model_discovery_generation += 1
                self._model_discovery_timer.stop()
                self.model_combo.setToolTip("")
                return
            self._model_discovery_timer.start(max(int(delay_ms), 0))

        def _refresh_models_now(self) -> None:
            self._model_discovery_timer.stop()
            self._refresh_models_for_current_provider()

        def _refresh_models_for_current_provider(self) -> None:
            provider = normalize_provider(self.provider_combo.currentData())
            if not provider_uses_http_settings(provider):
                return
            defaults = provider_defaults(provider)
            base_url = (self.base_url_edit.text().strip() or defaults.base_url).rstrip("/")
            api_key = self.api_key_edit.text() if provider_uses_api_key_settings(provider) else ""
            timeout_seconds = model_discovery_timeout_seconds(self.timeout_spin.value())
            self._model_discovery_generation += 1
            generation = self._model_discovery_generation
            self.refresh_models_button.setEnabled(False)
            self._set_model_discovery_status("Loading from %s/models" % base_url)
            thread = QtCore.QThread()
            worker = ModelDiscoveryWorker(generation, provider, base_url, api_key, timeout_seconds)
            worker.moveToThread(thread)
            self._model_discovery_threads.append((thread, worker))
            thread.started.connect(worker.run)
            worker.completed.connect(self._model_discovery_completed)
            worker.completed.connect(thread.quit)
            worker.completed.connect(worker.deleteLater)
            thread.finished.connect(thread.deleteLater)
            thread.finished.connect(lambda thread=thread: self._model_discovery_thread_finished(thread))
            thread.start()

        def _model_discovery_completed(
            self,
            generation: int,
            provider: str,
            base_url: str,
            result: ModelDiscoveryResult,
        ) -> None:
            if generation != self._model_discovery_generation:
                return
            current_provider = normalize_provider(self.provider_combo.currentData())
            if provider != current_provider:
                return
            defaults = provider_defaults(current_provider)
            current_base_url = (self.base_url_edit.text().strip() or defaults.base_url).rstrip("/")
            if base_url != current_base_url:
                return
            current_model = self.model_combo.currentText().strip() or defaults.model
            self._set_model_options(result.models, current_model)
            self.refresh_models_button.setEnabled(True)
            if result.warning:
                warning = _format_model_discovery_warning(result.warning)
                self._set_model_discovery_status("Fallback: %s" % warning, warning=True)
                self.model_combo.setToolTip("Model discovery fallback: %s" % warning)
            else:
                self._set_model_discovery_status(
                    "Loaded %d model(s) from %s" % (len(result.models), result.source)
                )
                self.model_combo.setToolTip("Models from %s" % result.source)

        def _model_discovery_thread_finished(self, finished_thread: QtCore.QThread) -> None:
            self._model_discovery_threads = [
                (thread, worker)
                for thread, worker in self._model_discovery_threads
                if thread is not finished_thread
            ]

        def _ignore_pending_model_discovery(self) -> None:
            self._model_discovery_generation += 1
            self._model_discovery_timer.stop()

        def _set_model_discovery_status(self, text: str, warning: bool = False) -> None:
            full_text = str(text or "")
            display_text = full_text
            if len(display_text) > 140:
                display_text = display_text[:137] + "..."
            self.model_status_label.setText(display_text)
            self.model_status_label.setToolTip(full_text)
            if warning:
                self.model_status_label.setStyleSheet("color: #d19a66;")
            else:
                self.model_status_label.setStyleSheet("")

        def closeEvent(self, event: QtGui.QCloseEvent) -> None:
            self._ignore_pending_model_discovery()
            super().closeEvent(event)

        def done(self, result: int) -> None:
            self._ignore_pending_model_discovery()
            super().done(result)


    class FreeStudioWindow(QtWidgets.QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle(plugin_title() + " Free Studio")
            self.resize(1400, 900)
            self._config = load_config()
            if provider_uses_api_key_settings(self._config.llm.provider):
                self._api_key = get_provider_api_key(self._config, self._config.llm.provider)
            else:
                self._api_key = ""
            self._project_root = ""
            self._rule_dirs_text = ""
            self._buffer_case_text = ""
            self._helper_depth = 2
            self._input_label = "clipboard.cpp"
            self._result: FreeAnalysisResult | None = None
            self._thread: QtCore.QThread | None = None
            self._worker: AnalysisWorker | None = None
            self._syntax_highlighters: list[object] = []
            self._build_ui()
            self._set_busy(False)

        def _build_ui(self) -> None:
            self.raw_edit = QtWidgets.QPlainTextEdit()
            self.cleaned_edit = QtWidgets.QPlainTextEdit()
            self.raw_edit.setPlaceholderText("Paste one complete IDA Free cloud-decompiled function here.")
            self.cleaned_edit.setPlaceholderText("Cleaned PseudoForge output appears here.")
            self._apply_editor_font(self.raw_edit)
            self._apply_editor_font(self.cleaned_edit)
            self.raw_edit.setLineWrapMode(_plain_text_no_wrap())
            self.cleaned_edit.setLineWrapMode(_plain_text_no_wrap())
            self._apply_code_highlighting(self.raw_edit)
            self._apply_code_highlighting(self.cleaned_edit)

            editor_split = QtWidgets.QSplitter(_qt_orientation("Horizontal"))
            editor_split.addWidget(self.raw_edit)
            editor_split.addWidget(self.cleaned_edit)
            editor_split.setSizes([700, 700])

            self.tabs = QtWidgets.QTabWidget()
            self.warnings_tab = QtWidgets.QPlainTextEdit()
            self.renames_tab = QtWidgets.QPlainTextEdit()
            self.diff_tab = QtWidgets.QPlainTextEdit()
            self.rule_report_tab = QtWidgets.QPlainTextEdit()
            self.artifacts_tab = QtWidgets.QPlainTextEdit()
            for editor in (
                self.warnings_tab,
                self.renames_tab,
                self.diff_tab,
                self.rule_report_tab,
                self.artifacts_tab,
            ):
                editor.setReadOnly(True)
                editor.setLineWrapMode(_plain_text_no_wrap())
                self._apply_editor_font(editor)
            self.tabs.addTab(self.warnings_tab, "Warnings")
            self.tabs.addTab(self.renames_tab, "Renames")
            self.tabs.addTab(self.diff_tab, "Diff")
            self.tabs.addTab(self.rule_report_tab, "Rule Report")
            self.tabs.addTab(self.artifacts_tab, "Artifacts")

            main_split = QtWidgets.QSplitter(_qt_orientation("Vertical"))
            main_split.addWidget(editor_split)
            main_split.addWidget(self.tabs)
            main_split.setSizes([640, 260])
            self.setCentralWidget(main_split)
            self._build_toolbar()
            self.statusBar().showMessage("Ready")

        def _build_toolbar(self) -> None:
            toolbar = self.addToolBar("PseudoForge Free Studio")
            toolbar.setMovable(False)
            self.paste_action = self._add_action(toolbar, "Paste", self._paste_input)
            self.open_action = self._add_action(toolbar, "Open", self._open_input)
            self.analyze_action = self._add_action(toolbar, "Analyze", self._start_analysis)
            self.stop_action = self._add_action(toolbar, "Stop", self._stop_analysis)
            self.copy_action = self._add_action(toolbar, "Copy Cleaned", self._copy_cleaned)
            self.save_action = self._add_action(toolbar, "Save Bundle", self._save_bundle)
            self.settings_action = self._add_action(toolbar, "Settings", self._show_settings)

        def _add_action(self, toolbar: QtWidgets.QToolBar, text: str, handler: Any) -> QtGui.QAction:
            action = QtGui.QAction(text, self)
            action.triggered.connect(handler)
            toolbar.addAction(action)
            return action

        def _apply_editor_font(self, editor: QtWidgets.QPlainTextEdit) -> None:
            font = QtGui.QFontDatabase.systemFont(_fixed_font_role())
            editor.setFont(font)

        def _apply_code_highlighting(self, editor: QtWidgets.QPlainTextEdit) -> None:
            highlighter = _apply_c_like_syntax_highlighting(editor)
            if highlighter is not None:
                self._syntax_highlighters.append(highlighter)

        def _paste_input(self) -> None:
            self.raw_edit.setPlainText(QtWidgets.QApplication.clipboard().text())
            self._input_label = "clipboard.cpp"
            self._clear_current_result()
            self.statusBar().showMessage("Pasted clipboard text")

        def _open_input(self) -> None:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self,
                "Open copied pseudocode",
                "",
                "Pseudocode (*.cpp *.c *.txt);;All files (*)",
            )
            if not path:
                return
            try:
                text = Path(path).read_text(encoding="utf-8-sig")
            except OSError as exc:
                QtWidgets.QMessageBox.warning(self, "Open failed", str(exc))
                return
            self.raw_edit.setPlainText(text)
            self._input_label = path
            self._clear_current_result()
            self.statusBar().showMessage("Opened %s" % path)

        def _start_analysis(self) -> None:
            source_text = self.raw_edit.toPlainText()
            if not source_text.strip():
                QtWidgets.QMessageBox.information(self, "No input", "Paste or open one decompiled function first.")
                return
            try:
                options = options_from_config(
                    self._config,
                    api_key=self._api_key,
                    project_root=self._project_root,
                    rule_dirs_text=self._rule_dirs_text,
                    buffer_case_text=self._buffer_case_text,
                    buffer_contract_helper_depth=self._helper_depth,
                )
            except ValueError as exc:
                QtWidgets.QMessageBox.warning(self, "Invalid settings", str(exc))
                return

            self._clear_current_result()
            output_dir = default_session_output_dir(self._input_label)
            self._thread = QtCore.QThread(self)
            self._worker = AnalysisWorker(source_text, self._input_label, output_dir, options)
            self._worker.moveToThread(self._thread)
            self._thread.started.connect(self._worker.run)
            self._worker.progress.connect(self._on_progress)
            self._worker.completed.connect(self._analysis_completed)
            self._worker.failed.connect(self._analysis_failed)
            self._worker.cancelled.connect(self._analysis_cancelled)
            self._worker.completed.connect(self._thread.quit)
            self._worker.failed.connect(self._thread.quit)
            self._worker.cancelled.connect(self._thread.quit)
            self._thread.finished.connect(self._thread.deleteLater)
            self._thread.finished.connect(self._clear_worker)
            self._set_busy(True)
            self.statusBar().showMessage("Analysis started")
            self._thread.start()

        def _stop_analysis(self) -> None:
            if self._worker is not None:
                self._worker.cancel()
                self.statusBar().showMessage("Stop requested. Current provider call may finish first.")

        def _copy_cleaned(self) -> None:
            QtWidgets.QApplication.clipboard().setText(self.cleaned_edit.toPlainText())
            self.statusBar().showMessage("Cleaned output copied")

        def _save_bundle(self) -> None:
            if self._result is None:
                QtWidgets.QMessageBox.information(self, "No result", "Run analysis before saving a bundle.")
                return
            path = QtWidgets.QFileDialog.getExistingDirectory(self, "Save PseudoForge bundle")
            if not path:
                return
            try:
                deps = load_free_analysis_deps()
                self._result = save_result_bundle(self._result, path, deps=deps)
            except Exception as exc:
                QtWidgets.QMessageBox.warning(self, "Save failed", str(exc))
                return
            self._populate_result(self._result)
            self.statusBar().showMessage("Bundle saved to %s" % path)

        def _show_settings(self) -> None:
            dialog = LlmSettingsDialog(
                self._config,
                self._api_key,
                self._project_root,
                self._rule_dirs_text,
                self._buffer_case_text,
                self._helper_depth,
                self,
            )
            if dialog.exec() != _dialog_accepted():
                return
            (
                self._config,
                self._api_key,
                self._project_root,
                self._rule_dirs_text,
                self._buffer_case_text,
                self._helper_depth,
            ) = dialog.updated_config()
            try:
                save_config(self._config)
            except OSError as exc:
                QtWidgets.QMessageBox.warning(self, "Settings warning", "Settings could not be saved: %s" % exc)
                return
            self.statusBar().showMessage("Settings saved")

        def _on_progress(self, event: FreeAnalysisProgress) -> None:
            detail = event.detail
            if detail:
                self.statusBar().showMessage("%s: %s" % (event.title, detail))
            else:
                self.statusBar().showMessage(event.title)

        def _analysis_completed(self, result: FreeAnalysisResult) -> None:
            self._result = result
            self._populate_result(result)
            self._set_busy(False)
            self.statusBar().showMessage(
                "Analysis complete: %s, LLM %s" % (result.function, result.llm_status)
            )

        def _analysis_failed(self, message: str) -> None:
            self._set_busy(False)
            QtWidgets.QMessageBox.warning(self, "Analysis failed", message)
            self.statusBar().showMessage("Analysis failed")

        def _analysis_cancelled(self, message: str) -> None:
            self._set_busy(False)
            self.statusBar().showMessage("Analysis cancelled: %s" % message)

        def _clear_worker(self) -> None:
            self._worker = None
            self._thread = None

        def _clear_current_result(self) -> None:
            self._result = None
            self.cleaned_edit.clear()
            self.warnings_tab.clear()
            self.renames_tab.clear()
            self.diff_tab.clear()
            self.rule_report_tab.clear()
            self.artifacts_tab.clear()
            self._set_busy(False)

        def _populate_result(self, result: FreeAnalysisResult) -> None:
            self.cleaned_edit.setPlainText(result.cleaned_text)
            self.warnings_tab.setPlainText(format_warnings(result.warnings))
            self.renames_tab.setPlainText(format_renames(result.plan))
            self.diff_tab.setPlainText(result.diff_text)
            self.rule_report_tab.setPlainText(format_rule_report(result.plan))
            self.artifacts_tab.setPlainText(format_artifacts(result.artifacts))

        def _set_busy(self, busy: bool) -> None:
            self.paste_action.setEnabled(not busy)
            self.open_action.setEnabled(not busy)
            self.analyze_action.setEnabled(not busy)
            self.stop_action.setEnabled(busy)
            self.settings_action.setEnabled(not busy)
            self.save_action.setEnabled((not busy) and self._result is not None)
            self.copy_action.setEnabled((not busy) and bool(self.cleaned_edit.toPlainText()))


    def _plain_text_no_wrap() -> Any:
        value = getattr(QtWidgets.QPlainTextEdit, "NoWrap", None)
        if value is not None:
            return value
        return QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap


    def _qt_orientation(name: str) -> Any:
        value = getattr(QtCore.Qt, name, None)
        if value is not None:
            return value
        return getattr(QtCore.Qt.Orientation, name)


    def _dialog_button(name: str) -> Any:
        value = getattr(QtWidgets.QDialogButtonBox, name, None)
        if value is not None:
            return value
        return getattr(QtWidgets.QDialogButtonBox.StandardButton, name)


    def _dialog_accepted() -> Any:
        value = getattr(QtWidgets.QDialog, "Accepted", None)
        if value is not None:
            return value
        return QtWidgets.QDialog.DialogCode.Accepted


    def _fixed_font_role() -> Any:
        value = getattr(QtGui.QFontDatabase, "FixedFont", None)
        if value is not None:
            return value
        return QtGui.QFontDatabase.SystemFont.FixedFont


    def _apply_c_like_syntax_highlighting(editor: QtWidgets.QPlainTextEdit) -> object | None:
        highlighter_cls = _c_like_highlighter_class()
        if highlighter_cls is None:
            return None
        try:
            highlighter = highlighter_cls(editor.document())
            rehighlight = getattr(highlighter, "rehighlight", None)
            if rehighlight is not None:
                rehighlight()
            return highlighter
        except Exception:
            return None


    def _c_like_highlighter_class() -> type | None:
        highlighter_base = getattr(QtGui, "QSyntaxHighlighter", None)
        text_format_cls = getattr(QtGui, "QTextCharFormat", None)
        color_cls = getattr(QtGui, "QColor", None)
        if highlighter_base is None or text_format_cls is None or color_cls is None:
            return None

        class _FreeStudioSyntaxHighlighter(highlighter_base):
            def __init__(self, document) -> None:
                super().__init__(document)
                self._formats = _c_like_text_formats()

            def highlightBlock(self, text: str) -> None:
                plain_format = self._formats.get("plain")
                if plain_format is not None and text:
                    self.setFormat(0, len(text), plain_format)
                for start_index, length, role in c_like_highlight_spans(text):
                    text_format = self._formats.get(role)
                    if text_format is None:
                        continue
                    self.setFormat(start_index, length, text_format)

        return _FreeStudioSyntaxHighlighter


    def _c_like_text_formats() -> dict[str, object]:
        formats: dict[str, object] = {}
        for role, rgb in C_LIKE_HIGHLIGHT_PALETTE.items():
            text_format = QtGui.QTextCharFormat()
            text_format.setForeground(QtGui.QColor(*rgb))
            formats[role] = text_format
        return formats


    def _format_model_discovery_warning(message: str) -> str:
        warning = str(message or "").strip()
        prefix = "static fallback: "
        if warning.startswith(prefix):
            warning = warning[len(prefix):]
        return warning or "model catalog unavailable"


def main(argv: list[str] | None = None) -> int:
    if QtWidgets is None:
        print(missing_qt_message(), file=sys.stderr)
        return 1
    app = QtWidgets.QApplication.instance()
    if app is None:
        app = QtWidgets.QApplication(argv or sys.argv)
    window = FreeStudioWindow()
    window.show()
    return int(app.exec())

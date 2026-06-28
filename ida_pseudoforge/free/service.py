from __future__ import annotations

import difflib
import json
import os
import re
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator

from ida_pseudoforge.version import VERSION


IDA_ONLY_MODULES = {
    "idaapi",
    "ida_auto",
    "ida_bytes",
    "ida_funcs",
    "ida_hexrays",
    "ida_ida",
    "ida_kernwin",
    "ida_name",
    "ida_nalt",
    "ida_typeinf",
    "idautils",
    "idc",
}

PROGRESS_STEP = "step"
PROGRESS_FIELD = "field"


class FreeAnalysisError(RuntimeError):
    pass


class FreeAnalysisCancelled(FreeAnalysisError):
    pass


@dataclass(slots=True)
class FreeAnalysisProgress:
    kind: str
    title: str
    detail: str = ""


ProgressCallback = Callable[[FreeAnalysisProgress], None]
CancelCheck = Callable[[], bool]


@dataclass(slots=True)
class FreeAnalysisOptions:
    name: str = ""
    profile_dir: str = ""
    project_root: str = ""
    rule_dirs: list[str] = field(default_factory=list)
    llm_enabled: bool = False
    llm_provider: str = "openai_compatible"
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model: str = ""
    llm_command: str = ""
    llm_timeout: int = 60
    buffer_contract_case_values: list[int] = field(default_factory=list)
    buffer_contract_helper_depth: int = 2
    projection_policy: str = "review_only"

    def effective_rule_dirs(self) -> list[str]:
        dirs = [str(item) for item in self.rule_dirs]
        if self.project_root:
            dirs.append(str(Path(self.project_root) / "pseudoforge_rules"))
        return dirs


@dataclass(slots=True)
class FreeAnalysisResult:
    input: str
    function: str
    pseudocode: str
    cleaned_text: str
    raw_text: str
    diff_text: str
    output_dir: str
    llm_status: str
    warnings: list[str]
    artifacts: dict[str, str]
    rule_diagnostics: dict[str, Any]
    payload: dict[str, Any]
    capture: Any = field(repr=False)
    plan: Any = field(repr=False)


@dataclass(slots=True)
class FreeAnalysisDeps:
    OfflinePseudocodeError: Any
    normalize_copied_pseudocode: Any
    capture_from_pseudocode: Any
    build_clean_plan: Any
    write_export_bundle: Any
    render_cleaned_pseudocode: Any
    export_warnings: Any
    export_warning_diagnostics: Any
    active_profile_manifests: Any
    active_profile_names: Any
    active_profile_root: Any
    profile_load_warnings: Any
    configure_profile_dir: Any
    LlmConfig: Any
    build_rename_provider: Any


@dataclass(slots=True)
class _FreeArtifactWrite:
    paths: dict[str, str]
    raw_text: str
    cleaned_text: str
    diff_text: str


def load_free_analysis_deps() -> FreeAnalysisDeps:
    try:
        from ida_pseudoforge.config import LlmConfig
        from ida_pseudoforge.core.capture import capture_from_pseudocode
        from ida_pseudoforge.core.export_bundle import write_export_bundle
        from ida_pseudoforge.core.lvar_analysis import build_clean_plan
        from ida_pseudoforge.core.offline_input import OfflinePseudocodeError, normalize_copied_pseudocode
        from ida_pseudoforge.core.render import render_cleaned_pseudocode
        from ida_pseudoforge.core.render_warnings import export_warning_diagnostics, export_warnings
        from ida_pseudoforge.models.provider_factory import build_rename_provider
        from ida_pseudoforge.profiles.loader import (
            active_profile_manifests,
            active_profile_names,
            active_profile_root,
            configure_profile_dir,
            profile_load_warnings,
        )
    except ModuleNotFoundError as exc:
        if (exc.name or "") in IDA_ONLY_MODULES:
            raise RuntimeError(
                "IDA Free offline analysis cannot import IDA-only module %s. "
                "Run this path with a normal Python interpreter outside IDA." % exc.name
            ) from exc
        raise

    assert_no_ida_modules_loaded("dependency import")
    return FreeAnalysisDeps(
        OfflinePseudocodeError=OfflinePseudocodeError,
        normalize_copied_pseudocode=normalize_copied_pseudocode,
        capture_from_pseudocode=capture_from_pseudocode,
        build_clean_plan=build_clean_plan,
        write_export_bundle=write_export_bundle,
        render_cleaned_pseudocode=render_cleaned_pseudocode,
        export_warnings=export_warnings,
        export_warning_diagnostics=export_warning_diagnostics,
        active_profile_manifests=active_profile_manifests,
        active_profile_names=active_profile_names,
        active_profile_root=active_profile_root,
        profile_load_warnings=profile_load_warnings,
        configure_profile_dir=configure_profile_dir,
        LlmConfig=LlmConfig,
        build_rename_provider=build_rename_provider,
    )


def analyze_file(
    input_path: str | Path,
    output_root: str | Path,
    options: FreeAnalysisOptions | None = None,
    deps: FreeAnalysisDeps | None = None,
    multiple_inputs: bool = False,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
) -> FreeAnalysisResult:
    resolved_options = options or FreeAnalysisOptions()
    resolved_deps = deps or load_free_analysis_deps()
    with _configured_profile_scope(resolved_deps, resolved_options.profile_dir):
        path = Path(input_path)
        _emit_step(progress, "Read input", str(path))
        _check_cancel(cancel_check)
        try:
            source_text = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise FreeAnalysisError("Input file could not be read: %s" % exc) from exc

        output_dir = Path(output_root) / safe_file_stem(path.stem) if multiple_inputs else Path(output_root)
        return _analyze_source(
            source_text=source_text,
            input_label=str(path),
            source_path=str(path),
            output_dir=output_dir,
            options=resolved_options,
            deps=resolved_deps,
            progress=progress,
            cancel_check=cancel_check,
        )


def analyze_text(
    source_text: str,
    output_dir: str | Path,
    input_label: str = "clipboard.cpp",
    source_path: str = "",
    options: FreeAnalysisOptions | None = None,
    deps: FreeAnalysisDeps | None = None,
    progress: ProgressCallback | None = None,
    cancel_check: CancelCheck | None = None,
) -> FreeAnalysisResult:
    resolved_options = options or FreeAnalysisOptions()
    resolved_deps = deps or load_free_analysis_deps()
    with _configured_profile_scope(resolved_deps, resolved_options.profile_dir):
        _emit_step(progress, "Read input", input_label)
        return _analyze_source(
            source_text=source_text,
            input_label=input_label,
            source_path=source_path or input_label,
            output_dir=Path(output_dir),
            options=resolved_options,
            deps=resolved_deps,
            progress=progress,
            cancel_check=cancel_check,
        )


def save_result_bundle(
    result: FreeAnalysisResult,
    output_dir: str | Path,
    deps: FreeAnalysisDeps | None = None,
) -> FreeAnalysisResult:
    resolved_deps = deps or load_free_analysis_deps()
    profile_root = str(result.payload.get("profile_root", "") or "")
    profile_metadata = _profile_metadata_from_payload(result.payload)
    with _configured_profile_scope(resolved_deps, profile_root):
        artifact_write = _write_analysis_artifacts(
            output_dir=Path(output_dir),
            input_label=result.input,
            capture=result.capture,
            plan=result.plan,
            pseudocode=result.pseudocode,
            warnings=result.warnings,
            deps=resolved_deps,
        )
        payload = _result_payload(
            input_label=result.input,
            capture=result.capture,
            plan=result.plan,
            warnings=result.warnings,
            llm_status=result.llm_status,
            artifacts=artifact_write.paths,
            deps=resolved_deps,
            profile_metadata=profile_metadata,
        )
        _write_summary(Path(output_dir), result.capture, payload)
        return FreeAnalysisResult(
            input=result.input,
            function=result.function,
            pseudocode=result.pseudocode,
            cleaned_text=artifact_write.cleaned_text,
            raw_text=artifact_write.raw_text,
            diff_text=artifact_write.diff_text,
            output_dir=str(Path(output_dir)),
            llm_status=result.llm_status,
            warnings=list(result.warnings),
            artifacts=artifact_write.paths,
            rule_diagnostics=dict(result.rule_diagnostics),
            payload=payload,
            capture=result.capture,
            plan=result.plan,
        )


@contextmanager
def _configured_profile_scope(deps: FreeAnalysisDeps, profile_dir: str) -> Iterator[None]:
    previous_profile_dir = deps.active_profile_root()
    deps.configure_profile_dir(profile_dir)
    try:
        yield
    finally:
        deps.configure_profile_dir(previous_profile_dir)


def build_run_payload(results: list[dict[str, Any]], failures: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "mode": "ida_free_offline",
        "pseudoforge_version": VERSION,
        "ida_apis_used": False,
        "idb_modified": False,
        "interactive_plugin_supported": False,
        "results": results,
        "failures": failures,
    }


def write_run_manifest(output_root: str | Path, payload: dict[str, Any]) -> None:
    try:
        root = Path(output_root)
        root.mkdir(parents=True, exist_ok=True)
        (root / "pseudoforge-free-report.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )
    except OSError as exc:
        raise RuntimeError("Output directory could not be written: %s" % exc) from exc


def default_session_output_dir(input_label: str = "clipboard") -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        root = Path(base) / "PseudoForge" / "sessions"
    else:
        root = Path.home() / ".pseudoforge" / "sessions"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return root / ("%s_%s" % (timestamp, safe_file_stem(Path(input_label).stem or "clipboard")))


def loaded_ida_modules() -> list[str]:
    return sorted(name for name in sys.modules if name.split(".", 1)[0] in IDA_ONLY_MODULES)


def assert_no_ida_modules_loaded(stage: str) -> None:
    loaded = loaded_ida_modules()
    if loaded:
        raise RuntimeError(
            "IDA Free offline analysis must not use IDA-only modules during %s: %s"
            % (stage, ", ".join(loaded))
        )


def safe_file_stem(name: str) -> str:
    cleaned = "".join(
        char if char.isascii() and (char.isalnum() or char in "._-") else "_"
        for char in str(name or "")
    )
    return cleaned.strip("._") or "function"


def parse_case_value(value: str) -> int:
    text = str(value or "").strip()
    cleaned = re.sub(r"(?i)(ui64|i64|ull|llu|ll|ul|lu|u|l)$", "", text)
    try:
        return int(cleaned, 0)
    except ValueError as exc:
        raise ValueError("case value must be a C integer literal") from exc


def _analyze_source(
    source_text: str,
    input_label: str,
    source_path: str,
    output_dir: Path,
    options: FreeAnalysisOptions,
    deps: FreeAnalysisDeps,
    progress: ProgressCallback | None,
    cancel_check: CancelCheck | None,
) -> FreeAnalysisResult:
    _emit_field(progress, "Input bytes", len((source_text or "").encode("utf-8", errors="replace")))
    _emit_step(progress, "Normalize copied text")
    _check_cancel(cancel_check)
    try:
        pseudocode = deps.normalize_copied_pseudocode(source_text)
    except deps.OfflinePseudocodeError as exc:
        raise FreeAnalysisError(str(exc)) from exc
    _emit_field(progress, "Pseudocode lines", len(pseudocode.splitlines()))

    _emit_step(progress, "Capture function")
    _check_cancel(cancel_check)
    capture = deps.capture_from_pseudocode(
        pseudocode,
        name=options.name,
        source_path=source_path,
    )
    if options.project_root:
        capture.source_path = str(Path(options.project_root))
    _emit_field(progress, "Function", capture.name)

    rule_dirs = options.effective_rule_dirs()
    _emit_step(progress, "Load rules", _format_rule_dirs(rule_dirs))
    _emit_step(progress, "Build clean plan", _format_plan_mode(options))
    _check_cancel(cancel_check)
    plan, llm_status = _build_plan(capture, options, deps, rule_dirs)
    _check_cancel(cancel_check)
    warnings = deps.export_warnings(plan)
    _emit_field(progress, "Rename candidates", len(plan.renames))
    _emit_field(progress, "Flow rewrites", len(plan.flow_rewrites))
    _emit_field(progress, "Warnings", len(warnings))
    _emit_field(progress, "LLM status", llm_status)

    _emit_step(progress, "Write artifacts", str(output_dir))
    try:
        profile_warnings = deps.profile_load_warnings()
        if profile_warnings:
            _emit_field(progress, "Profile warnings", len(profile_warnings))
        artifact_write = _write_analysis_artifacts(
            output_dir=output_dir,
            input_label=input_label,
            capture=capture,
            plan=plan,
            pseudocode=pseudocode,
            warnings=warnings,
            deps=deps,
        )
    except OSError as exc:
        raise FreeAnalysisError("Output artifacts could not be written: %s" % exc) from exc

    payload = _result_payload(
        input_label=input_label,
        capture=capture,
        plan=plan,
        warnings=warnings,
        llm_status=llm_status,
        artifacts=artifact_write.paths,
        deps=deps,
    )
    _write_summary(output_dir, capture, payload)
    _emit_step(progress, "Input complete", "%d artifact(s)" % len(payload["artifacts"]))
    return FreeAnalysisResult(
        input=input_label,
        function=capture.name,
        pseudocode=pseudocode,
        cleaned_text=artifact_write.cleaned_text,
        raw_text=artifact_write.raw_text,
        diff_text=artifact_write.diff_text,
        output_dir=str(output_dir),
        llm_status=llm_status,
        warnings=warnings,
        artifacts=artifact_write.paths,
        rule_diagnostics=dict(payload["rule_diagnostics"]),
        payload=payload,
        capture=capture,
        plan=plan,
    )


def _build_plan(
    capture: Any,
    options: FreeAnalysisOptions,
    deps: FreeAnalysisDeps,
    rule_dirs: list[str],
) -> tuple[Any, str]:
    case_values = options.buffer_contract_case_values or None
    helper_depth = max(0, int(options.buffer_contract_helper_depth))
    if not options.llm_enabled:
        return deps.build_clean_plan(
            capture,
            rule_dirs=rule_dirs,
            buffer_contract_case_values=case_values,
            buffer_contract_helper_depth=helper_depth,
            projection_policy=options.projection_policy,
        ), "disabled"

    try:
        provider = _build_provider(options, deps)
        return deps.build_clean_plan(
            capture,
            rename_provider=provider,
            rule_dirs=rule_dirs,
            buffer_contract_case_values=case_values,
            buffer_contract_helper_depth=helper_depth,
            projection_policy=options.projection_policy,
        ), "ok"
    except Exception as exc:
        from ida_pseudoforge.core.llm_failures import format_llm_fallback_warning

        plan = deps.build_clean_plan(
            capture,
            rule_dirs=rule_dirs,
            buffer_contract_case_values=case_values,
            buffer_contract_helper_depth=helper_depth,
            projection_policy=options.projection_policy,
        )
        plan.warnings.insert(0, format_llm_fallback_warning(exc))
        return plan, "failed_fallback"


def _build_provider(options: FreeAnalysisOptions, deps: FreeAnalysisDeps) -> Any:
    config = deps.LlmConfig(
        enabled=True,
        provider=options.llm_provider,
        base_url=options.llm_base_url,
        model=options.llm_model,
        timeout_seconds=options.llm_timeout,
        command_template=options.llm_command,
    )
    return deps.build_rename_provider(config, api_key=options.llm_api_key)


def _write_analysis_artifacts(
    output_dir: Path,
    input_label: str,
    capture: Any,
    plan: Any,
    pseudocode: str,
    warnings: list[str],
    deps: FreeAnalysisDeps,
) -> _FreeArtifactWrite:
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_paths = deps.write_export_bundle(
        output_dir,
        capture,
        plan,
        entrypoint="ida_free_offline",
        summary_suffix="ida-free-summary",
    )
    extra_paths, raw_text, cleaned_text, diff_text = _write_free_artifacts(
        output_dir,
        input_label,
        capture,
        plan,
        pseudocode,
        warnings,
        deps,
    )
    artifact_paths.update(extra_paths)
    return _FreeArtifactWrite(
        paths=artifact_paths,
        raw_text=raw_text,
        cleaned_text=cleaned_text,
        diff_text=diff_text,
    )


def _write_free_artifacts(
    output_dir: Path,
    input_label: str,
    capture: Any,
    plan: Any,
    pseudocode: str,
    warnings: list[str],
    deps: FreeAnalysisDeps,
) -> tuple[dict[str, str], str, str, str]:
    safe_name = safe_file_stem(capture.name or Path(input_label).stem or "function")
    raw_path = output_dir / ("%s.raw.cpp" % safe_name)
    warnings_path = output_dir / ("%s.warnings.json" % safe_name)
    warning_diagnostics_path = output_dir / ("%s.warning-diagnostics.json" % safe_name)
    diff_path = output_dir / ("%s.raw-vs-cleaned.diff" % safe_name)

    cleaned_text = deps.render_cleaned_pseudocode(capture, plan)
    warning_diagnostics = deps.export_warning_diagnostics(plan)
    raw_text = pseudocode.rstrip() + "\n"
    raw_path.write_text(raw_text, encoding="utf-8")
    warnings_path.write_text(
        json.dumps(warnings, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    warning_diagnostics_path.write_text(
        json.dumps(warning_diagnostics, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    diff_text = "".join(
        difflib.unified_diff(
            raw_text.splitlines(keepends=True),
            cleaned_text.splitlines(keepends=True),
            fromfile="raw/%s.cpp" % safe_name,
            tofile="cleaned/%s.cpp" % safe_name,
            lineterm="",
        )
    )
    diff_path.write_text(diff_text, encoding="utf-8")
    return {
        "raw_pseudocode": str(raw_path),
        "warnings": str(warnings_path),
        "warning_diagnostics": str(warning_diagnostics_path),
        "raw_vs_cleaned_diff": str(diff_path),
    }, raw_text, cleaned_text, diff_text


def _result_payload(
    input_label: str,
    capture: Any,
    plan: Any,
    warnings: list[str],
    llm_status: str,
    artifacts: dict[str, str],
    deps: FreeAnalysisDeps,
    profile_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from ida_pseudoforge.core.rule_diagnostics import summarize_rule_report

    rule_diagnostics = summarize_rule_report(plan.rule_report)
    profile_root = deps.active_profile_root()
    active_profiles = deps.active_profile_names()
    profile_manifests = deps.active_profile_manifests()
    if profile_metadata is not None:
        profile_root = str(profile_metadata.get("profile_root", profile_root) or "")
        active_profiles = _list_from_payload(profile_metadata.get("active_profiles", active_profiles))
        profile_manifests = _list_from_payload(profile_metadata.get("profile_manifests", profile_manifests))
    return {
        "input": input_label,
        "function": capture.name,
        "mode": "ida_free_offline",
        "pseudoforge_version": VERSION,
        "ida_apis_used": False,
        "idb_modified": False,
        "llm_status": llm_status,
        "rule_diagnostics": rule_diagnostics,
        "rule_load_errors": list(rule_diagnostics["load_error_details"]),
        "rule_validation_errors": list(rule_diagnostics["validation_error_details"]),
        "warnings": warnings,
        "profile_root": profile_root,
        "active_profiles": active_profiles,
        "profile_manifests": profile_manifests,
        "artifacts": artifacts,
    }


def _profile_metadata_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile_root": str(payload.get("profile_root", "") or ""),
        "active_profiles": _list_from_payload(payload.get("active_profiles", [])),
        "profile_manifests": _list_from_payload(payload.get("profile_manifests", [])),
    }


def _list_from_payload(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _write_summary(output_dir: Path, capture: Any, result: dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / ("%s.ida-free-summary.json" % safe_file_stem(capture.name or "function"))
    path.write_text(json.dumps(result, indent=2, ensure_ascii=True), encoding="utf-8")
    result["artifacts"]["summary"] = str(path)
    return path


def _format_rule_dirs(rule_dirs: list[str]) -> str:
    if not rule_dirs:
        return "builtin and user-global"
    return "builtin, user-global, " + ", ".join(rule_dirs)


def _format_plan_mode(options: FreeAnalysisOptions) -> str:
    if not options.llm_enabled:
        return "deterministic only"
    return "deterministic plus %s LLM assist, timeout %ds" % (
        options.llm_provider,
        options.llm_timeout,
    )


def _emit_step(progress: ProgressCallback | None, title: str, detail: object = "") -> None:
    _emit(progress, FreeAnalysisProgress(kind=PROGRESS_STEP, title=title, detail=str(detail or "")))


def _emit_field(progress: ProgressCallback | None, title: str, detail: object = "") -> None:
    _emit(progress, FreeAnalysisProgress(kind=PROGRESS_FIELD, title=title, detail=str(detail)))


def _emit(progress: ProgressCallback | None, event: FreeAnalysisProgress) -> None:
    if progress is not None:
        progress(event)


def _check_cancel(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None and cancel_check():
        raise FreeAnalysisCancelled("IDA Free analysis was cancelled.")

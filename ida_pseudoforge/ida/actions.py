from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

from ida_pseudoforge.config import (
    get_provider_api_key,
    load_config,
    save_config,
)
from ida_pseudoforge.core.export_bundle import write_export_bundle
from ida_pseudoforge.core.buffer_contracts import (
    find_case_value_near_line,
    helper_names_for_selected_case,
    render_buffer_contract_report,
    render_case_context_report,
    render_buffer_struct_header,
)
from ida_pseudoforge.core.forge_store import (
    ForgeFunctionSection,
    find_forge_function_section,
    write_forge_function,
)
from ida_pseudoforge.core.helper_aliases import (
    RuntimeHelperAlias,
    apply_runtime_helper_aliases,
    infer_direct_runtime_helper_aliases,
    is_runtime_helper_alias_advisory,
    runtime_helper_alias_summary,
)
from ida_pseudoforge.core.llm_failures import (
    format_llm_fallback_warning,
    is_llm_provider_cyber_policy_block,
    summarize_llm_failure,
)
from ida_pseudoforge.core.ioctl import parse_c_integer_literal
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture
from ida_pseudoforge.core.capture import profile_context_from_source_path
from ida_pseudoforge.core.domain_identity_summary import format_domain_identity_summary
from ida_pseudoforge.core.render_header import (
    format_function_identity_candidate_summary,
    format_parameter_type_correction_summary,
)
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.rule_diagnostics import format_rule_report_summary
from ida_pseudoforge.ida.apply_changes import apply_selected_renames
from ida_pseudoforge.ida.analysis_state import PluginAnalysisSession, PluginAnalysisState
from ida_pseudoforge.ida.async_runner import (
    CancellationRequested,
    active_group_task,
    raise_if_cancelled,
    request_group_cancel,
    run_background,
)
from ida_pseudoforge.ida.decompiler import capture_current_function, capture_current_lvars, capture_function_by_name
from ida_pseudoforge.ida.disasm_capture import capture_disasm_case_slice
from ida_pseudoforge.ida.llm_config_dialog import ask_llm_config, format_llm_summary
from ida_pseudoforge.ida.preview_config_dialog import ask_preview_config, format_preview_summary
from ida_pseudoforge.ida.profile_config_dialog import ask_profile_dir, format_profile_summary
from ida_pseudoforge.ida.source_context import format_source_context_summary
from ida_pseudoforge.ida.thread_helpers import run_on_main_thread
from ida_pseudoforge.ida.ui_preview import (
    build_save_as_filename,
    choose_renames,
    info,
    side_by_side_preview_enabled,
    show_analyzed_functions_from_text,
    show_text_view,
    warning,
)
from ida_pseudoforge.logging import log_checkpoint, log_event, log_output, trace_scope
from ida_pseudoforge.models.provider_factory import build_rename_provider
from ida_pseudoforge.models.provider_registry import (
    normalize_provider,
    provider_label,
    provider_requires_api_key,
)
from ida_pseudoforge.profiles.loader import DEFAULT_PROFILE_DIR, active_profile_root, configure_profile_dir
from ida_pseudoforge.version import VERSION

try:
    import ida_hexrays  # type: ignore
    import ida_nalt  # type: ignore
    import ida_kernwin  # type: ignore
    import idaapi  # type: ignore
    import ida_funcs  # type: ignore
except Exception:
    ida_hexrays = None
    ida_nalt = None
    ida_kernwin = None
    idaapi = None
    ida_funcs = None


PLUGIN_STATE_GROUP = "plugin_state"
_ANALYSIS_STATE = PluginAnalysisState()
_DIRECT_HELPER_ALIAS_MAX_CALLEES = 8


def analyze_current_function(purpose: str = "analyze") -> tuple[FunctionCapture, CleanPlan]:
    with trace_scope("analysis", purpose=purpose):
        log_event("analysis.start purpose=%s" % _ascii_for_log(purpose))
        _raise_if_task_cancelled(purpose, "before capture")
        with trace_scope("analysis.capture", purpose=purpose):
            capture, _cfunc = capture_current_function()
        _raise_if_task_cancelled(purpose, "after capture")
        _set_capture_source_path(capture)
        log_event(
            "capture.ok function=\"%s\" ea=0x%X lvars=%d calls=%d"
            % (_ascii_for_log(capture.name), capture.ea, len(capture.lvars), len(capture.calls))
        )
        with trace_scope("analysis.build_plan", function=capture.name, ea="0x%X" % capture.ea):
            plan = _build_plan_with_config(capture, task_name=purpose)
        _raise_if_task_cancelled(purpose, "after build plan")
        forge_path: Path | None = None
        forge_text = ""
        try:
            with trace_scope("analysis.forge_write", function=capture.name, ea="0x%X" % capture.ea):
                _raise_if_task_cancelled(purpose, "before forge write")
                forge_path, forge_text = _write_forge_snapshot(capture, plan)
        except CancellationRequested:
            raise
        except Exception as exc:
            log_checkpoint("analysis.forge_write.warning", function=capture.name, ea="0x%X" % capture.ea, error=str(exc))
            log_event(
                "forge.write.failed function=\"%s\" ea=0x%X error=\"%s\""
                % (_ascii_for_log(capture.name), capture.ea, _ascii_for_log(str(exc)))
            )
            plan.warnings.insert(0, "Forge file write failed: %s" % exc)
        session = _store_analysis_session(capture, plan, forge_path, forge_text)
        log_event(
            "analysis.done function=\"%s\" ea=0x%X fingerprint=%s renames=%d flow_rewrites=%d warnings=%d"
            % (
                _ascii_for_log(capture.name),
                capture.ea,
                session.fingerprint[:16],
                len(plan.active_renames()),
                len(plan.flow_rewrites),
                len(plan.warnings),
            )
        )
        return capture, plan


def export_current_function() -> dict[str, str]:
    with trace_scope("export_current_function"):
        capture, plan = analyze_current_function(purpose="export")
        _raise_if_task_cancelled("export", "before output directory")
        with trace_scope("export.output_dir"):
            output_dir = run_on_main_thread(_default_output_dir, write=False)
        _raise_if_task_cancelled("export", "before bundle write")
        with trace_scope("export.write_bundle", function=capture.name, output_dir=str(output_dir)):
            paths = write_export_bundle(output_dir, capture, plan, entrypoint="ida_interactive")
        log_event("export.done function=\"%s\" output_dir=\"%s\"" % (_ascii_for_log(capture.name), output_dir))
        return paths


def analyze_current_buffer_contract_case(
    command_value: int,
    capture: FunctionCapture | None = None,
    case_entry_ea: int | None = None,
) -> tuple[FunctionCapture, CleanPlan, str]:
    purpose = "buffer_contract_case"
    with trace_scope(purpose, command_value="0x%X" % command_value):
        _raise_if_task_cancelled(purpose, "before capture")
        if capture is None:
            with trace_scope("buffer_contract_case.capture"):
                capture, _cfunc = capture_current_function()
        _set_capture_source_path(capture)
        _raise_if_task_cancelled(purpose, "after capture")
        log_event(
            "buffer_contract_case.capture function=\"%s\" ea=0x%X case=0x%X"
            % (_ascii_for_log(capture.name), capture.ea, command_value)
        )
        with trace_scope("buffer_contract_case.initial_plan", function=capture.name, case="0x%X" % command_value):
            initial_plan = _build_plan_with_config(
                capture,
                task_name=purpose,
                force_deterministic=True,
                buffer_contract_case_values=[command_value],
                buffer_contract_helper_depth=1,
            )
        helper_names = _dedupe_helper_names(
            _helper_names_from_contracts(initial_plan)
            + helper_names_for_selected_case(capture, initial_plan, command_value)
        )
        log_event(
            "buffer_contract_case.helper_candidates function=\"%s\" ea=0x%X case=0x%X count=%d names=\"%s\""
            % (
                _ascii_for_log(capture.name),
                capture.ea,
                command_value,
                len(helper_names),
                ",".join(_ascii_for_log(name) for name in helper_names),
            )
        )
        _raise_if_task_cancelled(purpose, "after initial plan")
        helper_captures = _capture_buffer_contract_helpers(
            helper_names,
            caller_ea=capture.ea,
            max_depth=2,
            max_helpers=12,
        )
        _raise_if_task_cancelled(purpose, "after helper capture")
        disasm_slices = _capture_buffer_contract_case_disasm(capture, command_value, case_entry_ea)
        _raise_if_task_cancelled(purpose, "after disasm capture")
        with trace_scope("buffer_contract_case.deep_plan", helpers=len(helper_captures), case="0x%X" % command_value):
            plan = _build_plan_with_config(
                capture,
                task_name=purpose,
                force_deterministic=True,
                helper_captures=helper_captures,
                buffer_contract_case_values=[command_value],
                buffer_contract_helper_depth=2,
                buffer_contract_disasm_slices=disasm_slices,
            )
        text = _format_buffer_contract_case_preview(capture, plan, command_value, helper_captures, helper_names)
        log_event(
            "buffer_contract_case.done function=\"%s\" ea=0x%X case=0x%X contracts=%d helpers=%d"
            % (_ascii_for_log(capture.name), capture.ea, command_value, len(plan.buffer_contracts), len(helper_captures))
        )
        return capture, plan, text


def _store_analysis_session(
    capture: FunctionCapture,
    plan: CleanPlan,
    forge_path: Path | None,
    forge_text: str,
) -> PluginAnalysisSession:
    target_path = capture.source_path
    if not target_path:
        try:
            target_path = str(run_on_main_thread(_target_file_path, write=False))
        except Exception:
            target_path = ""
    session = PluginAnalysisSession.from_capture_plan(
        capture,
        plan,
        target_path=target_path,
        forge_path=forge_path,
        forge_text=forge_text,
    )
    _ANALYSIS_STATE.set(session)
    return session


def _session_matches_current_function(session: PluginAnalysisSession) -> bool:
    current = _current_function_identity()
    if current is None:
        log_checkpoint("analysis.session.current_missing", function=session.function_name, ea="0x%X" % session.function_ea)
        return False
    current_ea, current_name = current
    try:
        target_path = run_on_main_thread(_target_file_path, write=False)
    except Exception:
        target_path = None
    matches = session.matches_current(target_path, current_ea)
    log_checkpoint(
        "analysis.session.match",
        session_function=session.function_name,
        current_function=current_name,
        session_ea="0x%X" % session.function_ea,
        current_ea="0x%X" % current_ea,
        matched=matches,
    )
    return matches


class AnalyzeCurrentFunctionHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.analyze.activate.before")
        log_output("PseudoForge analysis is running. Please wait...")
        def on_success(result):
            log_checkpoint("action.analyze.on_success.before")
            capture, plan = result
            log_output(
                "PseudoForge analysis completed: 0x%X, %d rename(s), %d flow rewrite(s), %d warning(s)."
                % (capture.ea, len(plan.renames), len(plan.flow_rewrites), len(plan.warnings))
            )
            info(_format_analysis_summary(capture, plan))
            log_output("PseudoForge opening analysis preview.")
            _show_analysis_preview(capture, plan)
            log_checkpoint("action.analyze.on_success.after")

        run_background("analyze", analyze_current_function, on_success, group_name=PLUGIN_STATE_GROUP)
        log_checkpoint("action.analyze.activate.after")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class PreviewCurrentAnalyzedFunctionHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.preview_current_cached.activate.before")
        log_output("PseudoForge current analysis result requested. This does not call the LLM.")
        try:
            opened = _show_cached_forge_for_current_function()
        except Exception as exc:
            log_checkpoint("action.preview_current_cached.activate.failed", error=str(exc))
            warning("PseudoForge current analysis result failed: %s" % exc)
        else:
            if opened:
                log_output("PseudoForge current analysis result opened.")
            else:
                log_output("PseudoForge current analysis result was not opened.")
            log_checkpoint("action.preview_current_cached.activate.after", opened=opened)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ShowAnalyzedFunctionsHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.analyzed_functions.activate.before")
        log_output("PseudoForge analyzed functions chooser requested. This does not call the LLM.")
        try:
            opened = _show_analyzed_functions_for_current_target()
        except Exception as exc:
            log_checkpoint("action.analyzed_functions.activate.failed", error=str(exc))
            warning("PseudoForge analyzed functions chooser failed: %s" % exc)
        else:
            if opened:
                log_output("PseudoForge analyzed function preview opened.")
            else:
                log_output("PseudoForge analyzed functions chooser closed.")
            log_checkpoint("action.analyzed_functions.activate.after", opened=opened)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ExportCleanedPseudocodeHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.export.activate.before")
        log_output("PseudoForge export is running. Please wait...")
        def on_success(paths):
            log_checkpoint("action.export.on_success.before")
            log_output("PseudoForge export completed.")
            info("PseudoForge exported:\n" + "\n".join(paths.values()))
            log_checkpoint("action.export.on_success.after")

        run_background("export", export_current_function, on_success, group_name=PLUGIN_STATE_GROUP)
        log_checkpoint("action.export.activate.after")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class AnalyzeBufferContractCaseHandler(idaapi.action_handler_t if idaapi else object):
    def __init__(self, prompt_always: bool = False) -> None:
        self.prompt_always = prompt_always

    def activate(self, ctx):
        log_checkpoint("action.buffer_contract_case.activate.before", prompt=int(self.prompt_always))
        capture = None
        case_entry_ea = None
        if self.prompt_always:
            command_value = _ask_buffer_contract_case_value()
        else:
            case_entry_ea = _current_screen_ea()
            command_value, capture = _resolve_buffer_contract_case_from_cursor(ctx)
        if command_value is None:
            if self.prompt_always:
                info("PseudoForge buffer contract case analysis cancelled.")
                log_checkpoint("action.buffer_contract_case.cancelled")
            else:
                warning(
                    "PseudoForge could not resolve the switch case under the cursor. "
                    "Place the cursor inside a concrete case body or use "
                    "Analyze buffer contract by case value..."
                )
                log_checkpoint("action.buffer_contract_case.cursor_unresolved")
            return 1
        log_output("PseudoForge buffer contract deep analysis is running for case 0x%X." % command_value)

        def on_success(result):
            log_checkpoint("action.buffer_contract_case.on_success.before")
            capture, plan, text = result
            title = "PseudoForge buffer contract: %s case 0x%X" % (capture.name or "function", command_value)
            show_text_view(
                title,
                text,
                suggested_filename=build_save_as_filename("pseudoforge-buffer-contract", capture.name, capture.ea),
                copy_from_source=False,
                reference_text=capture.pseudocode,
                reference_title="Raw Hex-Rays pseudocode",
                content_title="PseudoForge buffer contract deep analysis",
                summary_text="PseudoForge analyzed case 0x%X: %d buffer contract(s)" % (
                    command_value,
                    len(plan.buffer_contracts),
                ),
            )
            log_output("PseudoForge buffer contract deep analysis completed for case 0x%X." % command_value)
            log_checkpoint("action.buffer_contract_case.on_success.after")

        run_background(
            "buffer-contract-case",
            lambda: analyze_current_buffer_contract_case(command_value, capture=capture, case_entry_ea=case_entry_ea),
            on_success,
            group_name=PLUGIN_STATE_GROUP,
        )
        log_checkpoint("action.buffer_contract_case.activate.after", case="0x%X" % command_value)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class CancelCurrentTaskHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.cancel.activate.before")
        task_name = request_group_cancel(PLUGIN_STATE_GROUP)
        if task_name:
            info(
                "PseudoForge cancellation requested for %s. "
                "The current decompiler or provider call may finish before the task stops."
                % task_name
            )
            log_checkpoint("action.cancel.activate.after", cancelled=task_name)
        else:
            info("No PseudoForge analyze/export/apply task is running.")
            log_checkpoint("action.cancel.activate.after", cancelled="")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ApplySelectedRenamesHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.apply.activate.before")
        try:
            running_task = active_group_task(PLUGIN_STATE_GROUP)
            if running_task:
                log_output("PseudoForge %s is already running. Please wait..." % running_task)
                log_checkpoint("action.apply.activate.skipped", running=running_task)
                return 1
            if _ANALYSIS_STATE.get() is None:
                log_checkpoint("action.apply.prepare_queued.before")
                log_output("PseudoForge apply requires analysis. Analysis is running. Please wait...")

                def on_success(result):
                    log_checkpoint("action.apply.prepare_success.before")
                    _apply_selected_renames_from_session()
                    log_checkpoint("action.apply.prepare_success.after")

                run_background(
                    "apply",
                    lambda: analyze_current_function(purpose="apply"),
                    on_success,
                    group_name=PLUGIN_STATE_GROUP,
                )
                log_checkpoint("action.apply.prepare_queued.after")
                return 1

            _apply_selected_renames_from_session()
        except Exception as exc:
            log_checkpoint("action.apply.activate.failed", error=str(exc))
            warning(f"PseudoForge apply failed: {exc}")
        else:
            log_checkpoint("action.apply.activate.after")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


def _apply_selected_renames_from_session() -> None:
    session = _ANALYSIS_STATE.get()
    if session is None:
        raise RuntimeError("No PseudoForge analysis result is available")
    if not _session_matches_current_function(session):
        message = (
            "PseudoForge apply refused: the current function no longer matches the analyzed function. "
            "Run Analyze current function again before applying renames."
        )
        warning(message)
        log_checkpoint("action.apply.stale_session", function=session.function_name, ea="0x%X" % session.function_ea)
        return

    log_checkpoint("action.apply.choose.before")
    selected = choose_renames(session.plan)
    log_checkpoint("action.apply.choose.after", selected=len(selected))
    if not selected:
        info("PseudoForge rename apply cancelled.")
        log_checkpoint("action.apply.cancelled")
        return

    log_checkpoint("action.apply.rename.before", selected=len(selected))
    current_lvars = None
    try:
        current_lvars = capture_current_lvars()
        known_lvar_names = [var.name for var in current_lvars if var.name] or None
    except Exception as exc:
        log_checkpoint("action.apply.current_lvars.warning", error=str(exc))
        if _selected_renames_have_identity(session.plan, selected):
            warning(
                "PseudoForge apply refused: current local variable identity could not be verified. "
                "Run Analyze current function again before applying identity-backed renames."
            )
            return
        known_lvar_names = [var.name for var in session.capture.lvars if var.name] or None
    result = apply_selected_renames(
        session.function_ea,
        session.plan,
        selected,
        known_lvar_names=known_lvar_names,
        captured_lvars=session.capture.lvars,
        current_lvars=current_lvars,
    )
    log_checkpoint("action.apply.rename.after", applied=len(result.applied), rejected=len(result.rejected))
    if result.rejected:
        log_output("PseudoForge rejected %d rename(s) during apply preflight." % len(result.rejected))
        warning("PseudoForge rejected rename(s):\n" + "\n".join(result.rejected[:8]))
    log_output("PseudoForge applied %d rename(s)." % len(result.applied))
    info("PseudoForge applied %d rename(s)." % len(result.applied))


def _selected_renames_have_identity(plan: CleanPlan, selected_old_names: list[str]) -> bool:
    selected = set(selected_old_names)
    return any(rename.old in selected and bool(rename.identity) for rename in plan.renames)


class ConfigureLlmHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.configure.activate.before")
        log_output("PseudoForge LLM configuration requested.")
        try:
            config = load_config()
            log_checkpoint("action.configure.ask.before")
            updated = ask_llm_config(config, warning)
            log_checkpoint("action.configure.ask.after", changed=updated is not None)
            if updated is None:
                info("PseudoForge LLM configuration unchanged.")
                log_output("PseudoForge LLM configuration unchanged.")
                log_checkpoint("action.configure.activate.after", changed=False)
                return 1
            log_checkpoint("action.configure.save.before")
            path = save_config(updated)
            log_checkpoint("action.configure.save.after", path=str(path))
            state = "enabled" if updated.llm.enabled else "disabled"
            info(
                "PseudoForge LLM rename assist %s.\nConfig: %s\n%s"
                % (state, path, format_llm_summary(updated.llm, updated))
            )
            log_output("PseudoForge LLM configuration saved.")
        except Exception as exc:
            log_checkpoint("action.configure.activate.failed", error=str(exc))
            warning(f"PseudoForge LLM configuration failed: {exc}")
        else:
            log_checkpoint("action.configure.activate.after", changed=True)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ConfigureProfileDirectoryHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.configure_profile.activate.before")
        log_output("PseudoForge profile directory configuration requested.")
        try:
            config = load_config()
            log_checkpoint("action.configure_profile.ask.before")
            selected = ask_profile_dir(config.profile_dir, warning)
            log_checkpoint("action.configure_profile.ask.after", changed=selected is not None)
            if selected is None:
                info("PseudoForge profile directory unchanged.")
                log_output("PseudoForge profile directory unchanged.")
                log_checkpoint("action.configure_profile.activate.after", changed=False)
                return 1
            config.profile_dir = selected
            log_checkpoint("action.configure_profile.apply.before", profile_dir=selected or "(default/env)")
            configure_profile_dir(config.profile_dir)
            log_checkpoint("action.configure_profile.save.before")
            path = save_config(config)
            log_checkpoint("action.configure_profile.save.after", path=str(path))
            info(
                "PseudoForge profile directory configured.\nConfig: %s\n%s"
                % (path, format_profile_summary(config.profile_dir))
            )
            log_output("PseudoForge profile directory configuration saved.")
        except Exception as exc:
            log_checkpoint("action.configure_profile.activate.failed", error=str(exc))
            warning(f"PseudoForge profile directory configuration failed: {exc}")
        else:
            log_checkpoint("action.configure_profile.activate.after", changed=True)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ConfigurePreviewModeHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.configure_preview.activate.before")
        log_output("PseudoForge preview mode configuration requested.")
        try:
            config = load_config()
            log_checkpoint("action.configure_preview.ask.before")
            updated = ask_preview_config(config, warning)
            log_checkpoint("action.configure_preview.ask.after", changed=updated is not None)
            if updated is None:
                info("PseudoForge preview mode unchanged.")
                log_output("PseudoForge preview mode unchanged.")
                log_checkpoint("action.configure_preview.activate.after", changed=False)
                return 1
            log_checkpoint("action.configure_preview.save.before")
            path = save_config(updated)
            log_checkpoint("action.configure_preview.save.after", path=str(path))
            info(
                "PseudoForge preview mode configured.\nConfig: %s\n%s"
                % (path, format_preview_summary(updated.preview))
            )
            log_output("PseudoForge preview mode configuration saved.")
        except Exception as exc:
            log_checkpoint("action.configure_preview.activate.failed", error=str(exc))
            warning(f"PseudoForge preview mode configuration failed: {exc}")
        else:
            log_checkpoint("action.configure_preview.activate.after", changed=True)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ShowSettingsHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.show_settings.activate.before")
        log_output("PseudoForge settings requested.")
        try:
            config = load_config()
            state = "enabled" if config.llm.enabled else "disabled"
            info(
                "PseudoForge settings\n"
                "Version: %s\n"
                "Config: %s\n"
                "%s\n"
                "%s\n"
                "%s\n"
                "LLM rename assist: %s\n"
                "%s"
                % (
                    VERSION,
                    _safe_config_path_text(),
                    format_profile_summary(config.profile_dir),
                    format_preview_summary(config.preview),
                    _current_source_context_summary(config.profile_dir),
                    state,
                    format_llm_summary(config.llm, config),
                )
            )
        except Exception as exc:
            log_checkpoint("action.show_settings.activate.failed", error=str(exc))
            warning(f"PseudoForge settings display failed: {exc}")
        else:
            log_checkpoint("action.show_settings.activate.after")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


def _default_output_dir() -> Path:
    if idaapi is not None:
        try:
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
            if idb_path:
                return Path(idb_path).with_suffix("").parent / "pseudoforge_out"
        except Exception:
            pass
    return Path.cwd() / "pseudoforge_out"


def _write_forge_snapshot(capture: FunctionCapture, plan: CleanPlan) -> tuple[Path, str]:
    target_path, forge_path = run_on_main_thread(_target_and_forge_paths, write=False)
    cleaned = _render_cleaned_with_direct_helper_aliases(capture, plan)
    forge_text = write_forge_function(forge_path, target_path, capture, plan, cleaned)
    log_event(
        "forge.write path=\"%s\" function=\"%s\" ea=0x%X chars=%d"
        % (_ascii_for_log(str(forge_path)), _ascii_for_log(capture.name), capture.ea, len(forge_text))
    )
    return forge_path, forge_text


def _render_cleaned_with_direct_helper_aliases(capture: FunctionCapture, plan: CleanPlan) -> str:
    aliases = _direct_runtime_helper_aliases(capture.pseudocode, capture)
    render_plan = _plan_without_runtime_helper_alias_warnings(plan, aliases)
    cleaned = render_cleaned_pseudocode(capture, render_plan)
    if not aliases:
        aliases = _direct_runtime_helper_aliases(cleaned, capture)
    if not aliases:
        return cleaned
    log_event(
        "analysis.helper_aliases function=\"%s\" ea=0x%X aliases=%s"
        % (_ascii_for_log(capture.name), capture.ea, _ascii_for_log(str(runtime_helper_alias_summary(aliases))))
    )
    return apply_runtime_helper_aliases(cleaned, aliases)


def _plan_without_runtime_helper_alias_warnings(plan: CleanPlan, aliases: dict[str, RuntimeHelperAlias]) -> CleanPlan:
    if not aliases or not plan.warnings:
        return plan
    filtered = [
        warning
        for warning in plan.warnings
        if not is_runtime_helper_alias_advisory(warning, aliases)
    ]
    if len(filtered) == len(plan.warnings):
        return plan
    return replace(plan, warnings=filtered)


def _direct_runtime_helper_aliases(cleaned: str, capture: FunctionCapture) -> dict[str, RuntimeHelperAlias]:
    def load_helper_text(call_name: str) -> str | None:
        try:
            helper_capture = capture_function_by_name(call_name)
        except Exception as exc:
            log_event(
                "analysis.helper_alias.capture_failed caller=\"%s\" callee=\"%s\" error=\"%s\""
                % (_ascii_for_log(capture.name), _ascii_for_log(call_name), _ascii_for_log(str(exc)))
            )
            return None
        if helper_capture is None or helper_capture.ea == capture.ea:
            return None
        try:
            helper_plan = build_clean_plan(helper_capture)
            return render_cleaned_pseudocode(helper_capture, helper_plan)
        except Exception as exc:
            log_event(
                "analysis.helper_alias.render_failed caller=\"%s\" callee=\"%s\" error=\"%s\""
                % (_ascii_for_log(capture.name), _ascii_for_log(call_name), _ascii_for_log(str(exc)))
            )
            return None

    return infer_direct_runtime_helper_aliases(
        cleaned,
        capture.name,
        load_helper_text,
        max_callees=_DIRECT_HELPER_ALIAS_MAX_CALLEES,
    )


def _set_capture_source_path(capture: FunctionCapture) -> None:
    if capture.source_path:
        if not capture.profile_context:
            capture.profile_context = profile_context_from_source_path(capture.source_path)
        return
    try:
        capture.source_path = str(run_on_main_thread(_target_file_path, write=False))
        capture.profile_context = profile_context_from_source_path(capture.source_path)
    except Exception:
        capture.source_path = ""
        capture.profile_context = {}


def _target_and_forge_paths() -> tuple[Path, Path]:
    target_path = _target_file_path()
    return target_path, target_path.with_suffix(".forge")


def _current_source_context_summary(configured_profile_dir: str) -> str:
    target_path = ""
    idb_path = ""
    if ida_nalt is not None or idaapi is not None:
        try:
            target_path = str(_target_file_path())
        except Exception:
            target_path = ""
        try:
            path = _idb_path()
            idb_path = str(path) if path is not None else ""
        except Exception:
            idb_path = ""
    return format_source_context_summary(
        source_path=target_path,
        idb_path=idb_path,
        configured_profile_dir=configured_profile_dir,
        active_profile_root=active_profile_root(),
    )


def _target_file_path() -> Path:
    raw_path = ""
    if ida_nalt is not None:
        try:
            raw_path = ida_nalt.get_input_file_path() or ""
        except Exception:
            raw_path = ""
    if not raw_path and idaapi is not None:
        getter = getattr(idaapi, "get_input_file_path", None)
        if callable(getter):
            try:
                raw_path = getter() or ""
            except Exception:
                raw_path = ""

    idb_path = _idb_path()
    if raw_path:
        target_path = Path(raw_path)
        if target_path.is_absolute():
            return target_path
        if idb_path is not None:
            return idb_path.parent / target_path.name
        return Path.cwd() / target_path.name
    if idb_path is not None:
        return idb_path
    return Path.cwd() / "pseudoforge.bin"


def _show_analyzed_functions_for_current_target() -> bool:
    log_event("preview.functions_menu.enter")
    try:
        _target_path, forge_path = _target_and_forge_paths()
    except Exception as exc:
        log_event("preview.functions_menu.unavailable error=\"%s\"" % _ascii_for_log(str(exc)))
        return False

    log_event(
        "preview.functions_menu.path path=\"%s\" exists=%d"
        % (_ascii_for_log(str(forge_path)), int(forge_path.exists()))
    )
    if not forge_path.exists():
        warning(
            "No cached PseudoForge analysis file was found for %s. Run Analyze current function first."
            % _target_path.name
        )
        log_event("preview.functions_menu.no_forge path=\"%s\"" % _ascii_for_log(str(forge_path)))
        return False

    try:
        text = forge_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        warning("PseudoForge failed to read cached analysis: %s" % exc)
        log_event(
            "preview.functions_menu.read_failed path=\"%s\" error=\"%s\""
            % (_ascii_for_log(str(forge_path)), _ascii_for_log(str(exc)))
        )
        return False

    opened = show_analyzed_functions_from_text(
        text,
        source_path=forge_path,
        target_stem=_target_path.stem,
        source_title="PseudoForge: %s analyzed functions" % forge_path.name,
    )
    log_event(
        "preview.functions_menu.show path=\"%s\" chars=%d opened=%d"
        % (_ascii_for_log(str(forge_path)), len(text), int(opened))
    )
    return opened


def _show_analysis_preview(capture: FunctionCapture, plan: CleanPlan) -> None:
    try:
        target_path, forge_path = _target_and_forge_paths()
    except Exception as exc:
        log_event("preview.analysis.unavailable error=\"%s\"" % _ascii_for_log(str(exc)))
        cleaned = _render_cleaned_with_direct_helper_aliases(capture, plan)
        show_text_view(
            "PseudoForge: %s 0x%X" % (capture.name, capture.ea),
            cleaned,
            suggested_filename=build_save_as_filename("pseudoforge", capture.name, capture.ea),
            copy_from_source=False,
            reference_text=capture.pseudocode,
            reference_title="Raw Hex-Rays pseudocode",
            content_title="PseudoForge cleaned pseudocode",
            summary_text=_format_analysis_summary(capture, plan),
        )
        return

    if side_by_side_preview_enabled():
        cleaned = _render_cleaned_with_direct_helper_aliases(capture, plan)
        target_stem = target_path.stem
        show_text_view(
            "PseudoForge: %s!%s 0x%X" % (target_stem, capture.name, capture.ea),
            cleaned,
            source_path=forge_path if forge_path.exists() else None,
            suggested_filename=build_save_as_filename(target_stem, capture.name, capture.ea),
            copy_from_source=False,
            target_stem=target_stem,
            reference_text=capture.pseudocode,
            reference_title="Raw Hex-Rays pseudocode",
            content_title="PseudoForge cleaned pseudocode",
            summary_text=_format_analysis_summary(capture, plan),
        )
        return

    session = _ANALYSIS_STATE.get()
    if (
        session is not None
        and session.function_ea == capture.ea
        and session.forge_text
        and _show_forge_section_text(target_path, forge_path, session.forge_text, capture.ea, capture.name)
    ):
        return

    if forge_path.exists():
        try:
            forge_text = forge_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            log_event(
                "preview.analysis.read_failed path=\"%s\" error=\"%s\""
                % (_ascii_for_log(str(forge_path)), _ascii_for_log(str(exc)))
            )
        else:
            if _show_forge_section_text(target_path, forge_path, forge_text, capture.ea, capture.name):
                return

    cleaned = _render_cleaned_with_direct_helper_aliases(capture, plan)
    target_stem = target_path.stem
    show_text_view(
        "PseudoForge: %s!%s 0x%X" % (target_stem, capture.name, capture.ea),
        cleaned,
        source_path=forge_path if forge_path.exists() else None,
        suggested_filename=build_save_as_filename(target_stem, capture.name, capture.ea),
        copy_from_source=False,
        target_stem=target_stem,
        reference_text=capture.pseudocode,
        reference_title="Raw Hex-Rays pseudocode",
        content_title="PseudoForge cleaned pseudocode",
        summary_text=_format_analysis_summary(capture, plan),
    )
    log_event(
        "preview.analysis.fallback function=\"%s\" ea=0x%X"
        % (_ascii_for_log(capture.name), capture.ea)
    )


def _show_cached_forge_for_current_function() -> bool:
    log_event("preview.cached_function.enter")
    try:
        target_path, forge_path = _target_and_forge_paths()
    except Exception as exc:
        log_event("preview.cached_function.unavailable error=\"%s\"" % _ascii_for_log(str(exc)))
        return False

    current = _current_function_identity()
    if current is None:
        warning("PseudoForge could not identify the current function.")
        log_event("preview.cached_function.no_current_function")
        return False

    current_ea, current_name = current
    if not forge_path.exists():
        warning(
            "No cached PseudoForge analysis file was found for %s. Run Analyze current function first."
            % target_path.name
        )
        log_event(
            "preview.cached_function.no_forge path=\"%s\" function=\"%s\" ea=0x%X"
            % (_ascii_for_log(str(forge_path)), _ascii_for_log(current_name), current_ea)
        )
        return False

    try:
        forge_text = forge_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        warning("PseudoForge failed to read cached analysis: %s" % exc)
        log_event(
            "preview.cached_function.read_failed path=\"%s\" error=\"%s\""
            % (_ascii_for_log(str(forge_path)), _ascii_for_log(str(exc)))
        )
        return False

    section = find_forge_function_section(forge_text, current_ea)
    if section is None:
        warning(
            "No cached PseudoForge analysis exists for %s 0x%X. Run Analyze current function first."
            % (current_name, current_ea)
        )
        log_event(
            "preview.cached_function.miss path=\"%s\" function=\"%s\" ea=0x%X"
            % (_ascii_for_log(str(forge_path)), _ascii_for_log(current_name), current_ea)
        )
        return False

    if _show_cached_side_by_side_section(
        target_path,
        forge_path,
        section,
        _ANALYSIS_STATE.get(),
        "preview.cached_function",
    ):
        return True

    _show_forge_section(target_path, forge_path, section, "preview.cached_function")
    return True


def _show_forge_section_text(
    target_path: Path,
    forge_path: Path,
    forge_text: str,
    function_ea: int,
    function_name: str,
) -> bool:
    section = find_forge_function_section(forge_text, function_ea)
    if section is None:
        log_event(
            "preview.section.miss path=\"%s\" function=\"%s\" ea=0x%X"
            % (_ascii_for_log(str(forge_path)), _ascii_for_log(function_name), function_ea)
        )
        return False
    _show_forge_section(target_path, forge_path, section, "preview.section")
    return True


def _show_forge_section(
    target_path: Path,
    forge_path: Path,
    section: ForgeFunctionSection,
    event_prefix: str,
) -> None:
    target_stem = target_path.stem
    title = "PseudoForge: %s!%s 0x%X" % (target_stem, section.name, section.ea)
    log_event(
        "%s.show.before title=\"%s\" function=\"%s\" ea=0x%X chars=%d"
        % (event_prefix, _ascii_for_log(title), _ascii_for_log(section.name), section.ea, len(section.text))
    )
    show_text_view(
        title,
        section.text,
        source_path=forge_path,
        suggested_filename=build_save_as_filename(target_stem, section.name, section.ea),
        copy_from_source=False,
        target_stem=target_stem,
    )
    log_event(
        "%s.show.after title=\"%s\" function=\"%s\" ea=0x%X"
        % (event_prefix, _ascii_for_log(title), _ascii_for_log(section.name), section.ea)
    )


def _show_cached_side_by_side_section(
    target_path: Path,
    forge_path: Path,
    section: ForgeFunctionSection,
    session: PluginAnalysisSession | None,
    event_prefix: str,
) -> bool:
    if not side_by_side_preview_enabled():
        return False
    raw_pseudocode = ""
    summary_text = ""
    raw_source = "none"
    if session is not None and session.matches_current(target_path, section.ea) and session.capture.pseudocode:
        raw_pseudocode = session.capture.pseudocode
        summary_text = _format_analysis_summary(session.capture, session.plan)
        raw_source = "session"
    elif section.raw_pseudocode:
        raw_pseudocode = section.raw_pseudocode
        summary_text = "PseudoForge cached analysis 0x%X: raw pseudocode loaded from .forge." % section.ea
        raw_source = "forge"

    if not raw_pseudocode:
        warning(
            "PseudoForge side-by-side preview needs stored raw Hex-Rays pseudocode. "
            "Opening the cached cleaned section only. Run Analyze current function once "
            "with this PseudoForge version to refresh the cached raw-vs-cleaned preview."
        )
        log_event(
            "%s.side_by_side.unavailable reason=\"missing_stored_raw_pseudocode\" function=\"%s\" ea=0x%X"
            % (event_prefix, _ascii_for_log(section.name), section.ea)
        )
        return False

    target_stem = target_path.stem
    title = "PseudoForge: %s!%s 0x%X" % (target_stem, section.name, section.ea)
    log_event(
        "%s.side_by_side.show.before title=\"%s\" function=\"%s\" ea=0x%X chars=%d raw_source=%s"
        % (
            event_prefix,
            _ascii_for_log(title),
            _ascii_for_log(section.name),
            section.ea,
            len(section.text),
            raw_source,
        )
    )
    show_text_view(
        title,
        section.text,
        source_path=forge_path,
        suggested_filename=build_save_as_filename(target_stem, section.name, section.ea),
        copy_from_source=False,
        target_stem=target_stem,
        reference_text=raw_pseudocode,
        reference_title="Raw Hex-Rays pseudocode",
        content_title="PseudoForge cleaned pseudocode",
        summary_text=summary_text,
    )
    log_event(
        "%s.side_by_side.show.after title=\"%s\" function=\"%s\" ea=0x%X"
        % (event_prefix, _ascii_for_log(title), _ascii_for_log(section.name), section.ea)
    )
    return True


def _idb_path() -> Path | None:
    if idaapi is None:
        return None
    try:
        path_text = idaapi.get_path(idaapi.PATH_TYPE_IDB)
    except Exception:
        return None
    if not path_text:
        return None
    return Path(path_text)


def _current_function_identity() -> tuple[int, str] | None:
    if ida_kernwin is None or ida_funcs is None:
        return None
    try:
        ea = ida_kernwin.get_screen_ea()
        function = ida_funcs.get_func(ea)
        if function is None:
            return None
        name = ida_funcs.get_func_name(function.start_ea) or "function"
        return int(function.start_ea), name
    except Exception:
        return None


def _current_screen_ea() -> int | None:
    if ida_kernwin is None or idaapi is None:
        return None
    try:
        ea = int(ida_kernwin.get_screen_ea())
    except Exception:
        return None
    try:
        if ea == int(idaapi.BADADDR):
            return None
    except Exception:
        pass
    return ea


def _capture_buffer_contract_case_disasm(
    capture: FunctionCapture,
    command_value: int,
    case_entry_ea: int | None,
) -> dict[int, object]:
    if case_entry_ea is None:
        log_checkpoint("buffer_contract_case.disasm_capture.entry_search", case="0x%X" % command_value)
    with trace_scope("buffer_contract_case.disasm_capture", function=capture.name, case="0x%X" % command_value):
        case_slice = capture_disasm_case_slice(
            capture.ea,
            command_value,
            entry_ea=case_entry_ea,
            max_blocks=32,
            max_instructions=512,
        )
    if case_slice is None:
        log_checkpoint("buffer_contract_case.disasm_capture.empty", case="0x%X" % command_value)
        return {}
    entry_ea = int(case_slice.entry_ea or case_entry_ea or 0)
    log_event(
        "buffer_contract_case.disasm_capture function=\"%s\" ea=0x%X case=0x%X entry=0x%X instructions=%d"
        % (
            _ascii_for_log(capture.name),
            capture.ea,
            command_value,
            entry_ea,
            len(case_slice.instructions),
        )
    )
    return {command_value: case_slice}


def _build_plan_with_config(
    capture: FunctionCapture,
    task_name: str = "",
    helper_captures: dict[str, FunctionCapture] | None = None,
    buffer_contract_case_values: list[int] | None = None,
    buffer_contract_helper_depth: int = 2,
    buffer_contract_disasm_slices: dict[int, object] | None = None,
    force_deterministic: bool = False,
) -> CleanPlan:
    log_checkpoint("build_plan.load_config.before", function=capture.name, ea="0x%X" % capture.ea)
    config = load_config()
    profile_root = _configure_profile_dir_for_analysis(config.profile_dir)
    log_checkpoint("build_plan.load_config.after", llm_enabled=config.llm.enabled, profile_root=str(profile_root))
    _raise_if_task_cancelled(task_name, "after config load")
    if force_deterministic or not config.llm.enabled:
        if force_deterministic and config.llm.enabled:
            log_output("PseudoForge targeted buffer contract analysis uses deterministic analysis only.")
        else:
            log_output("PseudoForge LLM rename assist is disabled. Running deterministic analysis only.")
        log_event(
            "llm.disabled function=\"%s\" ea=0x%X deterministic=true"
            % (_ascii_for_log(capture.name), capture.ea)
        )
        with trace_scope("build_plan.deterministic", function=capture.name, ea="0x%X" % capture.ea):
            plan = build_clean_plan(
                capture,
                helper_captures=helper_captures,
                buffer_contract_case_values=buffer_contract_case_values,
                buffer_contract_helper_depth=buffer_contract_helper_depth,
                buffer_contract_disasm_slices=buffer_contract_disasm_slices,
            )
        _raise_if_task_cancelled(task_name, "after deterministic plan")
        return plan

    provider_name = normalize_provider(config.llm.provider)
    log_output(
        "PseudoForge requesting LLM rename assist: %s model=%s."
        % (provider_label(provider_name), _ascii_for_log(config.llm.model))
    )
    log_event(
        "llm.request provider=%s model=\"%s\" function=\"%s\" ea=0x%X timeout=%d"
        % (
            provider_name,
            _ascii_for_log(config.llm.model),
            _ascii_for_log(capture.name),
            capture.ea,
            config.llm.timeout_seconds,
        )
    )
    with trace_scope("build_plan.provider_factory", provider=provider_name, model=config.llm.model):
        provider = build_rename_provider(
            config.llm,
            api_key=get_provider_api_key(config, config.llm.provider) if provider_requires_api_key(provider_name) else "",
        )
    _raise_if_task_cancelled(task_name, "before llm provider")

    try:
        with trace_scope("build_plan.llm", provider=provider_name, model=config.llm.model, function=capture.name):
            plan = build_clean_plan(
                capture,
                rename_provider=provider,
                helper_captures=helper_captures,
                buffer_contract_case_values=buffer_contract_case_values,
                buffer_contract_helper_depth=buffer_contract_helper_depth,
                buffer_contract_disasm_slices=buffer_contract_disasm_slices,
            )
        _raise_if_task_cancelled(task_name, "after llm provider")
        log_event(
            "llm.plan.done provider=%s model=\"%s\" renames=%d warnings=%d"
            % (
                provider_name,
                _ascii_for_log(config.llm.model),
                len(plan.active_renames()),
                len(plan.warnings),
            )
        )
        log_output(
            "PseudoForge LLM rename assist completed: %d rename(s), %d warning(s)."
            % (len(plan.active_renames()), len(plan.warnings))
        )
        return plan
    except CancellationRequested:
        raise
    except Exception as exc:
        failure_summary = summarize_llm_failure(exc)
        fallback_warning = format_llm_fallback_warning(exc)
        failure_class = "cyber_policy_block" if is_llm_provider_cyber_policy_block(exc) else "provider_failure"
        log_event(
            "llm.failed provider=%s model=\"%s\" function=\"%s\" class=%s error=\"%s\""
            % (
                provider_name,
                _ascii_for_log(config.llm.model),
                _ascii_for_log(capture.name),
                failure_class,
                _ascii_for_log(str(exc)),
            )
        )
        if is_llm_provider_cyber_policy_block(exc):
            log_output(
                "PseudoForge LLM rename assist blocked by provider cyber policy; "
                "deterministic fallback will be used. Reason: %s" % failure_summary
            )
        else:
            log_output(
                "PseudoForge LLM rename assist failed; deterministic fallback will be used. Reason: %s"
                % failure_summary
            )
        with trace_scope("build_plan.fallback", function=capture.name, ea="0x%X" % capture.ea):
            plan = build_clean_plan(
                capture,
                helper_captures=helper_captures,
                buffer_contract_case_values=buffer_contract_case_values,
                buffer_contract_helper_depth=buffer_contract_helper_depth,
                buffer_contract_disasm_slices=buffer_contract_disasm_slices,
            )
        _raise_if_task_cancelled(task_name, "after fallback plan")
        plan.warnings.insert(0, fallback_warning)
        return plan


def _configure_profile_dir_for_analysis(profile_dir: str) -> Path:
    selected = _resolve_configured_profile_dir(profile_dir)
    if str(selected) == active_profile_root():
        return selected
    return configure_profile_dir(profile_dir)


def _resolve_configured_profile_dir(profile_dir: str) -> Path:
    path_text = str(profile_dir or "").strip()
    raw_path = path_text if path_text else os.environ.get("PSEUDOFORGE_PROFILE_DIR", "").strip()
    return Path(raw_path).expanduser() if raw_path else DEFAULT_PROFILE_DIR


def _format_analysis_summary(capture: FunctionCapture, plan: CleanPlan) -> str:
    lines = [
        "PseudoForge analyzed 0x%X: %d rename(s), %d flow rewrite(s), %d warning(s)"
        % (capture.ea, len(plan.renames), len(plan.flow_rewrites), len(plan.warnings))
    ]
    rule_summary = format_rule_report_summary(plan.rule_report, include_error_details=True)
    if rule_summary:
        lines.append(rule_summary)
    domain_summary = format_domain_identity_summary(plan)
    if domain_summary:
        lines.append(domain_summary)
    function_identity_summary = format_function_identity_candidate_summary(plan)
    if function_identity_summary:
        lines.append(function_identity_summary)
    type_summary = format_parameter_type_correction_summary(plan)
    if type_summary:
        lines.extend(type_summary)
    if plan.warnings:
        lines.append("")
        lines.append("Warnings:")
        for item in plan.warnings[:8]:
            lines.append("- %s" % _format_warning(item))
        if len(plan.warnings) > 8:
            lines.append("- ... %d more warning(s)" % (len(plan.warnings) - 8))
    return "\n".join(lines)


def _format_warning(item: object) -> str:
    if isinstance(item, dict):
        message = str(item.get("message", "")).strip()
        if message:
            return message
        old = str(item.get("old", "")).strip()
        reason = str(item.get("reason", "")).strip()
        if old and reason:
            return "Potential bad call target %s: %s" % (old, reason)
    return str(item)


def _resolve_buffer_contract_case_from_cursor(ctx) -> tuple[int | None, FunctionCapture | None]:
    line_index, line_text = _current_pseudocode_cursor_location(ctx)
    value = find_case_value_near_line("", line_text=line_text)
    if value is not None:
        log_checkpoint("buffer_contract_case.cursor.resolved_line", case="0x%X" % value)
        return value, None
    if line_index < 0:
        log_checkpoint("buffer_contract_case.cursor.no_line")
        return None, None
    try:
        capture, _cfunc = capture_current_function()
        _set_capture_source_path(capture)
    except Exception as exc:
        log_checkpoint("buffer_contract_case.cursor.capture_failed", error=str(exc))
        return None, None
    value = find_case_value_near_line(capture.pseudocode, line_index=line_index, line_text=line_text)
    if value is None:
        log_checkpoint("buffer_contract_case.cursor.unresolved", line=line_index)
        return None, capture
    log_checkpoint("buffer_contract_case.cursor.resolved_context", line=line_index, case="0x%X" % value)
    return value, capture


def _current_pseudocode_cursor_location(ctx) -> tuple[int, str]:
    if ida_kernwin is None:
        return -1, ""
    widget = _context_widget(ctx)
    if widget is None:
        for getter_name in ("get_current_viewer", "get_current_widget"):
            getter = getattr(ida_kernwin, getter_name, None)
            if not callable(getter):
                continue
            try:
                widget = getter()
            except Exception:
                widget = None
            if widget is not None:
                break
    line_index, line_text = _hexrays_viewer_cursor_location(widget)
    if line_index >= 0 or line_text:
        return line_index, line_text
    line_text = _current_viewer_line_text(widget)
    line_index = _current_viewer_line_index(widget)
    return line_index, line_text


def _context_widget(ctx) -> object | None:
    if ctx is None:
        return None
    for attr in ("widget", "form", "viewer"):
        try:
            value = getattr(ctx, attr, None)
        except Exception:
            continue
        if value is not None:
            return value
    return None


def _hexrays_viewer_cursor_location(widget) -> tuple[int, str]:
    if ida_hexrays is None or widget is None:
        return -1, ""
    getter = getattr(ida_hexrays, "get_widget_vdui", None)
    if not callable(getter):
        return -1, ""
    try:
        vdui = getter(widget)
    except Exception:
        return -1, ""
    if vdui is None:
        return -1, ""
    line_index = _line_index_from_place(getattr(vdui, "cpos", None))
    line_text = _pseudocode_line_from_vdui(vdui, line_index)
    return line_index, line_text


def _pseudocode_line_from_vdui(vdui, line_index: int) -> str:
    if line_index < 0:
        return ""
    cfunc = getattr(vdui, "cfunc", None)
    getter = getattr(cfunc, "get_pseudocode", None)
    if not callable(getter):
        return ""
    try:
        pseudocode = getter()
        line = pseudocode[line_index]
    except Exception:
        return ""
    raw = getattr(line, "line", line)
    return _strip_ida_tags(raw)


def _current_viewer_line_text(widget) -> str:
    getter = getattr(ida_kernwin, "get_custom_viewer_curline", None) if ida_kernwin is not None else None
    if not callable(getter) or widget is None:
        return ""
    for mouse in (True, False):
        try:
            line = getter(widget, mouse)
        except Exception:
            continue
        if line:
            return _strip_ida_tags(line)
    return ""


def _current_viewer_line_index(widget) -> int:
    getter = getattr(ida_kernwin, "get_custom_viewer_place", None) if ida_kernwin is not None else None
    if not callable(getter) or widget is None:
        return -1
    for mouse in (True, False):
        try:
            place_info = getter(widget, mouse)
        except Exception:
            continue
        place = place_info[0] if isinstance(place_info, tuple) and place_info else place_info
        line_index = _line_index_from_place(place)
        if line_index >= 0:
            return line_index
    return -1


def _line_index_from_place(place) -> int:
    if place is None:
        return -1
    for attr in ("lnnum", "line", "n", "num"):
        try:
            value = getattr(place, attr, None)
        except Exception:
            continue
        if callable(value):
            try:
                value = value()
            except Exception:
                continue
        try:
            number = int(value)
        except Exception:
            continue
        if number >= 0:
            return number
    return -1


def _strip_ida_tags(text: object) -> str:
    result = str(text or "")
    for owner in (idaapi, ida_kernwin):
        remover = getattr(owner, "tag_remove", None) if owner is not None else None
        if not callable(remover):
            continue
        try:
            result = str(remover(result))
        except Exception:
            continue
    return result


def _ask_buffer_contract_case_value() -> int | None:
    if ida_kernwin is None:
        return None
    asker = getattr(ida_kernwin, "ask_str", None)
    if not callable(asker):
        return None
    try:
        text = asker("0x0", 0, "PseudoForge command/case value for buffer contract analysis")
    except Exception as exc:
        log_checkpoint("buffer_contract_case.ask.failed", error=str(exc))
        return None
    value = _parse_buffer_contract_case_value(text)
    if value is None and text:
        warning("PseudoForge could not parse case value: %s" % text)
    return value


def _parse_buffer_contract_case_value(text: str | None) -> int | None:
    if text is None:
        return None
    return parse_c_integer_literal(str(text).strip())


def _helper_names_from_contracts(plan: CleanPlan) -> list[str]:
    result: list[str] = []
    seen = set()
    for contract in plan.buffer_contracts:
        for edge in contract.helper_edges:
            if edge.callee and edge.callee not in seen:
                seen.add(edge.callee)
                result.append(edge.callee)
    return result


def _dedupe_helper_names(names: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for name in names:
        if not name or name in seen:
            continue
        seen.add(name)
        result.append(name)
    return result


def _capture_buffer_contract_helpers(
    helper_names: list[str],
    caller_ea: int,
    max_depth: int,
    max_helpers: int,
) -> dict[str, FunctionCapture]:
    result: dict[str, FunctionCapture] = {}
    queue = [(name, 1) for name in helper_names if name]
    seen = set()
    while queue and len(result) < max_helpers:
        name, depth = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        try:
            helper_capture = capture_function_by_name(name)
        except Exception as exc:
            log_checkpoint("buffer_contract_case.helper.capture_failed", helper=name, error=str(exc))
            continue
        if helper_capture is None or helper_capture.ea == caller_ea:
            continue
        result[name] = helper_capture
        if depth >= max_depth:
            continue
        for call_name in helper_capture.calls:
            if call_name not in seen:
                queue.append((call_name, depth + 1))
    return result


def _format_buffer_contract_case_preview(
    capture: FunctionCapture,
    plan: CleanPlan,
    command_value: int,
    helper_captures: dict[str, FunctionCapture],
    helper_candidates: list[str] | None = None,
) -> str:
    contracts = [contract for contract in plan.buffer_contracts if contract.command_value == command_value]
    report = render_buffer_contract_report(capture, contracts)
    context_report = render_case_context_report(capture, plan, command_value)
    header = render_buffer_struct_header(capture, contracts)
    lines = [
        "# PseudoForge Buffer Contract Deep Analysis",
        "",
        "- Function: `%s`" % (capture.name or "function"),
        "- EA: `0x%X`" % capture.ea,
        "- Case: `0x%X`" % command_value,
        "- Contracts: `%d`" % len(contracts),
        "- Helper candidates: `%d`" % len(helper_candidates or []),
        "- Helper captures: `%d`" % len(helper_captures),
        "",
    ]
    if helper_candidates:
        lines.append("Helper candidate set:")
        lines.append("")
        for name in helper_candidates:
            suffix = "" if name in helper_captures else " (capture unavailable)"
            lines.append("- `%s`%s" % (name, suffix))
        lines.append("")
    if helper_captures:
        lines.append("Helper capture set:")
        lines.append("")
        for name in sorted(helper_captures):
            lines.append("- `%s`" % name)
        lines.append("")
        unlinked_helpers = _unlinked_helper_capture_names(contracts, helper_captures)
        if unlinked_helpers:
            lines.append("Captured helpers not linked to selected buffer path:")
            lines.append("")
            for name in unlinked_helpers:
                lines.append("- `%s`" % name)
            lines.append("")
    lines.append(report.rstrip())
    lines.append("")
    if context_report:
        lines.append(context_report.rstrip())
        lines.append("")
    lines.append("# C++ Struct Sketch")
    lines.append("")
    lines.append(header.rstrip())
    lines.append("")
    return "\n".join(lines)


def _unlinked_helper_capture_names(
    contracts: list[object],
    helper_captures: dict[str, FunctionCapture],
) -> list[str]:
    linked: set[str] = set()
    for contract in contracts:
        for edge in getattr(contract, "helper_edges", []):
            _collect_linked_helper_names(edge, linked)
    return [name for name in sorted(helper_captures) if name not in linked]


def _collect_linked_helper_names(edge: object, linked: set[str]) -> None:
    callee = getattr(edge, "callee", "")
    if callee:
        linked.add(callee)
    for nested in getattr(edge, "nested_edges", []):
        _collect_linked_helper_names(nested, linked)


def _raise_if_task_cancelled(task_name: str, phase: str) -> None:
    if not task_name:
        return
    try:
        raise_if_cancelled(task_name)
    except CancellationRequested:
        log_checkpoint("task.cancelled", task=task_name, phase=phase)
        raise


def _ascii_for_log(message: str) -> str:
    return message.encode("ascii", errors="replace").decode("ascii")


def _safe_config_path_text() -> str:
    try:
        from ida_pseudoforge.config import get_config_path

        return str(get_config_path())
    except Exception:
        return "(unavailable)"

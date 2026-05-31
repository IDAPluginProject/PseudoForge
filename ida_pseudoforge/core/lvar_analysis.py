from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ida_pseudoforge.core.cleanup_rewriter import classify_cleanup_labels
from ida_pseudoforge.core.api_semantics import FUNCTION_PARAMETER_NAMES, LOCAL_NAME_RULES
from ida_pseudoforge.core.deterministic.context import build_rule_context
from ida_pseudoforge.core.deterministic.emitters import emissions_to_comments, emissions_to_renames
from ida_pseudoforge.core.deterministic.engine import RuleEngine
from ida_pseudoforge.core.deterministic.loader import load_default_rule_packs
from ida_pseudoforge.core.deterministic.schema import RuleReport
from ida_pseudoforge.core.flow_recovery import recover_flow
from ida_pseudoforge.core.kernel_api import kernel_function_metadata
from ida_pseudoforge.core.kernel_semantics import (
    callback_registration_parameter_names,
    driver_dispatch_parameter_names,
    driver_entry_parameter_names,
    kernel_comments,
    kernel_rename_suggestions,
    kernel_warnings,
    registry_callback_parameter_names,
)
from ida_pseudoforge.core.llm_assist import suggest_renames_with_provider
from ida_pseudoforge.core.normalize import (
    extract_function_name,
    extract_parameters_from_signature,
    safe_identifier_replace,
)
from ida_pseudoforge.core.pattern_renames import pattern_renames
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture, RenameSuggestion
from ida_pseudoforge.core.validation import validate_renames


def build_clean_plan(
    capture: FunctionCapture,
    rename_provider: Any | None = None,
    rule_dirs: list[str | Path] | None = None,
) -> CleanPlan:
    rule_report = RuleReport()
    rule_engine = _build_rule_engine(rule_report, rule_dirs, capture)
    suggestions = []
    suggestions.extend(_parameter_renames(capture, include_generic=rename_provider is None))
    suggestions.extend(_local_rule_renames(capture))
    suggestions.extend(pattern_renames(capture))
    suggestions.extend(kernel_rename_suggestions(capture))
    suggestions.extend(_rule_rename_suggestions(capture, rule_engine, rule_report))
    llm_warnings = []
    if rename_provider is not None:
        llm_suggestions, llm_warnings = suggest_renames_with_provider(capture, rename_provider)
        suggestions.extend(llm_suggestions)
    suggestions = _dedupe_suggestions(suggestions)
    validated, warnings = validate_renames(capture, suggestions)
    _attach_rename_identities(validated, capture)
    rename_map = {item.old: item.new for item in validated if item.apply}
    flow_rewrites = recover_flow(capture, rename_map=rename_map)
    cleanup_labels = classify_cleanup_labels(capture)
    comments = _dedupe_comments(
        kernel_comments(capture, rename_map)
        + _rule_semantic_comments(capture, rename_map, rule_engine, rule_report)
    )
    _rule_call_arg_rewrite_report(capture, rename_map, rule_engine, rule_report)
    combined_warnings = _dedupe_warnings(
        _filter_shadowed_rename_warnings(
            kernel_warnings(capture) + llm_warnings + warnings + _rule_report_warnings(rule_report),
            validated,
        )
    )

    return CleanPlan(
        function_ea=capture.ea,
        function_name=capture.name,
        input_fingerprint=capture.input_fingerprint(),
        renames=validated,
        flow_rewrites=flow_rewrites,
        cleanup_labels=cleanup_labels,
        comments=comments,
        warnings=combined_warnings,
        rule_report=rule_report.to_dict(),
    )


def _build_rule_engine(
    report: RuleReport,
    rule_dirs: list[str | Path] | None,
    capture: FunctionCapture,
) -> RuleEngine:
    packs = load_default_rule_packs(
        extra_dirs=rule_dirs,
        project_root=_project_root_from_capture_source(capture),
        report=report,
    )
    return RuleEngine(packs)


def _project_root_from_capture_source(capture: FunctionCapture) -> Path | None:
    source_path = str(capture.source_path or "").strip()
    if not source_path:
        return None
    path = Path(source_path)
    if path.suffix:
        return path.parent
    return path


def _rule_rename_suggestions(
    capture: FunctionCapture,
    engine: RuleEngine,
    report: RuleReport,
) -> list[RenameSuggestion]:
    result = engine.run(
        build_rule_context(capture, profile_function_lookup=kernel_function_metadata),
        phases={"rename"},
        report=report,
    )
    return emissions_to_renames(result.emissions)


def _rule_semantic_comments(
    capture: FunctionCapture,
    rename_map: dict[str, str],
    engine: RuleEngine,
    report: RuleReport,
) -> list[dict[str, Any]]:
    text = safe_identifier_replace(capture.pseudocode, rename_map)
    result = engine.run(
        build_rule_context(capture, text=text, profile_function_lookup=kernel_function_metadata),
        phases={"semantic_comment"},
        report=report,
    )
    return emissions_to_comments(result.emissions)


def _rule_call_arg_rewrite_report(
    capture: FunctionCapture,
    rename_map: dict[str, str],
    engine: RuleEngine,
    report: RuleReport,
) -> None:
    text = safe_identifier_replace(capture.pseudocode, rename_map)
    engine.run(
        build_rule_context(capture, text=text, profile_function_lookup=kernel_function_metadata),
        phases={"call_arg_rewrite"},
        report=report,
    )


def _parameter_renames(capture: FunctionCapture, include_generic: bool = True) -> list[RenameSuggestion]:
    function_name = capture.name or extract_function_name(capture.prototype)
    explicit_names = FUNCTION_PARAMETER_NAMES.get(function_name, [])
    if not explicit_names:
        explicit_names = driver_entry_parameter_names(capture)
    if not explicit_names:
        explicit_names = driver_dispatch_parameter_names(capture)
    if not explicit_names:
        explicit_names = callback_registration_parameter_names(capture)
    if not explicit_names:
        explicit_names = registry_callback_parameter_names(capture)
    if not explicit_names:
        explicit_names = _callback_parameter_names(capture, function_name)
    params = extract_parameters_from_signature(capture.prototype)
    suggestions = []

    for index, (old_name, type_text) in enumerate(params):
        new_name = ""
        if index < len(explicit_names):
            new_name = explicit_names[index]
        elif "SYSTEM_INFORMATION_CLASS" in type_text:
            new_name = "systemInformationClass"
        elif "Length" in old_name or "ULONG" in type_text and index >= 2:
            new_name = "inputLength"
        elif include_generic and old_name.startswith("a"):
            new_name = f"argument{index}"

        if new_name and old_name != new_name:
            suggestions.append(
                RenameSuggestion(
                    kind="arg",
                    old=old_name,
                    new=new_name,
                    confidence=0.99 if explicit_names else 0.82,
                    source="prototype",
                    evidence=f"Parameter {index} inferred from prototype",
                )
            )

    return suggestions


def _callback_parameter_names(capture: FunctionCapture, function_name: str) -> list[str]:
    if _looks_like_object_pre_operation_callback(capture, function_name):
        if function_name.endswith("ObjectPreOperation") or _has_known_ob_pre_operation_signature(capture):
            return ["registrationContext", "preOperationInfo"]
        return ["", "preOperationInfo"]
    return []


def _looks_like_object_pre_operation_callback(capture: FunctionCapture, function_name: str) -> bool:
    if function_name.endswith("ObjectPreOperation"):
        return True
    if _has_known_ob_pre_operation_signature(capture):
        return True
    params = extract_parameters_from_signature(capture.prototype)
    if len(params) != 2:
        return False
    operation_info = params[1][0]
    return _has_ob_pre_operation_field_evidence(capture.pseudocode, operation_info)


def _has_known_ob_pre_operation_signature(capture: FunctionCapture) -> bool:
    prototype = capture.prototype or ""
    if "OB_PREOP_CALLBACK_STATUS" in prototype and "PRE_OPERATION" in prototype:
        return True
    return False


def _has_ob_pre_operation_field_evidence(text: str, variable: str) -> bool:
    escaped = re.escape(variable)
    operation_check = re.search(
        r"\*\(_DWORD\s+\*\)\s*%s\b\s*==\s*[12]\b" % escaped,
        text,
    )
    desired_access_load = re.search(
        r"\*\(_DWORD\s+\*\)\(\s*(?:\*\(_QWORD\s+\*\)\(\s*%s\s*\+\s*32(?:LL|i64|L)?\s*\)|"
        r"\*\(\(_QWORD\s+\*\)\s*%s\s*\+\s*4\s*\))\s*\+\s*4(?:LL|i64|L)?\s*\)"
        % (escaped, escaped),
        text,
    )
    object_load = re.search(
        r"\*\(\(\s*PEPROCESS\s+\*\s*\)\s*%s\s*\+\s*1\s*\)" % escaped,
        text,
    )
    return bool(operation_check and (desired_access_load or object_load))


def _local_rule_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    suggestions = []
    for var in capture.lvars:
        rule = LOCAL_NAME_RULES.get(var.name)
        if not rule:
            continue
        new_name, confidence, evidence = rule
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=var.name,
                new=new_name,
                confidence=confidence,
                source="semantic-rule",
                evidence=evidence,
            )
        )
    return suggestions


def _dedupe_suggestions(suggestions: list[RenameSuggestion]) -> list[RenameSuggestion]:
    best: dict[str, RenameSuggestion] = {}
    for suggestion in suggestions:
        current = best.get(suggestion.old)
        if current is None or _suggestion_rank(suggestion) > _suggestion_rank(current):
            best[suggestion.old] = suggestion
    return list(best.values())


def _attach_rename_identities(renames: list[RenameSuggestion], capture: FunctionCapture) -> None:
    identities = {var.name: var.identity for var in capture.lvars if var.name and var.identity}
    for rename in renames:
        if rename.identity:
            continue
        if (rename.kind or "").lower() not in {"arg", "lvar", "local", "param", "parameter", "argument"}:
            continue
        identity = identities.get(rename.old, "")
        if identity:
            rename.identity = identity


def _suggestion_rank(suggestion: RenameSuggestion) -> tuple[int, float]:
    return (_source_priority(suggestion.source), suggestion.confidence)


def _source_priority(source: str) -> int:
    priorities = {
        "prototype": 100,
        "kernel-irp-stack": 97,
        "kernel-status": 96,
        "kernel-driver-entry": 96,
        "kernel-driver-dispatch": 96,
        "kernel-callback-registration": 96,
        "kernel-registry-callback": 96,
        "kernel-mm-probe": 96,
        "kernel-zw-probe": 96,
        "kernel-list": 95,
        "kernel-pool": 94,
        "semantic-rule": 90,
        "pattern": 80,
        "rule": 70,
        "llm": 50,
    }
    return priorities.get(source, 40)


def _dedupe_warnings(warnings: list[str]) -> list[str]:
    result = []
    seen = set()
    for warning in warnings:
        key = str(warning)
        if key in seen:
            continue
        seen.add(key)
        result.append(warning)
    return result


def _dedupe_comments(comments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen = set()
    for comment in comments:
        key = (
            str(comment.get("kind", "")),
            str(comment.get("text", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(comment)
    return result


def _rule_report_warnings(report: RuleReport) -> list[str]:
    warnings = []
    for item in report.load_errors:
        path = item.get("path", "")
        error = item.get("error", "")
        warnings.append("Deterministic rule pack rejected: %s: %s" % (path, error))
    for item in report.rejected_emissions:
        rule_id = item.get("rule_id", "")
        reason = item.get("reason", "")
        warnings.append("Deterministic rule emission rejected: %s: %s" % (rule_id, reason))
    return warnings


def _filter_shadowed_rename_warnings(
    warnings: list[str],
    renames: list[RenameSuggestion],
) -> list[str]:
    accepted_pairs = {(item.old, item.new) for item in renames if item.apply}
    accepted_olds = {item.old for item in renames if item.apply}
    accepted_targets = {item.new for item in renames if item.apply}
    if not accepted_pairs:
        return warnings
    result = []
    for warning in warnings:
        pair = _skipped_rename_warning_pair(warning)
        if pair:
            if pair in accepted_pairs or pair[0] in accepted_olds:
                continue
        duplicate_target = _skipped_duplicate_target_warning(warning)
        if duplicate_target and duplicate_target in accepted_targets:
            continue
        result.append(warning)
    return result


def _skipped_rename_warning_pair(warning: str) -> tuple[str, str] | None:
    match = re.match(
        r"^Skipped .+ rename (?P<old>[A-Za-z_][A-Za-z0-9_]*)->(?P<new>[A-Za-z_][A-Za-z0-9_]*)\b",
        str(warning),
    )
    if not match:
        return None
    return match.group("old"), match.group("new")


def _skipped_duplicate_target_warning(warning: str) -> str:
    match = re.match(r"^Skipped duplicate target (?P<new>[A-Za-z_][A-Za-z0-9_]*)\b", str(warning))
    if not match:
        return ""
    return match.group("new")

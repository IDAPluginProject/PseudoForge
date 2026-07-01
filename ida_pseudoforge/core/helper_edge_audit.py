from __future__ import annotations

import re
from collections import Counter
from functools import lru_cache
from typing import Any

from ida_pseudoforge.core.plan_schema import CommandBufferContract, HelperContractEdge
from ida_pseudoforge.profiles.loader import load_kernel_api_family


def helper_edge_audit_records(contracts: list[CommandBufferContract]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for contract in contracts:
        primary_buffers = _contract_primary_buffers(contract)
        for path, edge, covered_by_ancestor in _iter_edges_with_context(contract.helper_edges):
            record = classify_helper_edge(
                edge,
                covered_by_ancestor_contract=covered_by_ancestor,
                primary_buffers=primary_buffers,
            )
            record.update(
                {
                    "command_value": contract.command_value,
                    "command": "0x%X" % contract.command_value,
                    "command_name": contract.command_name,
                    "path": path,
                }
            )
            records.append(record)
    return records


def helper_edge_class_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(record.get("classification", "unknown")) for record in records)
    return dict(sorted(counts.items()))


def unresolved_helper_edge_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [record for record in records if not bool(record.get("resolved", False))]


def blocking_unresolved_helper_edge_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [record for record in records if bool(record.get("blocks_recovery", False))]


def helper_path_family_records(contracts: list[CommandBufferContract]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for contract in contracts:
        primary_buffers = _contract_primary_buffers(contract)
        for index, edge in enumerate(contract.helper_edges):
            audit = [
                classify_helper_edge(
                    item,
                    covered_by_ancestor_contract=covered_by_ancestor,
                    primary_buffers=primary_buffers,
                )
                for _path, item, covered_by_ancestor in _iter_edges_with_context([edge])
            ]
            metrics = _edge_tree_metrics(edge, primary_buffers=primary_buffers)
            root = classify_helper_edge(edge, primary_buffers=primary_buffers)
            records.append(
                {
                    "command_value": contract.command_value,
                    "command": "0x%X" % contract.command_value,
                    "command_name": contract.command_name,
                    "family_id": "%s:%d:%s" % ("0x%X" % contract.command_value, index, edge.callee),
                    "root_callee": edge.callee,
                    "root_classification": root["classification"],
                    "root_resolved": root["resolved"],
                    "passed_buffers": list(edge.passed_buffers),
                    "edge_count": metrics["edge_count"],
                    "unresolved_edges": metrics["unresolved_edges"],
                    "blocking_unresolved_edges": metrics["blocking_unresolved_edges"],
                    "size_constraints": metrics["size_constraints"],
                    "field_accesses": metrics["field_accesses"],
                    "field_constraints": metrics["field_constraints"],
                    "warnings": metrics["warnings"],
                    "class_counts": helper_edge_class_counts(audit),
                }
            )
    return records


def classify_helper_edge(
    edge: HelperContractEdge,
    *,
    covered_by_ancestor_contract: bool = False,
    primary_buffers: set[str] | None = None,
) -> dict[str, Any]:
    warnings = [str(item) for item in edge.warnings if str(item)]
    warning_text = " ".join(warnings).lower()
    callee = edge.callee or ""
    evidence = edge.evidence or ""
    indirect_target = _indirect_target_from_warnings(warnings)
    indirect_target_candidates = _indirect_target_candidates_from_warnings(warnings)
    external_profile = _external_function_profile(callee)
    classification = "resolved"
    severity = "info"
    reason = "helper edge resolved"
    next_action = "none"
    blocks_recovery = False

    if edge.resolved:
        if _edge_has_contract_evidence(edge):
            classification = "resolved_contract_evidence"
            reason = "helper was analyzed and propagated buffer evidence"
        else:
            classification = "resolved_no_contract_evidence"
            reason = "helper was analyzed but no buffer contract evidence was propagated"
    elif "helper depth limit" in warning_text:
        depth_summary = _depth_limit_summary(callee, external_profile)
        if depth_summary:
            classification = depth_summary["classification"]
            severity = depth_summary["severity"]
            reason = depth_summary["reason"]
            next_action = depth_summary["next_action"]
            blocks_recovery = False
        elif _depth_limit_is_helper_local_after_contract_evidence(
            edge,
            covered_by_ancestor_contract,
            primary_buffers or set(),
        ):
            classification = "depth_limit_helper_local_context"
            severity = "info"
            reason = "maximum helper depth stopped in helper-local context after caller buffer evidence was recovered"
            next_action = "none"
            blocks_recovery = False
        else:
            classification = "depth_limit_reached"
            severity = "warning"
            reason = "maximum helper depth stopped deeper propagation"
            next_action = "increase helper depth if allowed or add a reusable helper summary"
            blocks_recovery = True
    elif "recursive helper edge skipped" in warning_text:
        classification = "recursive_edge_skipped"
        severity = "warning"
        reason = "recursive helper cycle was skipped"
        next_action = "add a fixed-point helper summary or review the recursive cycle manually"
        blocks_recovery = True
    elif _looks_like_indirect_helper(callee, evidence, warning_text):
        if indirect_target_candidates:
            classification = "indirect_dispatch_target_candidate"
            reason = "buffer reaches an indirect dispatch target with unresolved target candidates"
            next_action = "capture/decompile candidate targets or attach a target-set summary"
        elif indirect_target:
            classification = "indirect_dispatch_target_unresolved"
            reason = "buffer reaches an unresolved indirect dispatch target"
            next_action = "resolve the dispatch target expression or attach a target-set summary"
        else:
            classification = "indirect_call_unresolved"
            reason = "buffer reaches an unresolved indirect helper call"
            next_action = "resolve the indirect target set or attach a profile-backed external summary"
        severity = "high"
        blocks_recovery = True
    elif external_profile and "helper not available" in warning_text:
        if external_profile.get("summary_kind") == "input_only":
            classification = "external_api_profile_summary"
            severity = "info"
            reason = "callee is known in the kernel API profile and has input-only SAL annotations"
            next_action = "none"
        else:
            classification = "external_api_summary_gap"
            severity = "medium"
            reason = "callee is known in the kernel API profile but needs an explicit buffer contract summary"
            next_action = "add or attach a reusable external API summary for this callee"
            blocks_recovery = True
    elif "helper not available" in warning_text:
        boundary_summary = _missing_helper_boundary_summary(edge)
        if boundary_summary:
            classification = boundary_summary["classification"]
            severity = boundary_summary["severity"]
            reason = boundary_summary["reason"]
            next_action = boundary_summary["next_action"]
            blocks_recovery = False
        else:
            classification = "helper_capture_missing"
            severity = "high"
            reason = "callee capture was not available to the helper analyzer"
            next_action = "decompile the callee, add it to helper captures, or provide a reusable summary"
            blocks_recovery = True
    elif "buffer pointer escapes" in warning_text:
        classification = "pointer_escape_unknown"
        severity = "medium"
        reason = "buffer pointer escapes to a function without contract evidence"
        next_action = "model the callee as an external summary or inspect the call target"
        blocks_recovery = True
    elif not edge.resolved:
        classification = "unknown_unresolved"
        severity = "medium"
        reason = "helper edge is unresolved without a more specific reason"
        next_action = "inspect helper capture availability and call-site evidence"
        blocks_recovery = True

    return {
        "callee": callee,
        "arguments": list(edge.arguments),
        "passed_buffers": list(edge.passed_buffers),
        "resolved": bool(edge.resolved),
        "depth": edge.depth,
        "classification": classification,
        "severity": severity,
        "reason": reason,
        "next_action": next_action,
        "blocks_recovery": blocks_recovery,
        "evidence": evidence,
        "warnings": warnings,
        "size_constraints": len(edge.propagated_size_constraints),
        "field_accesses": len(edge.propagated_field_accesses),
        "field_constraints": len(edge.propagated_field_constraints),
        "nested_edges": len(edge.nested_edges),
        "confidence": edge.confidence,
        "external_profile": external_profile,
        "indirect_target": indirect_target,
        "indirect_target_candidates": indirect_target_candidates,
    }


def _iter_edges(edges: list[HelperContractEdge], prefix: str = "") -> list[tuple[str, HelperContractEdge]]:
    result: list[tuple[str, HelperContractEdge]] = []
    for index, edge in enumerate(edges):
        path = ("%s.%d" % (prefix, index)) if prefix else str(index)
        result.append((path, edge))
        result.extend(_iter_edges(edge.nested_edges, path))
    return result


def _iter_edges_with_context(
    edges: list[HelperContractEdge],
    prefix: str = "",
    covered_by_ancestor_contract: bool = False,
) -> list[tuple[str, HelperContractEdge, bool]]:
    result: list[tuple[str, HelperContractEdge, bool]] = []
    for index, edge in enumerate(edges):
        path = ("%s.%d" % (prefix, index)) if prefix else str(index)
        result.append((path, edge, covered_by_ancestor_contract))
        child_covered = covered_by_ancestor_contract or _edge_has_direct_contract_evidence(edge)
        result.extend(_iter_edges_with_context(edge.nested_edges, path, child_covered))
    return result


def _edge_has_contract_evidence(edge: HelperContractEdge) -> bool:
    return bool(
        _edge_has_direct_contract_evidence(edge)
        or edge.nested_edges
    )


def _edge_has_direct_contract_evidence(edge: HelperContractEdge) -> bool:
    return bool(
        edge.propagated_size_constraints
        or edge.propagated_field_accesses
        or edge.propagated_field_constraints
    )


def _edge_tree_metrics(
    edge: HelperContractEdge,
    *,
    primary_buffers: set[str],
    covered_by_ancestor_contract: bool = False,
) -> dict[str, int]:
    audit = classify_helper_edge(
        edge,
        covered_by_ancestor_contract=covered_by_ancestor_contract,
        primary_buffers=primary_buffers,
    )
    metrics = {
        "edge_count": 1,
        "unresolved_edges": 0 if edge.resolved else 1,
        "blocking_unresolved_edges": 1 if bool(audit.get("blocks_recovery", False)) else 0,
        "size_constraints": len(edge.propagated_size_constraints),
        "field_accesses": len(edge.propagated_field_accesses),
        "field_constraints": len(edge.propagated_field_constraints),
        "warnings": len(edge.warnings),
    }
    child_covered = covered_by_ancestor_contract or _edge_has_direct_contract_evidence(edge)
    for nested in edge.nested_edges:
        nested_metrics = _edge_tree_metrics(
            nested,
            primary_buffers=primary_buffers,
            covered_by_ancestor_contract=child_covered,
        )
        for key, value in nested_metrics.items():
            metrics[key] += value
    return metrics


def _contract_primary_buffers(contract: CommandBufferContract) -> set[str]:
    return {
        str(buffer.variable or "")
        for buffer in contract.buffers
        if str(buffer.variable or "")
    }


def _depth_limit_is_helper_local_after_contract_evidence(
    edge: HelperContractEdge,
    covered_by_ancestor_contract: bool,
    primary_buffers: set[str],
) -> bool:
    if not covered_by_ancestor_contract or not primary_buffers:
        return False
    if _edge_has_direct_contract_evidence(edge):
        return False
    passed = {str(buffer or "") for buffer in edge.passed_buffers if str(buffer or "")}
    return bool(passed) and not bool(passed & primary_buffers)


@lru_cache(maxsize=4096)
def _external_function_profile(callee: str) -> dict[str, str]:
    name = str(callee or "").strip()
    if not name:
        return {}
    builtin = _builtin_external_profile(name)
    if builtin:
        return builtin
    functions = load_kernel_api_family("functions")
    item = functions.get(name) if isinstance(functions, dict) else None
    if not isinstance(item, dict) or not item:
        return {}
    raw_signature = str(item.get("raw_signature", "") or "")
    summary_kind = "input_only" if _external_profile_is_input_only(raw_signature) else "requires_explicit_summary"
    return {
        "name": name,
        "return_type": str(item.get("return_type", "") or ""),
        "header": str(item.get("header", "") or ""),
        "summary_kind": summary_kind,
        "raw_signature": raw_signature,
    }


def _builtin_external_profile(name: str) -> dict[str, str]:
    builtin_signatures = {
        "memcmp": "int memcmp(_In_reads_bytes_(Length) const void *Left, _In_reads_bytes_(Length) const void *Right, _In_ size_t Length);",
    }
    raw_signature = builtin_signatures.get(name)
    if not raw_signature:
        return {}
    return {
        "name": name,
        "return_type": "int",
        "header": "crt",
        "summary_kind": "input_only",
        "raw_signature": raw_signature,
    }


def _depth_limit_summary(callee: str, external_profile: dict[str, str]) -> dict[str, str]:
    name = str(callee or "")
    if external_profile.get("summary_kind") == "input_only":
        return {
            "classification": "depth_limit_external_profile_summary",
            "severity": "info",
            "reason": "maximum helper depth stopped at an input-only external/profile function",
            "next_action": "none",
        }
    if _looks_like_terminal_sink(name):
        return {
            "classification": "depth_limit_terminal_sink",
            "severity": "info",
            "reason": "maximum helper depth stopped at a diagnostic or terminal sink",
            "next_action": "none",
        }
    if _looks_like_internal_state_probe(name):
        return {
            "classification": "depth_limit_internal_state_probe",
            "severity": "info",
            "reason": "maximum helper depth stopped at a kernel-internal state probe",
            "next_action": "review manually only if this helper is expected to write the caller ABI",
        }
    return {}


def _missing_helper_boundary_summary(edge: HelperContractEdge) -> dict[str, str]:
    if _looks_like_terminal_guarded_boundary(edge):
        return {
            "classification": "terminal_helper_boundary_summary",
            "severity": "info",
            "reason": "missing helper is a directly returned subsystem boundary after caller-side buffer guards",
            "next_action": "none",
        }
    if _looks_like_external_lock_boundary(edge.callee) and _has_explicit_length_for_passed_buffer(edge):
        return {
            "classification": "external_lock_boundary_summary",
            "severity": "info",
            "reason": "missing helper looks like a synchronization boundary with an explicit buffer length argument",
            "next_action": "none",
        }
    return {}


def _looks_like_terminal_guarded_boundary(edge: HelperContractEdge) -> bool:
    warning_text = " ".join(str(item or "").lower() for item in edge.warnings)
    if "terminal helper call returned directly" not in warning_text:
        return False
    if "caller case has local buffer guard before terminal helper" not in warning_text:
        return False
    if not _looks_like_subsystem_boundary(edge.callee):
        return False
    return _has_selector_context_boundary_shape(edge)


def _looks_like_subsystem_boundary(callee: str) -> bool:
    name = str(callee or "")
    if not name:
        return False
    boundary_markers = (
        "Initialize",
        "Register",
        "Unregister",
        "Notify",
        "Notification",
        "Callback",
        "Control",
    )
    return any(marker in name for marker in boundary_markers)


def _has_selector_context_boundary_shape(edge: HelperContractEdge) -> bool:
    arguments = [str(item or "").strip() for item in edge.arguments]
    if len(arguments) < 3:
        return False
    passed = {_argument_identifier(buffer) for buffer in edge.passed_buffers}
    has_constant_selector = any(_is_constant_argument(argument) for argument in arguments)
    has_context_reference = any(_is_context_reference_argument(argument, passed) for argument in arguments)
    return has_constant_selector and has_context_reference


def _is_constant_argument(argument: str) -> bool:
    text = str(argument or "").strip()
    if not text:
        return False
    return bool(re.fullmatch(r"(?:0x[0-9A-Fa-f]+|\d+)(?:LL|i64|L|u|U)?", text))


def _is_context_reference_argument(argument: str, passed_buffers: set[str]) -> bool:
    text = str(argument or "").strip()
    if not text.startswith("&"):
        return False
    identifier = _argument_identifier(text)
    return bool(identifier and identifier not in passed_buffers)


def _looks_like_terminal_sink(callee: str) -> bool:
    name = str(callee or "")
    if name in {"KeBugCheck2", "KeBugCheckEx"}:
        return True
    terminal_markers = (
        "ReportRuleViolation",
        "LogHeapFailure",
        "LogPoolTrace",
        "Notification",
    )
    return any(marker in name for marker in terminal_markers)


def _looks_like_internal_state_probe(callee: str) -> bool:
    name = str(callee or "")
    if name.startswith(("ExpCheckFor", "KeCheckFor")):
        return True
    internal_state_queries = {
        "ExGetHeapFromVA",
        "ExIsSpecialPoolAddress",
        "MmDeterminePoolType",
        "MmIsNonPagedPoolNx",
    }
    return name in internal_state_queries


def _looks_like_external_lock_boundary(callee: str) -> bool:
    name = str(callee or "")
    lock_markers = (
        "AcquireLock",
        "ReleaseLock",
    )
    return any(marker in name for marker in lock_markers)


def _has_explicit_length_for_passed_buffer(edge: HelperContractEdge) -> bool:
    arguments = [str(item or "").strip() for item in edge.arguments]
    if not arguments or not edge.passed_buffers:
        return False
    identifiers = [_argument_identifier(item) for item in arguments]
    for buffer in edge.passed_buffers:
        buffer_name = _argument_identifier(str(buffer or ""))
        if not buffer_name:
            continue
        for index, identifier in enumerate(identifiers):
            if identifier != buffer_name:
                continue
            following = identifiers[index + 1 :]
            if any(_is_length_identifier_for_buffer(item, buffer_name) for item in following):
                return True
    return False


def _argument_identifier(argument: str) -> str:
    text = str(argument or "").strip()
    if not text:
        return ""
    if text.startswith("&"):
        text = text[1:].strip()
    while text.startswith("(") and ")" in text:
        close = text.find(")")
        if close <= 0:
            break
        text = text[close + 1 :].strip()
    result = []
    for char in text:
        if char.isalnum() or char == "_":
            result.append(char)
        elif result:
            break
    return "".join(result)


def _is_length_identifier_for_buffer(identifier: str, buffer_name: str) -> bool:
    lowered = str(identifier or "").lower()
    buffer_lowered = str(buffer_name or "").lower()
    if not lowered or lowered == buffer_lowered:
        return False
    if lowered in {
        "%slength" % buffer_lowered,
        "%ssize" % buffer_lowered,
        "%sbytes" % buffer_lowered,
    }:
        return True
    return lowered.endswith(("length", "size", "bytes"))


def _external_profile_is_input_only(raw_signature: str) -> bool:
    lowered = str(raw_signature or "").lower()
    if not lowered:
        return False
    output_markers = (
        "_out",
        "_inout",
        "outptr",
        "out_writes",
        "out_reads",
        "deref_out",
    )
    return not any(marker in lowered for marker in output_markers)


def _looks_like_indirect_helper(callee: str, evidence: str, warning_text: str) -> bool:
    lowered = " ".join([callee or "", evidence or "", warning_text or ""]).lower()
    return any(
        marker in lowered
        for marker in (
            "guard_dispatch_icall",
            "__guard_dispatch_icall",
            "indirect helper",
            "indirect call",
            "function pointer",
            "(*",
        )
    )


def _indirect_target_from_warnings(warnings: list[str]) -> str:
    prefix = "indirect dispatch target argument:"
    for warning in warnings:
        text = str(warning or "").strip()
        if text.lower().startswith(prefix):
            return text[len(prefix) :].strip()
    return ""


def _indirect_target_candidates_from_warnings(warnings: list[str]) -> list[str]:
    prefix = "indirect dispatch target candidate:"
    result: list[str] = []
    for warning in warnings:
        text = str(warning or "").strip()
        if text.lower().startswith(prefix):
            candidate = text[len(prefix) :].strip()
            if candidate and candidate not in result:
                result.append(candidate)
    return result

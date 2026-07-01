from __future__ import annotations

from collections import Counter
from functools import lru_cache
from typing import Any

from ida_pseudoforge.core.plan_schema import CommandBufferContract, HelperContractEdge
from ida_pseudoforge.profiles.loader import load_kernel_api_family


def helper_edge_audit_records(contracts: list[CommandBufferContract]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for contract in contracts:
        for path, edge in _iter_edges(contract.helper_edges):
            record = classify_helper_edge(edge)
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
        for index, edge in enumerate(contract.helper_edges):
            audit = [classify_helper_edge(item) for _path, item in _iter_edges([edge])]
            metrics = _edge_tree_metrics(edge)
            root = classify_helper_edge(edge)
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


def classify_helper_edge(edge: HelperContractEdge) -> dict[str, Any]:
    warnings = [str(item) for item in edge.warnings if str(item)]
    warning_text = " ".join(warnings).lower()
    callee = edge.callee or ""
    evidence = edge.evidence or ""
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
        classification = "indirect_call_unresolved"
        severity = "high"
        reason = "buffer reaches an unresolved indirect helper call"
        next_action = "resolve the indirect target set or attach a profile-backed external summary"
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
    }


def _iter_edges(edges: list[HelperContractEdge], prefix: str = "") -> list[tuple[str, HelperContractEdge]]:
    result: list[tuple[str, HelperContractEdge]] = []
    for index, edge in enumerate(edges):
        path = ("%s.%d" % (prefix, index)) if prefix else str(index)
        result.append((path, edge))
        result.extend(_iter_edges(edge.nested_edges, path))
    return result


def _edge_has_contract_evidence(edge: HelperContractEdge) -> bool:
    return bool(
        edge.propagated_size_constraints
        or edge.propagated_field_accesses
        or edge.propagated_field_constraints
        or edge.nested_edges
    )


def _edge_tree_metrics(edge: HelperContractEdge) -> dict[str, int]:
    audit = classify_helper_edge(edge)
    metrics = {
        "edge_count": 1,
        "unresolved_edges": 0 if edge.resolved else 1,
        "blocking_unresolved_edges": 1 if bool(audit.get("blocks_recovery", False)) else 0,
        "size_constraints": len(edge.propagated_size_constraints),
        "field_accesses": len(edge.propagated_field_accesses),
        "field_constraints": len(edge.propagated_field_constraints),
        "warnings": len(edge.warnings),
    }
    for nested in edge.nested_edges:
        nested_metrics = _edge_tree_metrics(nested)
        for key, value in nested_metrics.items():
            metrics[key] += value
    return metrics


@lru_cache(maxsize=4096)
def _external_function_profile(callee: str) -> dict[str, str]:
    name = str(callee or "").strip()
    if not name:
        return {}
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

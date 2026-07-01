from __future__ import annotations

import argparse
import json
import re
import sys
import time
import traceback
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

for module_name in list(sys.modules):
    if module_name == "ida_pseudoforge" or module_name.startswith("ida_pseudoforge."):
        del sys.modules[module_name]

from ida_pseudoforge.core.buffer_contracts import buffer_contracts_json_payload
from ida_pseudoforge.core.helper_edge_audit import (
    blocking_unresolved_helper_edge_records,
    helper_edge_audit_records,
    helper_edge_class_counts,
    helper_path_family_records,
    unresolved_helper_edge_records,
)
from ida_pseudoforge.core.helper_depth import (
    DEFAULT_HELPER_DEPTH,
    MAX_HELPER_DEPTH,
    MIN_HELPER_DEPTH,
    parse_helper_depth,
)
from ida_pseudoforge.core.ioctl import parse_c_integer_literal
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.ida.actions import analyze_current_selector_case
from ida_pseudoforge.ida.decompiler import capture_function_by_name
from ida_pseudoforge.profiles.loader import active_profile_root, configure_profile_dir

try:
    import ida_auto  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_nalt  # type: ignore
    import ida_pro  # type: ignore
    import idaapi  # type: ignore
    import idc  # type: ignore
except Exception:
    ida_auto = None
    ida_hexrays = None
    ida_nalt = None
    ida_pro = None
    idaapi = None
    idc = None


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(_script_argv() if argv is None else argv)
    configure_profile_dir(args.profile_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = Path(args.report) if args.report else out_dir / "pseudoforge-case-contracts.jsonl"
    explicit_targets = [_parse_target(text) for text in args.target]
    reporter = _JsonlReporter(report_path)
    target_records: list[dict[str, Any]] = []
    exit_code = 0
    started = time.monotonic()

    try:
        _require_ida()
        if not args.no_auto_wait:
            ida_auto.auto_wait()
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler is not available")
        source_path = _input_path()
        targets = _dedupe_targets(explicit_targets + _expand_all_case_targets(args.target_all_cases))
        reporter.write(
            {
                "event": "start",
                "targets": len(targets),
                "out_dir": str(out_dir),
                "profile_dir": active_profile_root(),
                "input_path": source_path,
                "helper_depth": args.helper_depth,
            }
        )
        for index, (function_name, case_value) in enumerate(targets, start=1):
            reporter.write(
                {
                    "event": "progress",
                    "index": index,
                    "function": function_name,
                    "case": "0x%X" % case_value,
                }
            )
            record = _analyze_target(function_name, case_value, out_dir, source_path, args.helper_depth)
            target_records.append(record)
            reporter.write(record)
            if record.get("status") != "ok":
                exit_code = 1
                if args.stop_on_error:
                    break
        coverage = _build_coverage_summary(
            target_records,
            out_dir=out_dir,
            source_path=source_path,
            helper_depth=args.helper_depth,
            elapsed_seconds=round(time.monotonic() - started, 3),
            exit_code=exit_code,
        )
        coverage_json_path = out_dir / "selector-coverage-summary.json"
        coverage_md_path = out_dir / "selector-coverage-summary.md"
        coverage_json_path.write_text(json.dumps(coverage, indent=2, ensure_ascii=True), encoding="utf-8")
        coverage_md_path.write_text(_render_coverage_markdown(coverage), encoding="utf-8")
        reporter.write(
            {
                "event": "summary",
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "exit_code": exit_code,
                "coverage_json_path": str(coverage_json_path),
                "coverage_md_path": str(coverage_md_path),
            }
        )
    except Exception as exc:
        exit_code = 1
        reporter.write(
            {
                "event": "fatal",
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
        )
    finally:
        reporter.close()
        if not args.no_exit and ida_pro is not None:
            ida_pro.qexit(exit_code)
    return exit_code


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run focused PseudoForge selector/buffer-contract case analysis inside IDA."
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="FunctionName:caseValue target. Case accepts decimal or C-style hex.",
    )
    parser.add_argument(
        "--target-all-cases",
        action="append",
        default=[],
        metavar="FunctionName",
        help="Expand all recovered selector cases for a function, for example NtSetSystemInformation.",
    )
    parser.add_argument("--out-dir", required=True, help="Directory for Markdown and JSON artifacts.")
    parser.add_argument("--report", default="", help="Optional JSONL report path.")
    parser.add_argument("--profile-dir", default="", help="Optional PseudoForge profile directory.")
    parser.add_argument(
        "--helper-depth",
        default=DEFAULT_HELPER_DEPTH,
        type=_parse_helper_depth_arg,
        help="Maximum helper/subhandler follow depth. Valid range: %d-%d. Default: %d."
        % (MIN_HELPER_DEPTH, MAX_HELPER_DEPTH, DEFAULT_HELPER_DEPTH),
    )
    parser.add_argument("--stop-on-error", action="store_true", help="Stop after the first failed target.")
    parser.add_argument("--no-auto-wait", action="store_true", help="Do not wait for IDA autoanalysis first.")
    parser.add_argument("--no-exit", action="store_true", help="Do not call ida_pro.qexit at the end.")
    args = parser.parse_args(argv)
    if not args.target and not args.target_all_cases:
        parser.error("at least one --target or --target-all-cases is required")
    return args


def _parse_helper_depth_arg(text: str) -> int:
    depth = parse_helper_depth(text)
    if depth is None:
        raise argparse.ArgumentTypeError(
            "helper depth must be an integer from %d to %d" % (MIN_HELPER_DEPTH, MAX_HELPER_DEPTH)
        )
    return depth


def _script_argv() -> list[str]:
    try:
        raw = list(getattr(idc, "ARGV", []) or [])
    except Exception:
        raw = []
    if raw:
        if raw[0].lower().endswith(".py"):
            return raw[1:]
        return raw
    return sys.argv[1:]


def _parse_target(text: str) -> tuple[str, int]:
    if ":" not in text:
        raise argparse.ArgumentTypeError("target must use FunctionName:caseValue")
    function_name, raw_case = text.split(":", 1)
    function_name = function_name.strip()
    if not function_name:
        raise argparse.ArgumentTypeError("target function name is empty")
    value = parse_c_integer_literal(raw_case.strip())
    if value is None:
        raise argparse.ArgumentTypeError("case value must be a C integer literal")
    return function_name, int(value)


def _expand_all_case_targets(function_names: list[str]) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    for function_name in function_names:
        target_name = function_name.strip()
        if not target_name:
            continue
        capture = capture_function_by_name(target_name)
        if capture is None:
            raise RuntimeError("function capture unavailable for --target-all-cases: %s" % target_name)
        plan = build_clean_plan(capture)
        values: set[int] = set()
        for flow in plan.flow_rewrites:
            values.update(int(value) for value in flow.recovered_cases)
        if not values:
            raise RuntimeError("no recovered selector cases for --target-all-cases: %s" % target_name)
        result.extend((target_name, value) for value in sorted(values))
    return result


def _dedupe_targets(targets: list[tuple[str, int]]) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for function_name, case_value in targets:
        key = (function_name, int(case_value))
        if key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


def _require_ida() -> None:
    missing = [
        name
        for name, module in (
            ("ida_auto", ida_auto),
            ("ida_hexrays", ida_hexrays),
            ("ida_pro", ida_pro),
        )
        if module is None
    ]
    if missing:
        raise RuntimeError("IDA APIs are not available: %s" % ", ".join(missing))


def _analyze_target(
    function_name: str,
    case_value: int,
    out_dir: Path,
    source_path: str,
    helper_depth: int,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        capture = capture_function_by_name(function_name)
        if capture is None:
            return {
                "event": "target",
                "status": "skipped",
                "function": function_name,
                "case": "0x%X" % case_value,
                "reason": "function capture unavailable",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        if source_path:
            capture.source_path = source_path
        capture, plan, preview = analyze_current_selector_case(
            case_value,
            capture=capture,
            helper_depth=helper_depth,
        )
        contracts = [contract for contract in plan.buffer_contracts if contract.command_value == case_value]
        stem = _safe_stem("%s_0x%X" % (capture.name or function_name, case_value))
        text_path = out_dir / (stem + ".md")
        json_path = out_dir / (stem + ".buffer-contracts.json")
        summary_path = out_dir / (stem + ".summary.json")
        text_path.write_text(preview.rstrip() + "\n", encoding="utf-8")
        json_path.write_text(
            json.dumps(buffer_contracts_json_payload(contracts), indent=2, ensure_ascii=True),
            encoding="utf-8",
        )
        summary = {
            "function": capture.name or function_name,
            "function_ea": "0x%X" % capture.ea,
            "case": "0x%X" % case_value,
            "case_value": case_value,
            "command_name": _case_name_for_value(plan, case_value),
            "contracts": len(contracts),
            "helpers": _count_helper_edges(contracts),
            "buffers": sum(len(contract.buffers) for contract in contracts),
            "text_path": str(text_path),
            "json_path": str(json_path),
            "report_kind": "selector_path",
            "helper_depth": helper_depth,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        summary.update(_contract_metrics(contracts))
        summary.update(_zero_contract_context(plan, case_value, contracts))
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=True), encoding="utf-8")
        return {"event": "target", "status": "ok", **summary}
    except Exception as exc:
        return {
            "event": "target",
            "status": "error",
            "function": function_name,
            "case": "0x%X" % case_value,
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }


def _count_helper_edges(contracts: list[object]) -> int:
    total = 0
    for contract in contracts:
        for edge in getattr(contract, "helper_edges", []):
            total += _count_edge(edge)
    return total


def _count_edge(edge: object) -> int:
    return 1 + sum(_count_edge(nested) for nested in getattr(edge, "nested_edges", []))


def _case_name_for_value(plan: object, case_value: int) -> str:
    for flow in getattr(plan, "flow_rewrites", []):
        names = getattr(flow, "case_names", {}) or {}
        name = names.get(case_value)
        if name:
            return str(name)
    return ""


def _contract_metrics(contracts: list[object]) -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "local_size_constraints": 0,
        "local_field_accesses": 0,
        "local_field_constraints": 0,
        "helper_size_constraints": 0,
        "helper_field_accesses": 0,
        "helper_field_constraints": 0,
        "helper_edges_total": 0,
        "helper_edges_resolved": 0,
        "helper_edges_unresolved": 0,
        "warnings": 0,
        "warning_messages": [],
        "buffer_names": [],
        "helper_edge_audit": [],
        "helper_edge_class_counts": {},
        "helper_path_families": [],
        "unresolved_helper_edge_audit": [],
        "blocking_unresolved_helper_edge_audit": [],
    }
    warning_messages: list[str] = []
    buffer_names: list[str] = []
    for contract in contracts:
        warning_messages.extend(str(item) for item in getattr(contract, "warnings", []) or [])
        for buffer in getattr(contract, "buffers", []) or []:
            name = str(getattr(buffer, "variable", "") or "")
            if name and name not in buffer_names:
                buffer_names.append(name)
            metrics["local_size_constraints"] += len(getattr(buffer, "size_constraints", []) or [])
            metrics["local_field_accesses"] += len(getattr(buffer, "field_accesses", []) or [])
            metrics["local_field_constraints"] += len(getattr(buffer, "field_constraints", []) or [])
        edge_metrics = _helper_edge_metrics(getattr(contract, "helper_edges", []) or [])
        metrics["helper_size_constraints"] += edge_metrics["helper_size_constraints"]
        metrics["helper_field_accesses"] += edge_metrics["helper_field_accesses"]
        metrics["helper_field_constraints"] += edge_metrics["helper_field_constraints"]
        metrics["helper_edges_total"] += edge_metrics["helper_edges_total"]
        metrics["helper_edges_resolved"] += edge_metrics["helper_edges_resolved"]
        metrics["helper_edges_unresolved"] += edge_metrics["helper_edges_unresolved"]
        warning_messages.extend(edge_metrics["warning_messages"])
    audit_records = helper_edge_audit_records(contracts)
    metrics["warnings"] = len(warning_messages)
    metrics["warning_messages"] = sorted(set(warning_messages))
    metrics["buffer_names"] = buffer_names
    metrics["helper_edge_audit"] = audit_records
    metrics["helper_edge_class_counts"] = helper_edge_class_counts(audit_records)
    metrics["helper_path_families"] = helper_path_family_records(contracts)
    metrics["unresolved_helper_edge_audit"] = unresolved_helper_edge_records(audit_records)
    metrics["blocking_unresolved_helper_edge_audit"] = blocking_unresolved_helper_edge_records(audit_records)
    return metrics


def _zero_contract_context(plan: object, case_value: int, contracts: list[object]) -> dict[str, Any]:
    if contracts:
        return {}
    body = _case_body_lines_for_value(plan, case_value)
    text = "\n".join(body)
    classification = "unknown_unclassified"
    reason = "no recovered contract and no selected case body was available"
    if body:
        has_buffer_reference = _case_body_has_buffer_reference(text)
        if has_buffer_reference:
            classification = "no_contract_but_buffer_referenced"
            reason = "selected case references buffer-like data but no contract was recovered"
        elif _case_body_is_status_only(text):
            classification = "no_buffer_immediate_status"
            reason = "selected case returns or assigns an immediate status without buffer evidence"
        elif _case_body_has_nonbuffer_call(text):
            classification = "no_buffer_context_call"
            reason = "selected case calls a routine without passing buffer-like data"
        else:
            classification = "no_buffer_context_only"
            reason = "selected case has no buffer-like evidence"
    return {
        "zero_contract": {
            "classification": classification,
            "reason": reason,
            "evidence": " ".join(line.strip() for line in body[:6] if line.strip()),
        }
    }


def _case_body_lines_for_value(plan: object, case_value: int) -> list[str]:
    for flow in getattr(plan, "flow_rewrites", []) or []:
        bodies = getattr(flow, "case_bodies", {}) or {}
        body = bodies.get(case_value)
        if body:
            return [str(line) for line in body]
    return []


def _case_body_has_buffer_reference(text: str) -> bool:
    lowered = (text or "").lower()
    markers = (
        "buffer",
        "inputbuffer",
        "outputbuffer",
        "systembuffer",
        "userbuffer",
        "informationlength",
        "processinformation",
        "threadinformation",
        "systeminformation",
        "associatedirp",
        "mdladdress",
    )
    return any(marker in lowered for marker in markers)


def _case_body_is_status_only(text: str) -> bool:
    source = text or ""
    lowered = source.lower()
    if "status_" in lowered:
        return True
    return bool(re.search(r"\breturn\s+(?:\([^)]+\)\s*)?-?(?:0x[0-9a-fA-F]+|\d+)\s*;", source))


def _case_body_has_nonbuffer_call(text: str) -> bool:
    if _case_body_has_buffer_reference(text):
        return False
    return bool(re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(", text or ""))


def _helper_edge_metrics(edges: list[object]) -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "helper_size_constraints": 0,
        "helper_field_accesses": 0,
        "helper_field_constraints": 0,
        "helper_edges_total": 0,
        "helper_edges_resolved": 0,
        "helper_edges_unresolved": 0,
        "warning_messages": [],
    }
    warning_messages: list[str] = []
    for edge in edges:
        metrics["helper_edges_total"] += 1
        if getattr(edge, "resolved", False):
            metrics["helper_edges_resolved"] += 1
        else:
            metrics["helper_edges_unresolved"] += 1
        metrics["helper_size_constraints"] += len(getattr(edge, "propagated_size_constraints", []) or [])
        metrics["helper_field_accesses"] += len(getattr(edge, "propagated_field_accesses", []) or [])
        metrics["helper_field_constraints"] += len(getattr(edge, "propagated_field_constraints", []) or [])
        warning_messages.extend(str(item) for item in getattr(edge, "warnings", []) or [])
        nested = _helper_edge_metrics(getattr(edge, "nested_edges", []) or [])
        metrics["helper_size_constraints"] += nested["helper_size_constraints"]
        metrics["helper_field_accesses"] += nested["helper_field_accesses"]
        metrics["helper_field_constraints"] += nested["helper_field_constraints"]
        metrics["helper_edges_total"] += nested["helper_edges_total"]
        metrics["helper_edges_resolved"] += nested["helper_edges_resolved"]
        metrics["helper_edges_unresolved"] += nested["helper_edges_unresolved"]
        warning_messages.extend(nested["warning_messages"])
    metrics["warning_messages"] = warning_messages
    return metrics


def _build_coverage_summary(
    target_records: list[dict[str, Any]],
    *,
    out_dir: Path,
    source_path: str,
    helper_depth: int,
    elapsed_seconds: float,
    exit_code: int,
) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    totals = {
        "targets": len(target_records),
        "contracts": 0,
        "buffers": 0,
        "helpers": 0,
        "local_size_constraints": 0,
        "local_field_accesses": 0,
        "local_field_constraints": 0,
        "helper_size_constraints": 0,
        "helper_field_accesses": 0,
        "helper_field_constraints": 0,
        "helper_edges_total": 0,
        "helper_edges_resolved": 0,
        "helper_edges_unresolved": 0,
        "blocking_unresolved_helper_edges": 0,
        "warnings": 0,
    }
    cases: list[dict[str, Any]] = []
    zero_contract_cases: list[str] = []
    warning_cases: list[str] = []
    unresolved_helper_cases: list[str] = []
    helper_edge_class_counts_total: dict[str, int] = {}
    unresolved_helper_edge_audit: list[dict[str, Any]] = []
    blocking_unresolved_helper_edge_audit: list[dict[str, Any]] = []
    path_families: list[dict[str, Any]] = []
    path_families_with_unresolved: list[str] = []
    zero_contract_audit: list[dict[str, Any]] = []
    for record in target_records:
        status = str(record.get("status", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
        case_label = str(record.get("case", ""))
        unresolved_audit = list(record.get("unresolved_helper_edge_audit", []) or [])
        blocking_unresolved_audit = list(record.get("blocking_unresolved_helper_edge_audit", []) or [])
        if not blocking_unresolved_audit and unresolved_audit:
            blocking_unresolved_audit = [
                item for item in unresolved_audit if bool(item.get("blocks_recovery", True))
            ]
        case_entry = {
            "function": record.get("function", ""),
            "case": case_label,
            "case_value": record.get("case_value"),
            "command_name": record.get("command_name", ""),
            "status": status,
            "contracts": int(record.get("contracts", 0) or 0),
            "buffers": int(record.get("buffers", 0) or 0),
            "helpers": int(record.get("helpers", 0) or 0),
            "local_size_constraints": int(record.get("local_size_constraints", 0) or 0),
            "local_field_accesses": int(record.get("local_field_accesses", 0) or 0),
            "local_field_constraints": int(record.get("local_field_constraints", 0) or 0),
            "helper_size_constraints": int(record.get("helper_size_constraints", 0) or 0),
            "helper_field_accesses": int(record.get("helper_field_accesses", 0) or 0),
            "helper_field_constraints": int(record.get("helper_field_constraints", 0) or 0),
            "helper_edges_total": int(record.get("helper_edges_total", 0) or 0),
            "helper_edges_resolved": int(record.get("helper_edges_resolved", 0) or 0),
            "helper_edges_unresolved": int(record.get("helper_edges_unresolved", 0) or 0),
            "warnings": int(record.get("warnings", 0) or 0),
            "warning_messages": list(record.get("warning_messages", []) or []),
            "helper_edge_class_counts": dict(record.get("helper_edge_class_counts", {}) or {}),
            "helper_edge_audit": list(record.get("helper_edge_audit", []) or []),
            "helper_path_families": list(record.get("helper_path_families", []) or []),
            "unresolved_helper_edge_audit": unresolved_audit,
            "blocking_unresolved_helper_edge_audit": blocking_unresolved_audit,
            "zero_contract": dict(record.get("zero_contract", {}) or {}),
            "text_path": record.get("text_path", ""),
            "json_path": record.get("json_path", ""),
        }
        cases.append(case_entry)
        for key in totals:
            if key == "targets":
                continue
            if key == "blocking_unresolved_helper_edges":
                totals[key] += len(case_entry["blocking_unresolved_helper_edge_audit"])
            else:
                totals[key] += int(case_entry.get(key, 0) or 0)
        if status == "ok" and case_entry["contracts"] == 0:
            zero_contract_cases.append(case_label)
            zero_contract = dict(case_entry.get("zero_contract", {}) or {})
            if not zero_contract:
                zero_contract = {
                    "classification": "unknown_unclassified",
                    "reason": "no zero-contract classification was provided",
                    "evidence": "",
                }
                case_entry["zero_contract"] = zero_contract
            zero_contract_audit.append(
                {
                    "case": case_label,
                    "case_value": case_entry.get("case_value"),
                    "command_name": case_entry.get("command_name", ""),
                    **zero_contract,
                }
            )
        if case_entry["warnings"]:
            warning_cases.append(case_label)
        if case_entry["helper_edges_unresolved"]:
            unresolved_helper_cases.append(case_label)
        for classification, count in case_entry["helper_edge_class_counts"].items():
            helper_edge_class_counts_total[str(classification)] = (
                helper_edge_class_counts_total.get(str(classification), 0) + int(count or 0)
            )
        unresolved_helper_edge_audit.extend(case_entry["unresolved_helper_edge_audit"])
        blocking_unresolved_helper_edge_audit.extend(case_entry["blocking_unresolved_helper_edge_audit"])
        for family in case_entry["helper_path_families"]:
            path_families.append(family)
            if int(family.get("unresolved_edges", 0) or 0) > 0:
                path_families_with_unresolved.append(str(family.get("family_id", "")))
    recovery_gate = _build_recovery_gate(
        status_counts=status_counts,
        totals=totals,
        zero_contract_cases=zero_contract_cases,
        warning_cases=warning_cases,
        unresolved_helper_cases=unresolved_helper_cases,
        blocking_unresolved_helper_edge_audit=blocking_unresolved_helper_edge_audit,
        helper_edge_class_counts=helper_edge_class_counts_total,
        path_families=path_families,
        zero_contract_audit=zero_contract_audit,
    )
    return {
        "schema": "pseudoforge_selector_coverage_summary_v1",
        "out_dir": str(out_dir),
        "source_path": source_path,
        "helper_depth": helper_depth,
        "elapsed_seconds": elapsed_seconds,
        "exit_code": exit_code,
        "status_counts": status_counts,
        "totals": totals,
        "zero_contract_cases": zero_contract_cases,
        "zero_contract_audit": zero_contract_audit,
        "warning_cases": warning_cases,
        "unresolved_helper_cases": unresolved_helper_cases,
        "helper_edge_class_counts": dict(sorted(helper_edge_class_counts_total.items())),
        "unresolved_helper_edge_audit": unresolved_helper_edge_audit,
        "blocking_unresolved_helper_edge_audit": blocking_unresolved_helper_edge_audit,
        "path_family_count": len(path_families),
        "path_families_with_unresolved": path_families_with_unresolved,
        "path_families": path_families,
        "recovery_gate": recovery_gate,
        "cases": cases,
    }


def _build_recovery_gate(
    *,
    status_counts: dict[str, int],
    totals: dict[str, int],
    zero_contract_cases: list[str],
    warning_cases: list[str],
    unresolved_helper_cases: list[str],
    blocking_unresolved_helper_edge_audit: list[dict[str, Any]],
    helper_edge_class_counts: dict[str, int],
    path_families: list[dict[str, Any]],
    zero_contract_audit: list[dict[str, Any]],
) -> dict[str, Any]:
    unclassified_zero_contracts = [
        item
        for item in zero_contract_audit
        if str(item.get("classification", "")) in {"", "unknown_unclassified", "no_contract_but_buffer_referenced"}
    ]
    checks = [
        {
            "name": "all_targets_ok",
            "passed": status_counts.get("error", 0) == 0 and status_counts.get("skipped", 0) == 0,
            "detail": "errors=%d skipped=%d" % (status_counts.get("error", 0), status_counts.get("skipped", 0)),
        },
        {
            "name": "no_unresolved_helper_edges",
            "passed": not blocking_unresolved_helper_edge_audit,
            "detail": "raw_unresolved=%d blocking_unresolved=%d"
            % (
                int(totals.get("helper_edges_unresolved", 0) or 0),
                len(blocking_unresolved_helper_edge_audit),
            ),
        },
        {
            "name": "no_warning_cases",
            "passed": not warning_cases,
            "detail": "warning_cases=%d" % len(warning_cases),
        },
        {
            "name": "zero_contract_cases_classified",
            "passed": not unclassified_zero_contracts,
            "detail": "zero_contract_cases=%d unclassified=%d"
            % (len(zero_contract_cases), len(unclassified_zero_contracts)),
        },
        {
            "name": "helper_edge_audit_available",
            "passed": bool(helper_edge_class_counts) or int(totals.get("helper_edges_total", 0) or 0) == 0,
            "detail": "classifications=%d" % len(helper_edge_class_counts),
        },
        {
            "name": "path_family_ledger_available",
            "passed": bool(path_families) or int(totals.get("helper_edges_total", 0) or 0) == 0,
            "detail": "path_families=%d" % len(path_families),
        },
    ]
    passed = all(bool(item["passed"]) for item in checks)
    if passed:
        level = "perfect_recovery_candidate"
        status = "passed"
    elif checks[0]["passed"] and checks[4]["passed"] and checks[5]["passed"]:
        level = "audited_incomplete_recovery"
        status = "incomplete"
    else:
        level = "insufficient_evidence"
        status = "failed"
    return {
        "schema": "pseudoforge_selector_recovery_gate_v1",
        "status": status,
        "level": level,
        "passed": passed,
        "checks": checks,
        "blockers": [
            item["name"]
            for item in checks
            if not bool(item["passed"])
        ],
    }


def _render_coverage_markdown(summary: dict[str, Any]) -> str:
    totals = summary.get("totals", {}) or {}
    lines = [
        "# PseudoForge Selector Coverage Summary",
        "",
        "- Source: `%s`" % summary.get("source_path", ""),
        "- Helper depth: `%s`" % summary.get("helper_depth", ""),
        "- Exit code: `%s`" % summary.get("exit_code", ""),
        "- Elapsed seconds: `%s`" % summary.get("elapsed_seconds", ""),
        "",
        "## Totals",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
    ]
    metric_order = [
        "targets",
        "contracts",
        "buffers",
        "helpers",
        "local_size_constraints",
        "local_field_accesses",
        "local_field_constraints",
        "helper_size_constraints",
        "helper_field_accesses",
        "helper_field_constraints",
        "helper_edges_total",
        "helper_edges_resolved",
        "helper_edges_unresolved",
        "blocking_unresolved_helper_edges",
        "warnings",
    ]
    for key in metric_order:
        lines.append("| `%s` | %s |" % (key, totals.get(key, 0)))
    lines.extend(
        [
            "",
            "## Attention Lists",
            "",
            "- Zero-contract cases: %s" % _markdown_case_list(summary.get("zero_contract_cases", [])),
            "- Warning cases: %s" % _markdown_case_list(summary.get("warning_cases", [])),
            "- Unresolved-helper cases: %s" % _markdown_case_list(summary.get("unresolved_helper_cases", [])),
            "",
            "## Recovery Gate",
            "",
        ]
    )
    gate = dict(summary.get("recovery_gate", {}) or {})
    if gate:
        lines.extend(
            [
                "- Status: `%s`" % gate.get("status", ""),
                "- Level: `%s`" % gate.get("level", ""),
                "- Passed: `%s`" % gate.get("passed", False),
                "",
                "| Check | Passed | Detail |",
                "| --- | --- | --- |",
            ]
        )
        for check in gate.get("checks", []) or []:
            lines.append(
                "| `%s` | `%s` | %s |"
                % (
                    check.get("name", ""),
                    check.get("passed", False),
                    _markdown_table_text(str(check.get("detail", "") or "")),
                )
            )
        lines.append("")
    else:
        lines.extend(["No recovery gate was produced.", ""])
    zero_contract_audit = list(summary.get("zero_contract_audit", []) or [])
    lines.extend(["## Zero-Contract Audit", ""])
    if zero_contract_audit:
        lines.extend(
            [
                "| Case | Name | Classification | Reason |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in zero_contract_audit:
            lines.append(
                "| `%s` | %s | `%s` | %s |"
                % (
                    item.get("case", ""),
                    _markdown_table_text(str(item.get("command_name", "") or "")),
                    _markdown_table_text(str(item.get("classification", "") or "")),
                    _markdown_table_text(str(item.get("reason", "") or "")),
                )
            )
        lines.append("")
    else:
        lines.extend(["No zero-contract cases were present.", ""])
    lines.extend(
        [
            "## Helper Edge Audit",
            "",
        ]
    )
    class_counts = dict(summary.get("helper_edge_class_counts", {}) or {})
    if class_counts:
        lines.extend(["| Classification | Count |", "| --- | ---: |"])
        for classification, count in class_counts.items():
            lines.append("| `%s` | %s |" % (classification, count))
        lines.append("")
    else:
        lines.extend(["No helper edge audit records were produced.", ""])
    unresolved = list(summary.get("unresolved_helper_edge_audit", []) or [])
    if unresolved:
        lines.extend(
            [
                "### Unresolved Helper Edges",
                "",
                "| Case | Callee | Classification | Blocks | Severity | Depth | Buffers | Next Action |",
                "| --- | --- | --- | --- | --- | ---: | --- | --- |",
            ]
        )
        for record in unresolved:
            lines.append(
                "| `%s` | `%s` | `%s` | `%s` | `%s` | %s | %s | %s |"
                % (
                    record.get("command", ""),
                    _markdown_table_text(str(record.get("callee", "") or "")),
                    _markdown_table_text(str(record.get("classification", "") or "")),
                    record.get("blocks_recovery", False),
                    _markdown_table_text(str(record.get("severity", "") or "")),
                    record.get("depth", ""),
                    _markdown_table_text(", ".join(record.get("passed_buffers", []) or []) or "none"),
                    _markdown_table_text(str(record.get("next_action", "") or "")),
                )
            )
        lines.append("")
    else:
        lines.extend(["Unresolved helper edges: none", ""])
    path_families = list(summary.get("path_families", []) or [])
    lines.extend(["## Helper Path Families", ""])
    if path_families:
        lines.extend(
            [
                "| Family | Root Callee | Root Class | Edges | Unresolved | Helper Fields | Helper Preds | Warnings |",
                "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for family in path_families:
            lines.append(
                "| `%s` | `%s` | `%s` | %s | %s | %s | %s | %s |"
                % (
                    _markdown_table_text(str(family.get("family_id", "") or "")),
                    _markdown_table_text(str(family.get("root_callee", "") or "")),
                    _markdown_table_text(str(family.get("root_classification", "") or "")),
                    family.get("edge_count", 0),
                    family.get("unresolved_edges", 0),
                    family.get("field_accesses", 0),
                    family.get("field_constraints", 0),
                    family.get("warnings", 0),
                )
            )
        lines.append("")
    else:
        lines.extend(["No helper path families were recovered.", ""])
    lines.extend(
        [
            "## Cases",
            "",
            "| Case | Name | Status | Contracts | Buffers | Helper fields | Helper preds | Unresolved helpers | Warnings |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for case in summary.get("cases", []) or []:
        lines.append(
            "| `%s` | %s | `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                case.get("case", ""),
                _markdown_table_text(str(case.get("command_name", "") or "")),
                case.get("status", ""),
                case.get("contracts", 0),
                case.get("buffers", 0),
                case.get("helper_field_accesses", 0),
                case.get("helper_field_constraints", 0),
                case.get("helper_edges_unresolved", 0),
                case.get("warnings", 0),
            )
        )
    lines.append("")
    return "\n".join(lines)


def _markdown_case_list(values: object) -> str:
    items = [str(item) for item in values or []]
    if not items:
        return "none"
    return ", ".join("`%s`" % item for item in items)


def _markdown_table_text(value: str) -> str:
    return (value or "").replace("|", "\\|") or "-"


def _input_path() -> str:
    if ida_nalt is not None:
        getter = getattr(ida_nalt, "get_input_file_path", None)
        if callable(getter):
            try:
                return str(getter() or "")
            except Exception:
                pass
    if idaapi is not None:
        getter = getattr(idaapi, "get_input_file_path", None)
        if callable(getter):
            try:
                return str(getter() or "")
            except Exception:
                pass
    return ""


def _safe_stem(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._") or "case"


class _JsonlReporter:
    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self._path.open("w", encoding="utf-8")

    def write(self, record: dict[str, Any]) -> None:
        self._handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
        self._handle.flush()

    def close(self) -> None:
        self._handle.close()


if __name__ == "__main__":
    raise SystemExit(main())

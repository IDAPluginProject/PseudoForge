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
    import ida_funcs  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_nalt  # type: ignore
    import ida_pro  # type: ignore
    import idaapi  # type: ignore
    import idautils  # type: ignore
    import idc  # type: ignore
except Exception:
    ida_auto = None
    ida_funcs = None
    ida_hexrays = None
    ida_nalt = None
    ida_pro = None
    idaapi = None
    idautils = None
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
        discovered_targets = []
        if args.discover_ioctl_dispatch_all_cases:
            discovery_candidates = _discover_ioctl_dispatch_candidates(min_score=args.discover_min_score)
            reporter.write(
                {
                    "event": "discovery",
                    "kind": "ioctl_dispatch",
                    "candidates": discovery_candidates,
                }
            )
            discovered_targets = _expand_discovered_ioctl_dispatch_targets(
                max_dispatchers=args.discover_max_dispatchers,
                min_score=args.discover_min_score,
                candidates=discovery_candidates,
            )
        targets = _dedupe_targets(explicit_targets + _expand_all_case_targets(args.target_all_cases) + discovered_targets)
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
    parser.add_argument(
        "--discover-ioctl-dispatch-all-cases",
        action="store_true",
        help="Discover likely WDM IOCTL dispatch functions and expand all recovered IOCTL cases.",
    )
    parser.add_argument(
        "--discover-max-dispatchers",
        default=1,
        type=int,
        help="Maximum discovered IOCTL dispatch functions to analyze. Default: 1.",
    )
    parser.add_argument(
        "--discover-min-score",
        default=6,
        type=int,
        help="Minimum WDM IOCTL dispatch discovery score. Default: 6.",
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
    if not args.target and not args.target_all_cases and not args.discover_ioctl_dispatch_all_cases:
        parser.error(
            "at least one --target, --target-all-cases, or --discover-ioctl-dispatch-all-cases is required"
        )
    if args.discover_max_dispatchers < 1:
        parser.error("--discover-max-dispatchers must be at least 1")
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
            values.update(
                int(value)
                for value in flow.recovered_cases
                if not _is_selector_sentinel_case_name(flow.case_names.get(int(value), ""))
            )
        if not values:
            raise RuntimeError("no recovered selector cases for --target-all-cases: %s" % target_name)
        result.extend((target_name, value) for value in sorted(values))
    return result


def _expand_discovered_ioctl_dispatch_targets(
    *,
    max_dispatchers: int,
    min_score: int,
    candidates: list[dict[str, Any]] | None = None,
) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    candidates = candidates if candidates is not None else _discover_ioctl_dispatch_candidates(min_score=min_score)
    for candidate in candidates[:max_dispatchers]:
        target_name = str(candidate.get("name", "") or "")
        if not target_name:
            continue
        capture = capture_function_by_name(target_name)
        if capture is None:
            continue
        plan = build_clean_plan(capture)
        values: set[int] = set()
        for flow in plan.flow_rewrites:
            values.update(int(value) for value in flow.recovered_cases)
        if values:
            result.extend((target_name, value) for value in sorted(values))
    if not result:
        raise RuntimeError("no recovered IOCTL cases from discovered dispatch functions")
    return result


def _discover_ioctl_dispatch_candidates(*, min_score: int = 6) -> list[dict[str, Any]]:
    if ida_funcs is None or ida_hexrays is None or idautils is None:
        return []
    candidates: list[dict[str, Any]] = []
    try:
        function_eas = list(idautils.Functions())
    except Exception:
        function_eas = []
    for ea in function_eas:
        try:
            func = ida_funcs.get_func(ea)
        except Exception:
            func = None
        if func is None:
            continue
        try:
            cfunc = ida_hexrays.decompile(func)
        except Exception:
            cfunc = None
        if cfunc is None:
            continue
        text = _ida_cfunc_text(cfunc)
        score, reasons = _score_ioctl_dispatch_pseudocode(text)
        if score < min_score:
            continue
        try:
            name = ida_funcs.get_func_name(getattr(func, "start_ea", ea)) or ""
        except Exception:
            name = ""
        if not name:
            name = "sub_%X" % int(getattr(func, "start_ea", ea))
        candidates.append(
            {
                "name": name,
                "ea": "0x%X" % int(getattr(func, "start_ea", ea)),
                "score": score,
                "reasons": reasons,
            }
        )
    return sorted(candidates, key=lambda item: (-int(item.get("score", 0) or 0), str(item.get("name", ""))))


def _score_ioctl_dispatch_pseudocode(text: str) -> tuple[int, list[str]]:
    lower = (text or "").lower()
    score = 0
    reasons: list[str] = []
    checks = [
        ("IoGetCurrentIrpStackLocation", "iogetcurrentirpstacklocation", 4),
        ("DeviceIoControl", "deviceiocontrol", 4),
        ("IoControlCode", "iocontrolcode", 4),
        ("InputBufferLength", "inputbufferlength", 2),
        ("OutputBufferLength", "outputbufferlength", 2),
        ("SystemBuffer", "systembuffer", 2),
        ("IoCompleteRequest", "iocompleterequest", 1),
        ("switch", "switch", 1),
        ("case", "case ", 1),
    ]
    for label, needle, weight in checks:
        if needle in lower:
            score += weight
            reasons.append(label)
    if re.search(r"case\s+0x[0-9a-f]+", lower):
        score += 2
        reasons.append("hex_case")
    if re.search(r"0x[0-9a-f]{8,}", lower) and "iocontrolcode" in lower:
        score += 2
        reasons.append("ioctl_constants")
    return score, reasons


def _ida_cfunc_text(cfunc: object) -> str:
    lines: list[str] = []
    try:
        pseudocode = cfunc.get_pseudocode()  # type: ignore[attr-defined]
        for line in pseudocode:
            raw = getattr(line, "line", str(line))
            if idaapi is not None:
                try:
                    raw = idaapi.tag_remove(raw)
                except Exception:
                    pass
            lines.append(str(raw))
    except Exception:
        return str(cfunc)
    return "\n".join(lines)


def _is_selector_sentinel_case_name(name: str) -> bool:
    compact = re.sub(r"[^A-Za-z0-9]", "", name or "").lower()
    if not compact:
        return False
    return compact.startswith("max") and (
        compact.endswith("infoclass")
        or compact.endswith("informationclass")
        or compact.endswith("processinfoclass")
        or compact.endswith("systeminfoclass")
        or compact.endswith("threadinfoclass")
    )


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
        contract_metrics = _contract_metrics(contracts)
        summary.update(contract_metrics)
        summary.update(_zero_contract_context(plan, case_value, contracts))
        summary.update(_helper_capture_metrics(plan, contract_metrics.get("blocking_unresolved_helper_edge_audit", [])))
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
        "blocking_warnings": 0,
        "warning_messages": [],
        "blocking_warning_messages": [],
        "buffer_names": [],
        "helper_edge_audit": [],
        "helper_edge_class_counts": {},
        "helper_path_families": [],
        "unresolved_helper_edge_audit": [],
        "blocking_unresolved_helper_edge_audit": [],
        "layout_field_offsets": 0,
        "layout_bytes_covered": 0,
        "layout_overlap_count": 0,
        "suspicious_layout_offsets": 0,
        "hard_size_requirements": 0,
        "likely_size_predicates": 0,
        "hard_user_field_requirements": 0,
        "likely_user_field_requirements": 0,
        "output_only_field_observations": 0,
        "context_field_observations": 0,
        "field_predicates_total": 0,
        "field_predicates_classified": 0,
        "field_backed_structure_cases": 0,
        "clean_field_backed_structure_cases": 0,
        "structure_quality_cases_passed": 0,
        "size_only_structure_cases": 0,
        "weak_structure_cases": 0,
        "buffer_quality": [],
        "structure_quality_level": "none",
        "structure_quality_score": 0.0,
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
            quality = _buffer_quality_metrics(contract, buffer)
            metrics["buffer_quality"].append(quality)
            for key in (
                "layout_field_offsets",
                "layout_bytes_covered",
                "layout_overlap_count",
                "suspicious_layout_offsets",
                "hard_size_requirements",
                "likely_size_predicates",
                "hard_user_field_requirements",
                "likely_user_field_requirements",
                "output_only_field_observations",
                "context_field_observations",
                "field_predicates_total",
                "field_predicates_classified",
                "field_backed_structure_cases",
                "clean_field_backed_structure_cases",
            ):
                metrics[key] += int(quality.get(key, 0) or 0)
            if quality.get("structure_quality_passed"):
                metrics["structure_quality_cases_passed"] += 1
            if quality.get("structure_quality_level") == "size_only":
                metrics["size_only_structure_cases"] += 1
            if quality.get("structure_quality_level") in {"weak_contract", "suspicious_only"}:
                metrics["weak_structure_cases"] += 1
        edge_metrics = _helper_edge_metrics(getattr(contract, "helper_edges", []) or [])
        metrics["helper_size_constraints"] += edge_metrics["helper_size_constraints"]
        metrics["helper_field_accesses"] += edge_metrics["helper_field_accesses"]
        metrics["helper_field_constraints"] += edge_metrics["helper_field_constraints"]
        metrics["helper_edges_total"] += edge_metrics["helper_edges_total"]
        metrics["helper_edges_resolved"] += edge_metrics["helper_edges_resolved"]
        metrics["helper_edges_unresolved"] += edge_metrics["helper_edges_unresolved"]
        warning_messages.extend(edge_metrics["warning_messages"])
    audit_records = helper_edge_audit_records(contracts)
    blocking_unresolved_audit = blocking_unresolved_helper_edge_records(audit_records)
    blocking_warning_messages = _blocking_warning_messages(warning_messages, blocking_unresolved_audit)
    metrics["warnings"] = len(warning_messages)
    metrics["blocking_warnings"] = len(blocking_warning_messages)
    metrics["warning_messages"] = sorted(set(warning_messages))
    metrics["blocking_warning_messages"] = blocking_warning_messages
    metrics["buffer_names"] = buffer_names
    metrics["helper_edge_audit"] = audit_records
    metrics["helper_edge_class_counts"] = helper_edge_class_counts(audit_records)
    metrics["helper_path_families"] = helper_path_family_records(contracts)
    metrics["unresolved_helper_edge_audit"] = unresolved_helper_edge_records(audit_records)
    metrics["blocking_unresolved_helper_edge_audit"] = blocking_unresolved_audit
    metrics["structure_quality_level"] = _case_structure_quality_level(metrics["buffer_quality"])
    metrics["structure_quality_score"] = _case_structure_quality_score(metrics["buffer_quality"])
    return metrics


def _buffer_quality_metrics(contract: object, buffer: object) -> dict[str, Any]:
    variable = str(getattr(buffer, "variable", "") or "")
    role = str(getattr(buffer, "role", "") or "")
    local_sizes = list(getattr(buffer, "size_constraints", []) or [])
    local_accesses = list(getattr(buffer, "field_accesses", []) or [])
    local_constraints = list(getattr(buffer, "field_constraints", []) or [])
    helper_edges = list(getattr(contract, "helper_edges", []) or [])
    helper_sizes = _edge_size_constraints_for_buffer(helper_edges, variable)
    helper_accesses = _edge_field_accesses_for_buffer(helper_edges, variable)
    helper_constraints = _edge_field_constraints_for_buffer(helper_edges, variable)
    sizes = local_sizes + helper_sizes
    accesses = local_accesses + helper_accesses
    constraints = local_constraints + helper_constraints
    suspicious_accesses = [item for item in accesses if _is_suspicious_layout_access(item)]
    layout_accesses = [
        item
        for item in accesses
        if _field_offset(item) >= 0 and not _is_suspicious_layout_access(item)
    ]
    layout_offsets = sorted({_field_offset(item) for item in layout_accesses if _field_offset(item) >= 0})
    hard_sizes = [item for item in sizes if _has_valid_requirement(item)]
    hard_user_fields = 0
    likely_user_fields = 0
    output_only_fields = 0
    context_fields = 0
    for item in constraints:
        if _field_constraint_user_controlled(role, item, accesses):
            if _has_valid_requirement(item):
                hard_user_fields += 1
            else:
                likely_user_fields += 1
        elif _field_constraint_output_only(role, item, accesses):
            output_only_fields += 1
        else:
            context_fields += 1
    field_predicates_total = len(constraints)
    field_predicates_classified = hard_user_fields + likely_user_fields + output_only_fields + context_fields
    bytes_covered = _covered_layout_bytes(layout_accesses)
    overlap_count = _layout_overlap_count(layout_accesses)
    has_field_layout = bool(layout_offsets)
    has_size_sketch = _has_size_sketch(sizes)
    quality_level = _structure_quality_level(
        has_field_layout=has_field_layout,
        has_size_sketch=has_size_sketch,
        suspicious_count=len(suspicious_accesses),
    )
    quality_score = _structure_quality_score(
        has_field_layout=has_field_layout,
        has_size_sketch=has_size_sketch,
        helper_accesses=helper_accesses,
        overlap_count=overlap_count,
        suspicious_count=len(suspicious_accesses),
    )
    field_backed_structure = 1 if has_field_layout else 0
    clean_field_backed_structure = 1 if has_field_layout and not suspicious_accesses else 0
    return {
        "buffer": variable,
        "role": role,
        "structure": str(getattr(buffer, "structure_name", "") or ""),
        "structure_quality_level": quality_level,
        "structure_quality_score": quality_score,
        "structure_quality_passed": bool(field_backed_structure),
        "field_backed_structure_cases": field_backed_structure,
        "clean_field_backed_structure_cases": clean_field_backed_structure,
        "layout_field_offsets": len(layout_offsets),
        "layout_bytes_covered": bytes_covered,
        "layout_overlap_count": overlap_count,
        "suspicious_layout_offsets": len({_field_offset(item) for item in suspicious_accesses}),
        "hard_size_requirements": len(hard_sizes),
        "likely_size_predicates": max(0, len(sizes) - len(hard_sizes)),
        "hard_user_field_requirements": hard_user_fields,
        "likely_user_field_requirements": likely_user_fields,
        "output_only_field_observations": output_only_fields,
        "context_field_observations": context_fields,
        "field_predicates_total": field_predicates_total,
        "field_predicates_classified": field_predicates_classified,
    }


def _edge_size_constraints_for_buffer(edges: list[object], buffer: str) -> list[object]:
    result: list[object] = []
    for edge in edges:
        for item in getattr(edge, "propagated_size_constraints", []) or []:
            if str(getattr(item, "buffer", "") or "") == buffer:
                result.append(item)
        result.extend(_edge_size_constraints_for_buffer(list(getattr(edge, "nested_edges", []) or []), buffer))
    return result


def _edge_field_accesses_for_buffer(edges: list[object], buffer: str) -> list[object]:
    result: list[object] = []
    for edge in edges:
        for item in getattr(edge, "propagated_field_accesses", []) or []:
            if str(getattr(item, "buffer", "") or "") == buffer:
                result.append(item)
        result.extend(_edge_field_accesses_for_buffer(list(getattr(edge, "nested_edges", []) or []), buffer))
    return result


def _edge_field_constraints_for_buffer(edges: list[object], buffer: str) -> list[object]:
    result: list[object] = []
    for edge in edges:
        for item in getattr(edge, "propagated_field_constraints", []) or []:
            if str(getattr(item, "buffer", "") or "") == buffer:
                result.append(item)
        result.extend(_edge_field_constraints_for_buffer(list(getattr(edge, "nested_edges", []) or []), buffer))
    return result


def _has_valid_requirement(item: object) -> bool:
    relation = str(getattr(item, "valid_relation", "") or "")
    value = str(getattr(item, "valid_value", "") or "")
    return bool(relation and value != "")


def _field_constraint_user_controlled(role: str, constraint: object, accesses: list[object]) -> bool:
    if role == "input":
        return True
    if role != "inout":
        return False
    offset = _field_offset(constraint)
    return any(_field_offset(item) == offset and _is_user_read_access(item) for item in accesses)


def _field_constraint_output_only(role: str, constraint: object, accesses: list[object]) -> bool:
    offset = _field_offset(constraint)
    same_offset = [item for item in accesses if _field_offset(item) == offset]
    if role == "output":
        return not same_offset or all(not _is_user_read_access(item) for item in same_offset)
    if role == "inout" and same_offset:
        return all(_access_kind_text(item) == "write" for item in same_offset)
    return False


def _is_user_read_access(item: object) -> bool:
    access = _access_kind_text(item)
    return access in {"read", "read_write"} or "read" in access


def _access_kind_text(item: object) -> str:
    return str(getattr(item, "access", "") or "").lower()


def _is_suspicious_layout_access(item: object) -> bool:
    source = str(getattr(item, "source", "") or "")
    evidence = str(getattr(item, "evidence", "") or "").lower()
    offset = _field_offset(item)
    if "disasm:" not in source:
        return False
    if offset >= 0x400:
        return True
    return "[rsp+" in evidence or "rsp+" in evidence


def _field_offset(item: object) -> int:
    try:
        return int(getattr(item, "offset", -1))
    except (TypeError, ValueError):
        return -1


def _covered_layout_bytes(accesses: list[object]) -> int:
    intervals = _layout_intervals(accesses)
    if not intervals:
        return 0
    intervals.sort()
    total = 0
    cursor_start, cursor_end = intervals[0]
    for start, end in intervals[1:]:
        if start <= cursor_end:
            cursor_end = max(cursor_end, end)
            continue
        total += cursor_end - cursor_start
        cursor_start, cursor_end = start, end
    total += cursor_end - cursor_start
    return total


def _layout_overlap_count(accesses: list[object]) -> int:
    intervals = _layout_intervals(accesses)
    count = 0
    for index, (start, end) in enumerate(intervals):
        for other_start, other_end in intervals[index + 1:]:
            if other_start < end and start < other_end:
                count += 1
    return count


def _layout_intervals(accesses: list[object]) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for item in accesses:
        offset = _field_offset(item)
        if offset < 0:
            continue
        size = _field_type_size(str(getattr(item, "type", "") or ""))
        result.append((offset, offset + max(1, size)))
    return result


def _field_type_size(type_text: str) -> int:
    normalized = re.sub(r"\s+", " ", (type_text or "").strip()).lower()
    if not normalized:
        return 4
    if any(token in normalized for token in ("_oword", "__int128", "__m128")):
        return 16
    if any(token in normalized for token in ("_qword", "uint64", "int64", "ulonglong", "longlong", "ptr", "handle")):
        return 8
    if any(token in normalized for token in ("_word", "uint16", "int16", "ushort", "wchar")):
        return 2
    if any(token in normalized for token in ("_byte", "uint8", "int8", "uchar", "char", "byte", "bool")):
        return 1
    return 4


def _has_size_sketch(sizes: list[object]) -> bool:
    for item in sizes:
        relation = str(getattr(item, "valid_relation", "") or getattr(item, "relation", "") or "")
        value = str(getattr(item, "valid_value", "") or getattr(item, "value", "") or "")
        if relation in {"==", ">="} and value != "":
            return True
    return False


def _structure_quality_level(
    *,
    has_field_layout: bool,
    has_size_sketch: bool,
    suspicious_count: int,
) -> str:
    if has_field_layout and has_size_sketch:
        return "field_and_size"
    if has_field_layout:
        return "field_layout"
    if has_size_sketch:
        return "size_only"
    if suspicious_count:
        return "suspicious_only"
    return "weak_contract"


def _structure_quality_score(
    *,
    has_field_layout: bool,
    has_size_sketch: bool,
    helper_accesses: list[object],
    overlap_count: int,
    suspicious_count: int,
) -> float:
    score = 0.0
    if has_field_layout:
        score += 0.58
    if has_size_sketch:
        score += 0.28
    if helper_accesses:
        score += 0.08
    if overlap_count == 0:
        score += 0.04
    if suspicious_count == 0:
        score += 0.02
    score -= min(0.25, suspicious_count * 0.08)
    score -= min(0.12, overlap_count * 0.02)
    return round(max(0.0, min(1.0, score)), 3)


def _case_structure_quality_level(buffer_quality: object) -> str:
    items = list(buffer_quality or [])
    if not items:
        return "none"
    levels = {str(item.get("structure_quality_level", "") or "") for item in items if isinstance(item, dict)}
    if "field_and_size" in levels:
        return "field_and_size"
    if "field_layout" in levels:
        return "field_layout"
    if "size_only" in levels:
        return "size_only"
    if "suspicious_only" in levels:
        return "suspicious_only"
    return "weak_contract"


def _case_structure_quality_score(buffer_quality: object) -> float:
    scores = [
        float(item.get("structure_quality_score", 0.0) or 0.0)
        for item in list(buffer_quality or [])
        if isinstance(item, dict)
    ]
    if not scores:
        return 0.0
    return round(max(scores), 3)


def _blocking_warning_messages(
    warning_messages: list[str],
    blocking_unresolved_audit: list[dict[str, Any]],
) -> list[str]:
    if not blocking_unresolved_audit:
        return []
    blocking_callees = {
        str(item.get("callee", "") or "")
        for item in blocking_unresolved_audit
        if str(item.get("callee", "") or "")
    }
    result: list[str] = []
    for message in warning_messages:
        text = str(message or "").strip()
        if not text:
            continue
        if not blocking_callees or any(text == callee or text.startswith(callee + ":") for callee in blocking_callees):
            if text not in result:
                result.append(text)
    if result:
        return sorted(result)
    return sorted({str(item or "").strip() for item in warning_messages if str(item or "").strip()})


def _helper_capture_metrics(plan: object, unresolved_helper_edge_audit: object | None = None) -> dict[str, Any]:
    rule_report = getattr(plan, "rule_report", {}) or {}
    full_ledger = _normalized_helper_capture_ledger(rule_report.get("buffer_contract_helper_capture_ledger", []))
    interesting_names = _unresolved_helper_callee_names(unresolved_helper_edge_audit)
    ledger = _focused_helper_capture_ledger(full_ledger, interesting_names)
    status_counts: dict[str, int] = {}
    unavailable: list[dict[str, Any]] = []
    for item in full_ledger:
        status = str(item.get("status", "") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    for item in ledger:
        status = str(item.get("status", "") or "unknown")
        if status != "captured":
            unavailable.append(item)
    return {
        "helper_capture_ledger": ledger,
        "helper_capture_candidate_count": len(full_ledger),
        "helper_capture_status_counts": dict(sorted(status_counts.items())),
        "helper_capture_unavailable": unavailable,
    }


def _normalized_helper_capture_ledger(raw_ledger: object) -> list[dict[str, Any]]:
    if not isinstance(raw_ledger, list):
        return []
    result: list[dict[str, Any]] = []
    for item in raw_ledger:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "name": str(item.get("name", "") or ""),
                "depth": _int_value(item.get("depth", 0), 0),
                "status": str(item.get("status", "") or "unknown"),
                "reason": str(item.get("reason", "") or ""),
                "ea": str(item.get("ea", "") or ""),
                "captured_name": str(item.get("captured_name", "") or ""),
                "call_count": _int_value(item.get("call_count", 0), 0),
            }
        )
    return result


def _focused_helper_capture_ledger(
    ledger: list[dict[str, Any]],
    interesting_names: set[str],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in ledger:
        name = str(item.get("name", "") or "")
        if not name or name in seen:
            continue
        depth = _int_value(item.get("depth", 0), 0)
        if depth == 1 or name in interesting_names:
            result.append(item)
            seen.add(name)
    return result


def _unresolved_helper_callee_names(records: object | None) -> set[str]:
    if not isinstance(records, list):
        return set()
    result: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        callee = str(record.get("callee", "") or "")
        if callee:
            result.add(callee)
    return result


def _int_value(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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
        "helper_capture_candidates": 0,
        "helper_capture_unavailable": 0,
        "warnings": 0,
        "blocking_warnings": 0,
        "layout_field_offsets": 0,
        "layout_bytes_covered": 0,
        "layout_overlap_count": 0,
        "suspicious_layout_offsets": 0,
        "hard_size_requirements": 0,
        "likely_size_predicates": 0,
        "hard_user_field_requirements": 0,
        "likely_user_field_requirements": 0,
        "output_only_field_observations": 0,
        "context_field_observations": 0,
        "field_predicates_total": 0,
        "field_predicates_classified": 0,
        "field_backed_structure_cases": 0,
        "clean_field_backed_structure_cases": 0,
        "structure_quality_cases_passed": 0,
        "size_only_structure_cases": 0,
        "weak_structure_cases": 0,
    }
    cases: list[dict[str, Any]] = []
    zero_contract_cases: list[str] = []
    warning_cases: list[str] = []
    blocking_warning_cases: list[str] = []
    unresolved_helper_cases: list[str] = []
    helper_edge_class_counts_total: dict[str, int] = {}
    unresolved_helper_edge_audit: list[dict[str, Any]] = []
    blocking_unresolved_helper_edge_audit: list[dict[str, Any]] = []
    helper_capture_unavailable: list[dict[str, Any]] = []
    helper_capture_status_counts_total: dict[str, int] = {}
    path_families: list[dict[str, Any]] = []
    path_families_with_unresolved: list[str] = []
    zero_contract_audit: list[dict[str, Any]] = []
    weak_structure_cases: list[str] = []
    suspicious_layout_cases: list[str] = []
    size_only_structure_cases: list[str] = []
    user_field_requirement_cases: list[str] = []
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
        record_warnings = int(record.get("warnings", 0) or 0)
        record_blocking_warning_messages = list(record.get("blocking_warning_messages", []) or [])
        if "blocking_warnings" in record:
            record_blocking_warnings = int(record.get("blocking_warnings", 0) or 0)
        elif record_blocking_warning_messages:
            record_blocking_warnings = len(record_blocking_warning_messages)
        elif blocking_unresolved_audit:
            record_blocking_warnings = record_warnings
        else:
            record_blocking_warnings = 0
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
            "warnings": record_warnings,
            "blocking_warnings": record_blocking_warnings,
            "warning_messages": list(record.get("warning_messages", []) or []),
            "blocking_warning_messages": record_blocking_warning_messages,
            "helper_edge_class_counts": dict(record.get("helper_edge_class_counts", {}) or {}),
            "helper_edge_audit": list(record.get("helper_edge_audit", []) or []),
            "helper_path_families": list(record.get("helper_path_families", []) or []),
            "unresolved_helper_edge_audit": unresolved_audit,
            "blocking_unresolved_helper_edge_audit": blocking_unresolved_audit,
            "helper_capture_ledger": list(record.get("helper_capture_ledger", []) or []),
            "helper_capture_candidate_count": int(
                record.get("helper_capture_candidate_count", len(record.get("helper_capture_ledger", []) or [])) or 0
            ),
            "helper_capture_status_counts": dict(record.get("helper_capture_status_counts", {}) or {}),
            "helper_capture_unavailable": list(record.get("helper_capture_unavailable", []) or []),
            "zero_contract": dict(record.get("zero_contract", {}) or {}),
            "layout_field_offsets": int(record.get("layout_field_offsets", 0) or 0),
            "layout_bytes_covered": int(record.get("layout_bytes_covered", 0) or 0),
            "layout_overlap_count": int(record.get("layout_overlap_count", 0) or 0),
            "suspicious_layout_offsets": int(record.get("suspicious_layout_offsets", 0) or 0),
            "hard_size_requirements": int(record.get("hard_size_requirements", 0) or 0),
            "likely_size_predicates": int(record.get("likely_size_predicates", 0) or 0),
            "hard_user_field_requirements": int(record.get("hard_user_field_requirements", 0) or 0),
            "likely_user_field_requirements": int(record.get("likely_user_field_requirements", 0) or 0),
            "output_only_field_observations": int(record.get("output_only_field_observations", 0) or 0),
            "context_field_observations": int(record.get("context_field_observations", 0) or 0),
            "field_predicates_total": int(record.get("field_predicates_total", 0) or 0),
            "field_predicates_classified": int(record.get("field_predicates_classified", 0) or 0),
            "field_backed_structure_cases": _record_field_backed_structure_cases(record),
            "clean_field_backed_structure_cases": _record_clean_field_backed_structure_cases(record),
            "structure_quality_cases_passed": int(record.get("structure_quality_cases_passed", 0) or 0),
            "size_only_structure_cases": int(record.get("size_only_structure_cases", 0) or 0),
            "weak_structure_cases": int(record.get("weak_structure_cases", 0) or 0),
            "structure_quality_level": record.get("structure_quality_level", "none"),
            "structure_quality_score": float(record.get("structure_quality_score", 0.0) or 0.0),
            "buffer_quality": list(record.get("buffer_quality", []) or []),
            "text_path": record.get("text_path", ""),
            "json_path": record.get("json_path", ""),
        }
        cases.append(case_entry)
        for key in totals:
            if key == "targets":
                continue
            if key == "blocking_unresolved_helper_edges":
                totals[key] += len(case_entry["blocking_unresolved_helper_edge_audit"])
            elif key == "helper_capture_candidates":
                totals[key] += int(case_entry.get("helper_capture_candidate_count", 0) or 0)
            elif key == "helper_capture_unavailable":
                totals[key] += len(case_entry["helper_capture_unavailable"])
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
        if case_entry["blocking_warnings"]:
            blocking_warning_cases.append(case_label)
        if case_entry["helper_edges_unresolved"]:
            unresolved_helper_cases.append(case_label)
        if case_entry["weak_structure_cases"]:
            weak_structure_cases.append(case_label)
        if case_entry["suspicious_layout_offsets"]:
            suspicious_layout_cases.append(case_label)
        if case_entry["size_only_structure_cases"]:
            size_only_structure_cases.append(case_label)
        if case_entry["hard_user_field_requirements"] or case_entry["likely_user_field_requirements"]:
            user_field_requirement_cases.append(case_label)
        for classification, count in case_entry["helper_edge_class_counts"].items():
            helper_edge_class_counts_total[str(classification)] = (
                helper_edge_class_counts_total.get(str(classification), 0) + int(count or 0)
            )
        for status, count in case_entry["helper_capture_status_counts"].items():
            helper_capture_status_counts_total[str(status)] = (
                helper_capture_status_counts_total.get(str(status), 0) + int(count or 0)
            )
        for item in case_entry["helper_capture_unavailable"]:
            helper_capture_unavailable.append(
                {
                    "case": case_label,
                    "case_value": case_entry.get("case_value"),
                    "command_name": case_entry.get("command_name", ""),
                    **item,
                }
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
        blocking_warning_cases=blocking_warning_cases,
        unresolved_helper_cases=unresolved_helper_cases,
        blocking_unresolved_helper_edge_audit=blocking_unresolved_helper_edge_audit,
        helper_edge_class_counts=helper_edge_class_counts_total,
        path_families=path_families,
        zero_contract_audit=zero_contract_audit,
    )
    quality_gate = _build_quality_gate(totals, cases)
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
        "blocking_warning_cases": blocking_warning_cases,
        "unresolved_helper_cases": unresolved_helper_cases,
        "weak_structure_cases": weak_structure_cases,
        "suspicious_layout_cases": suspicious_layout_cases,
        "size_only_structure_cases": size_only_structure_cases,
        "user_field_requirement_cases": user_field_requirement_cases,
        "helper_edge_class_counts": dict(sorted(helper_edge_class_counts_total.items())),
        "helper_capture_status_counts": dict(sorted(helper_capture_status_counts_total.items())),
        "helper_capture_unavailable": helper_capture_unavailable,
        "unresolved_helper_edge_audit": unresolved_helper_edge_audit,
        "blocking_unresolved_helper_edge_audit": blocking_unresolved_helper_edge_audit,
        "path_family_count": len(path_families),
        "path_families_with_unresolved": path_families_with_unresolved,
        "path_families": path_families,
        "recovery_gate": recovery_gate,
        "quality_gate": quality_gate,
        "cases": cases,
    }


def _build_quality_gate(totals: dict[str, int], cases: list[dict[str, Any]]) -> dict[str, Any]:
    buffer_cases = [
        item
        for item in cases
        if int(item.get("buffers", 0) or 0) > 0
    ]
    total_buffer_cases = len(buffer_cases)
    field_backed_cases = sum(
        1
        for item in buffer_cases
        if int(item.get("field_backed_structure_cases", 0) or 0) > 0
    )
    clean_field_backed_cases = sum(
        1
        for item in buffer_cases
        if int(item.get("clean_field_backed_structure_cases", 0) or 0) > 0
    )
    structure_ratio = (field_backed_cases / total_buffer_cases) if total_buffer_cases else 1.0
    clean_structure_ratio = (
        clean_field_backed_cases / total_buffer_cases
    ) if total_buffer_cases else 1.0
    field_total = int(totals.get("field_predicates_total", 0) or 0)
    field_classified = int(totals.get("field_predicates_classified", 0) or 0)
    field_ratio = (field_classified / field_total) if field_total else 1.0
    checks = [
        {
            "name": "structure_quality_90_percent",
            "passed": structure_ratio >= 0.90,
            "detail": "field_backed=%d total=%d ratio=%.3f" % (
                field_backed_cases,
                total_buffer_cases,
                structure_ratio,
            ),
        },
        {
            "name": "clean_structure_quality_90_percent",
            "passed": clean_structure_ratio >= 0.90,
            "detail": "clean_field_backed=%d total=%d ratio=%.3f" % (
                clean_field_backed_cases,
                total_buffer_cases,
                clean_structure_ratio,
            ),
        },
        {
            "name": "field_predicate_classification_95_percent",
            "passed": field_ratio >= 0.95,
            "detail": "classified=%d total=%d ratio=%.3f" % (
                field_classified,
                field_total,
                field_ratio,
            ),
        },
    ]
    passed = all(bool(item["passed"]) for item in checks)
    return {
        "schema": "pseudoforge_selector_quality_gate_v1",
        "status": "passed" if passed else "incomplete",
        "level": "quality_ledger_candidate" if passed else "quality_gaps_present",
        "passed": passed,
        "structure_quality_ratio": round(structure_ratio, 3),
        "clean_structure_quality_ratio": round(clean_structure_ratio, 3),
        "field_predicate_classification_ratio": round(field_ratio, 3),
        "checks": checks,
        "blockers": [item["name"] for item in checks if not bool(item["passed"])],
    }


def _record_field_backed_structure_cases(record: dict[str, Any]) -> int:
    explicit = record.get("field_backed_structure_cases")
    if explicit is not None:
        return int(explicit or 0)
    buffer_quality = list(record.get("buffer_quality", []) or [])
    if buffer_quality:
        return sum(
            1
            for item in buffer_quality
            if isinstance(item, dict) and int(item.get("layout_field_offsets", 0) or 0) > 0
        )
    return 1 if int(record.get("layout_field_offsets", 0) or 0) > 0 else 0


def _record_clean_field_backed_structure_cases(record: dict[str, Any]) -> int:
    explicit = record.get("clean_field_backed_structure_cases")
    if explicit is not None:
        return int(explicit or 0)
    buffer_quality = list(record.get("buffer_quality", []) or [])
    if buffer_quality:
        return sum(
            1
            for item in buffer_quality
            if (
                isinstance(item, dict)
                and int(item.get("layout_field_offsets", 0) or 0) > 0
                and int(item.get("suspicious_layout_offsets", 0) or 0) == 0
            )
        )
    if int(record.get("layout_field_offsets", 0) or 0) <= 0:
        return 0
    return 1 if int(record.get("suspicious_layout_offsets", 0) or 0) == 0 else 0


def _build_recovery_gate(
    *,
    status_counts: dict[str, int],
    totals: dict[str, int],
    zero_contract_cases: list[str],
    warning_cases: list[str],
    blocking_warning_cases: list[str],
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
            "name": "no_blocking_warning_cases",
            "passed": not blocking_warning_cases,
            "detail": "warning_cases=%d blocking_warning_cases=%d"
            % (len(warning_cases), len(blocking_warning_cases)),
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
        "helper_capture_candidates",
        "helper_capture_unavailable",
        "warnings",
        "blocking_warnings",
        "layout_field_offsets",
        "layout_bytes_covered",
        "layout_overlap_count",
        "suspicious_layout_offsets",
        "hard_size_requirements",
        "likely_size_predicates",
        "hard_user_field_requirements",
        "likely_user_field_requirements",
        "output_only_field_observations",
        "context_field_observations",
        "field_predicates_total",
        "field_predicates_classified",
        "field_backed_structure_cases",
        "clean_field_backed_structure_cases",
        "structure_quality_cases_passed",
        "size_only_structure_cases",
        "weak_structure_cases",
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
            "- Blocking-warning cases: %s" % _markdown_case_list(summary.get("blocking_warning_cases", [])),
            "- Unresolved-helper cases: %s" % _markdown_case_list(summary.get("unresolved_helper_cases", [])),
            "- Weak-structure cases: %s" % _markdown_case_list(summary.get("weak_structure_cases", [])),
            "- Suspicious-layout cases: %s" % _markdown_case_list(summary.get("suspicious_layout_cases", [])),
            "- Size-only structure cases: %s" % _markdown_case_list(summary.get("size_only_structure_cases", [])),
            "- User-field requirement cases: %s" % _markdown_case_list(summary.get("user_field_requirement_cases", [])),
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
    quality_gate = dict(summary.get("quality_gate", {}) or {})
    lines.extend(["## Recovery Quality Ledger", ""])
    if quality_gate:
        lines.extend(
            [
                "- Status: `%s`" % quality_gate.get("status", ""),
                "- Level: `%s`" % quality_gate.get("level", ""),
                "- Field-backed structure ratio: `%s`" % quality_gate.get("structure_quality_ratio", ""),
                "- Clean field-backed structure ratio: `%s`"
                % quality_gate.get("clean_structure_quality_ratio", ""),
                "- Field predicate classification ratio: `%s`"
                % quality_gate.get("field_predicate_classification_ratio", ""),
                "",
                "| Check | Passed | Detail |",
                "| --- | --- | --- |",
            ]
        )
        for check in quality_gate.get("checks", []) or []:
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
        lines.extend(["No recovery quality gate was produced.", ""])
    quality_cases = [
        case
        for case in summary.get("cases", []) or []
        if int(case.get("buffers", 0) or 0) > 0
    ]
    if quality_cases:
        lines.extend(
            [
                "| Case | Name | Struct Quality | Score | Offsets | Bytes | Field-Backed | Clean | Hard Size | Hard Fields | Likely Fields | Output Observations | Suspicious |",
                "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for case in quality_cases:
            lines.append(
                "| `%s` | %s | `%s` | %.3f | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
                % (
                    case.get("case", ""),
                    _markdown_table_text(str(case.get("command_name", "") or "")),
                    _markdown_table_text(str(case.get("structure_quality_level", "") or "")),
                    float(case.get("structure_quality_score", 0.0) or 0.0),
                    case.get("layout_field_offsets", 0),
                    case.get("layout_bytes_covered", 0),
                    case.get("field_backed_structure_cases", 0),
                    case.get("clean_field_backed_structure_cases", 0),
                    case.get("hard_size_requirements", 0),
                    case.get("hard_user_field_requirements", 0),
                    case.get("likely_user_field_requirements", 0),
                    case.get("output_only_field_observations", 0),
                    case.get("suspicious_layout_offsets", 0),
                )
            )
        lines.append("")
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
    capture_counts = dict(summary.get("helper_capture_status_counts", {}) or {})
    capture_unavailable = list(summary.get("helper_capture_unavailable", []) or [])
    lines.extend(["## Helper Capture Ledger", ""])
    if capture_counts:
        lines.extend(["| Status | Count |", "| --- | ---: |"])
        for status, count in capture_counts.items():
            lines.append("| `%s` | %s |" % (_markdown_table_text(str(status)), count))
        lines.append("")
    else:
        lines.extend(["No helper capture candidates were recorded.", ""])
    if capture_unavailable:
        lines.extend(
            [
                "### Uncaptured Helper Candidates",
                "",
                "| Case | Helper | Status | Depth | Reason |",
                "| --- | --- | --- | ---: | --- |",
            ]
        )
        for item in capture_unavailable:
            lines.append(
                "| `%s` | `%s` | `%s` | %s | %s |"
                % (
                    item.get("case", ""),
                    _markdown_table_text(str(item.get("name", "") or "")),
                    _markdown_table_text(str(item.get("status", "") or "")),
                    item.get("depth", ""),
                    _markdown_table_text(str(item.get("reason", "") or "")),
                )
            )
        lines.append("")
    else:
        lines.extend(["Uncaptured helper candidates: none", ""])
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

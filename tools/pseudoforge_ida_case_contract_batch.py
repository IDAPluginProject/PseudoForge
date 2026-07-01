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
            reporter.write(record)
            if record.get("status") != "ok":
                exit_code = 1
                if args.stop_on_error:
                    break
        reporter.write(
            {
                "event": "summary",
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "exit_code": exit_code,
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
            "contracts": len(contracts),
            "helpers": _count_helper_edges(contracts),
            "buffers": sum(len(contract.buffers) for contract in contracts),
            "text_path": str(text_path),
            "json_path": str(json_path),
            "report_kind": "selector_path",
            "helper_depth": helper_depth,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
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

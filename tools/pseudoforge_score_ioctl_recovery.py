from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    report = score_ioctl_recovery(
        manifest_path=Path(args.manifest),
        recovered_dir=Path(args.recovered_dir),
    )
    output = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0 if float(report["overall_score"]) >= float(args.min_score) else 1


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score PseudoForge IOCTL recovery against a ground-truth manifest.")
    parser.add_argument("--manifest", required=True, help="Ground-truth ioctl_contracts.json path.")
    parser.add_argument("--recovered-dir", required=True, help="Directory containing PseudoForge case artifacts.")
    parser.add_argument("--out", default="", help="Optional JSON output path.")
    parser.add_argument("--min-score", default=0.95, type=float, help="Minimum acceptable score. Default: 0.95.")
    return parser.parse_args(argv)


def score_ioctl_recovery(*, manifest_path: Path, recovered_dir: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    recovered = _load_recovered_contracts(recovered_dir)
    coverage_cases = _load_coverage_cases(recovered_dir)
    case_reports: list[dict[str, Any]] = []
    totals = {
        "case": [0.0, 0.0],
        "size": [0.0, 0.0],
        "field": [0.0, 0.0],
        "predicate": [0.0, 0.0],
    }
    for expected in manifest.get("ioctls", []) or []:
        case_report = _score_case(expected, recovered, coverage_cases)
        case_reports.append(case_report)
        for key in totals:
            earned, possible = case_report["components"][key]
            totals[key][0] += float(earned)
            totals[key][1] += float(possible)
    component_scores = {
        key: _ratio(earned, possible)
        for key, (earned, possible) in totals.items()
    }
    earned_total = sum(item[0] for item in totals.values())
    possible_total = sum(item[1] for item in totals.values())
    return {
        "schema": "pseudoforge_ioctl_recovery_score_v1",
        "manifest": str(manifest_path),
        "recovered_dir": str(recovered_dir),
        "overall_score": round(_ratio(earned_total, possible_total), 4),
        "component_scores": component_scores,
        "earned": round(earned_total, 3),
        "possible": round(possible_total, 3),
        "cases": case_reports,
    }


def _score_case(
    expected: dict[str, Any],
    recovered: dict[int, list[dict[str, Any]]],
    coverage_cases: set[int],
) -> dict[str, Any]:
    code = _to_int(expected.get("code"))
    contracts = recovered.get(code, [])
    seen = bool(contracts) or code in coverage_cases
    role = str(expected.get("role", "") or "")
    components = {
        "case": [1.0 if seen else 0.0, 1.0],
        "size": [0.0, 0.0],
        "field": [0.0, 0.0],
        "predicate": [0.0, 0.0],
    }
    if role == "none":
        no_buffers = seen and not any(contract.get("buffers") for contract in contracts)
        components["field"] = [1.0 if no_buffers else 0.0, 1.0]
        return _case_result(expected, components, seen, "no_buffer_control")

    size_constraints = _contract_size_constraints(contracts)
    for key, length_kind in (("required_input_size", "input"), ("required_output_size", "output")):
        expected_size = _to_int(expected.get(key))
        if expected_size is None:
            continue
        components["size"][1] += 1.0
        if _size_requirement_recovered(size_constraints, expected_size, length_kind):
            components["size"][0] += 1.0

    recovered_fields = _contract_field_accesses(contracts)
    expected_fields = list(expected.get("fields", []) or [])
    components["field"][1] = float(len(expected_fields))
    for field in expected_fields:
        offset = _to_int(field.get("offset"))
        size = _to_int(field.get("size"))
        if _field_recovered(recovered_fields, offset, size):
            components["field"][0] += 1.0

    recovered_predicates = _contract_field_constraints(contracts)
    expected_predicates = list(expected.get("requirements", []) or [])
    components["predicate"][1] = float(len(expected_predicates))
    for predicate in expected_predicates:
        components["predicate"][0] += _predicate_credit(recovered_predicates, predicate)

    return _case_result(expected, components, seen, "buffer_contract")


def _case_result(
    expected: dict[str, Any],
    components: dict[str, list[float]],
    seen: bool,
    kind: str,
) -> dict[str, Any]:
    earned = sum(item[0] for item in components.values())
    possible = sum(item[1] for item in components.values())
    return {
        "name": expected.get("name", ""),
        "code": expected.get("code", ""),
        "kind": kind,
        "seen": seen,
        "score": round(_ratio(earned, possible), 4),
        "components": components,
    }


def _load_recovered_contracts(recovered_dir: Path) -> dict[int, list[dict[str, Any]]]:
    result: dict[int, list[dict[str, Any]]] = {}
    for path in recovered_dir.glob("*.buffer-contracts.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for contract in payload if isinstance(payload, list) else []:
            code = _to_int(contract.get("command_value"))
            if code is None:
                continue
            result.setdefault(code, []).append(contract)
    return result


def _load_coverage_cases(recovered_dir: Path) -> set[int]:
    path = recovered_dir / "selector-coverage-summary.json"
    if not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    result: set[int] = set()
    for item in payload.get("cases", []) or []:
        value = _to_int(item.get("case_value"))
        if value is not None:
            result.add(value)
    return result


def _contract_size_constraints(contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for contract in contracts:
        for buffer in contract.get("buffers", []) or []:
            result.extend(buffer.get("size_constraints", []) or [])
        for edge in _iter_edges(contract.get("helper_edges", []) or []):
            result.extend(edge.get("propagated_size_constraints", []) or [])
    return result


def _contract_field_accesses(contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for contract in contracts:
        for buffer in contract.get("buffers", []) or []:
            result.extend(buffer.get("field_accesses", []) or [])
        for edge in _iter_edges(contract.get("helper_edges", []) or []):
            result.extend(edge.get("propagated_field_accesses", []) or [])
    return result


def _contract_field_constraints(contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for contract in contracts:
        for buffer in contract.get("buffers", []) or []:
            result.extend(buffer.get("field_constraints", []) or [])
        for edge in _iter_edges(contract.get("helper_edges", []) or []):
            result.extend(edge.get("propagated_field_constraints", []) or [])
    return result


def _iter_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for edge in edges:
        result.append(edge)
        result.extend(_iter_edges(edge.get("nested_edges", []) or []))
    return result


def _size_requirement_recovered(constraints: list[dict[str, Any]], expected_size: int, length_kind: str) -> bool:
    for item in constraints:
        value = _to_int(item.get("valid_value") or item.get("value"))
        if value != expected_size:
            continue
        relation = str(item.get("valid_relation") or item.get("relation") or "")
        if relation not in {"==", ">="}:
            continue
        length_name = str(item.get("length", "") or "").lower()
        if length_kind == "input" and "output" in length_name:
            continue
        if length_kind == "output" and "input" in length_name:
            continue
        return True
    return False


def _field_recovered(fields: list[dict[str, Any]], expected_offset: int | None, expected_size: int | None) -> bool:
    if expected_offset is None:
        return False
    expected_size = expected_size or 0
    for item in fields:
        offset = _to_int(item.get("offset"))
        if offset is None:
            continue
        if offset == expected_offset and expected_size <= 0:
            return True
        recovered_size = _type_size(str(item.get("type", "") or ""))
        if offset == expected_offset and (recovered_size == expected_size or recovered_size <= 0):
            return True
        if expected_size > 0 and recovered_size > 0:
            if offset <= expected_offset and expected_offset + expected_size <= offset + recovered_size:
                return True
    if expected_size <= 0:
        return False
    covered: set[int] = set()
    for item in fields:
        offset = _to_int(item.get("offset"))
        if offset is None:
            continue
        recovered_size = _type_size(str(item.get("type", "") or ""))
        if recovered_size <= 0:
            continue
        covered.update(range(offset, offset + recovered_size))
    if all(byte in covered for byte in range(expected_offset, expected_offset + expected_size)):
        return True
    return False


def _predicate_credit(predicates: list[dict[str, Any]], expected: dict[str, Any]) -> float:
    expected_offset = _to_int(expected.get("offset"))
    expected_relation = str(expected.get("relation", "") or "")
    expected_value = _normalize_int_text(expected.get("value"))
    expected_mask = _normalize_int_text(expected.get("mask"))
    offset_seen = False
    for item in predicates:
        if _to_int(item.get("offset")) != expected_offset:
            continue
        offset_seen = True
        relation = str(item.get("valid_relation") or item.get("relation") or "")
        value = _normalize_int_text(item.get("valid_value") or item.get("value"))
        mask = _normalize_int_text(item.get("mask"))
        if relation == expected_relation and value == expected_value and (not expected_mask or mask == expected_mask):
            return 1.0
    return 0.5 if offset_seen else 0.0


def _type_size(type_text: str) -> int:
    normalized = re.sub(r"\s+", " ", type_text.strip()).lower()
    if not normalized:
        return 0
    if any(token in normalized for token in ("_oword", "__int128", "__m128")):
        return 16
    if any(token in normalized for token in ("_qword", "uint64", "int64", "ulonglong", "longlong", "handle", "ptr")):
        return 8
    if any(token in normalized for token in ("_word", "uint16", "int16", "ushort", "wchar")):
        return 2
    if any(token in normalized for token in ("_byte", "uint8", "int8", "uchar", "char", "byte", "bool")):
        return 1
    return 4


def _to_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _normalize_int_text(value: object) -> str:
    parsed = _to_int(value)
    if parsed is None:
        return str(value or "")
    return str(parsed)


def _ratio(earned: float, possible: float) -> float:
    if possible <= 0:
        return 1.0
    return float(earned) / float(possible)


if __name__ == "__main__":
    raise SystemExit(main())

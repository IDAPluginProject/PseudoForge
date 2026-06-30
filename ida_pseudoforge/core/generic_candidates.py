from __future__ import annotations

import re
from collections import Counter
from typing import Any

from ida_pseudoforge.core.dense_structural_hints import synthetic_aggregate_json_payload
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture


SCHEMA = "pseudoforge_generic_candidates_v1"
REPORT_MODE = "report-only"

FIELD_COMMENT_KINDS = {
    "inferred_offset_field_preview",
    "inferred_offset_field_aliases",
    "inferred_offset_field_hot_cluster",
}

LAYOUT_COMMENT_KINDS = {
    "dense_accumulator_block",
    "dense_stack_local_region",
    "inferred_offset_field_hot_cluster",
    "inferred_offset_indexed_callback_table_evidence",
    "inferred_offset_layout",
    "inferred_offset_parameter_indexed_element",
    "inferred_offset_rewrite_blockers",
    "inferred_offset_rewrite_near_ready",
    "inferred_offset_rewrite_partial_opportunity",
    "inferred_offset_rewrite_ready",
    "review_only_struct_candidate",
}


def generic_candidate_json_payload(capture: FunctionCapture, plan: CleanPlan) -> dict[str, Any]:
    comments = [item for item in plan.comments if isinstance(item, dict)]
    blockers_by_base = _blockers_by_base(comments)
    type_candidates = _type_candidates(plan)
    field_candidates = _field_candidates(comments, blockers_by_base)
    layout_candidates = _layout_candidates(comments, blockers_by_base)
    blocker_counts = Counter()
    for candidate in [*type_candidates, *field_candidates, *layout_candidates]:
        for blocker in candidate.get("blockers", []) or []:
            blocker_counts[str(blocker)] += 1
    return {
        "schema": SCHEMA,
        "mode": REPORT_MODE,
        "function": capture.name,
        "function_ea": "0x%X" % capture.ea,
        "candidate_count": len(type_candidates) + len(field_candidates) + len(layout_candidates),
        "type_candidate_count": len(type_candidates),
        "field_candidate_count": len(field_candidates),
        "layout_candidate_count": len(layout_candidates),
        "rewrite_eligible_count": 0,
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "type_candidates": type_candidates,
        "field_candidates": field_candidates,
        "layout_candidates": layout_candidates,
    }


def render_generic_candidate_report(payload: dict[str, Any]) -> str:
    lines = [
        "# PseudoForge Generic Type/Layout Candidates",
        "",
        "Report-only candidate side view. No IDB type, name, or body rewrite is applied by this artifact.",
        "",
        "- Function: `%s`" % str(payload.get("function", "") or ""),
        "- EA: `%s`" % str(payload.get("function_ea", "") or ""),
        "- Type candidates: `%d`" % int(payload.get("type_candidate_count", 0) or 0),
        "- Field candidates: `%d`" % int(payload.get("field_candidate_count", 0) or 0),
        "- Layout candidates: `%d`" % int(payload.get("layout_candidate_count", 0) or 0),
        "- Rewrite eligible candidates: `0`",
        "",
        "## Layout Candidates",
        "",
    ]
    lines.extend(_layout_candidate_table(payload.get("layout_candidates", []) or []))
    lines.extend(["", "## Field Candidates", ""])
    lines.extend(_field_candidate_table(payload.get("field_candidates", []) or []))
    lines.extend(["", "## Type Candidates", ""])
    lines.extend(_type_candidate_table(payload.get("type_candidates", []) or []))
    return "\n".join(lines).rstrip() + "\n"


def generic_candidate_summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_count": int(payload.get("candidate_count", 0) or 0),
        "type_candidates": int(payload.get("type_candidate_count", 0) or 0),
        "field_candidates": int(payload.get("field_candidate_count", 0) or 0),
        "layout_candidates": int(payload.get("layout_candidate_count", 0) or 0),
        "rewrite_eligible": int(payload.get("rewrite_eligible_count", 0) or 0),
        "blocker_counts": dict(payload.get("blocker_counts", {}) or {}),
    }


def _type_candidates(plan: CleanPlan) -> list[dict[str, Any]]:
    payload = synthetic_aggregate_json_payload(plan)
    candidates = []
    for index, aggregate in enumerate(payload.get("aggregates", []) or []):
        if not isinstance(aggregate, dict):
            continue
        base = str(aggregate.get("base", "") or aggregate.get("display_name", "") or "")
        blockers = _string_list(aggregate.get("safety_blockers"))
        blockers.extend(_string_list(aggregate.get("projection_blockers")))
        candidates.append(
            {
                "id": "type:%s:%d" % (base or "aggregate", index),
                "kind": "synthetic_aggregate_type",
                "mode": REPORT_MODE,
                "rewrite_eligible": False,
                "base": base,
                "candidate_type": str(aggregate.get("synthetic_name", "") or ""),
                "display_name": str(aggregate.get("display_name", "") or ""),
                "aggregate_kind": str(aggregate.get("aggregate_kind", "") or ""),
                "confidence": float(aggregate.get("confidence", 0.0) or 0.0),
                "confidence_tier": str(aggregate.get("confidence_tier", "") or ""),
                "field_count": len(aggregate.get("fields", []) or []),
                "size_hint": int(aggregate.get("size_hint", 0) or 0),
                "evidence": _string_list(aggregate.get("evidence")),
                "blockers": _dedupe_strings(blockers),
            }
        )
    return candidates


def _field_candidates(
    comments: list[dict[str, Any]],
    blockers_by_base: dict[str, list[str]],
) -> list[dict[str, Any]]:
    result = []
    seen: set[tuple[str, int, str, str]] = set()
    for comment in comments:
        kind = str(comment.get("kind", "") or "")
        if kind not in FIELD_COMMENT_KINDS:
            continue
        base = _comment_base(comment)
        fields = [item for item in comment.get("fields", []) or [] if isinstance(item, dict)]
        for field in fields:
            offset = _int_value(field.get("offset"), 0)
            name = str(field.get("name", "") or "")
            type_text = str(field.get("type", "") or "unknown")
            key = (base, offset, name, type_text)
            if key in seen:
                continue
            seen.add(key)
            result.append(
                {
                    "id": "field:%s:0x%X:%s" % (base or "base", offset, name or "field"),
                    "kind": "offset_field_candidate",
                    "source_kind": kind,
                    "mode": REPORT_MODE,
                    "rewrite_eligible": False,
                    "base": base,
                    "base_kind": str(comment.get("base_kind", "") or ""),
                    "offset": offset,
                    "name": name,
                    "type": type_text,
                    "size": _int_value(field.get("size"), 0),
                    "access_count": _int_value(field.get("access_count"), _int_value(comment.get("access_count"), 0)),
                    "confidence": float(field.get("confidence", comment.get("confidence", 0.0)) or 0.0),
                    "evidence": _field_evidence(kind, field),
                    "blockers": _candidate_blockers(base, comment, blockers_by_base),
                }
            )
    result.sort(key=lambda item: (str(item.get("base", "")), int(item.get("offset", 0)), str(item.get("name", ""))))
    return result


def _layout_candidates(
    comments: list[dict[str, Any]],
    blockers_by_base: dict[str, list[str]],
) -> list[dict[str, Any]]:
    result = []
    seen: set[tuple[str, str]] = set()
    for index, comment in enumerate(comments):
        kind = str(comment.get("kind", "") or "")
        if kind not in LAYOUT_COMMENT_KINDS:
            continue
        base = _comment_base(comment)
        key = (kind, base or str(index))
        if key in seen:
            continue
        seen.add(key)
        offsets = _comment_offsets(comment)
        locals_ = _string_list(comment.get("locals"))
        result.append(
            {
                "id": "layout:%s:%s:%d" % (kind, base or "region", index),
                "kind": _layout_candidate_kind(kind),
                "source_kind": kind,
                "mode": REPORT_MODE,
                "rewrite_eligible": False,
                "base": base,
                "base_kind": str(comment.get("base_kind", "") or ""),
                "offsets": offsets,
                "offset_count": _int_value(comment.get("offset_count"), len(offsets)),
                "access_count": _int_value(
                    comment.get("access_count"),
                    _int_value(
                        comment.get("field_count"),
                        _int_value(comment.get("local_count"), _comment_access_count(comment)),
                    ),
                ),
                "local_region": locals_,
                "stride": _int_value(comment.get("stride"), 0),
                "confidence": float(comment.get("confidence", 0.0) or 0.0),
                "evidence": _layout_evidence(comment),
                "blockers": _candidate_blockers(base, comment, blockers_by_base),
                "text": str(comment.get("text", "") or ""),
            }
        )
    result.sort(key=lambda item: (str(item.get("base", "")), str(item.get("source_kind", ""))))
    return result


def _blockers_by_base(comments: list[dict[str, Any]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for comment in comments:
        if str(comment.get("kind", "") or "") != "inferred_offset_rewrite_blockers":
            continue
        base = _comment_base(comment)
        if not base:
            continue
        result.setdefault(base, []).extend(_string_list(comment.get("blockers")))
    return {base: _dedupe_strings(blockers) for base, blockers in result.items()}


def _candidate_blockers(
    base: str,
    comment: dict[str, Any],
    blockers_by_base: dict[str, list[str]],
) -> list[str]:
    blockers = []
    blockers.extend(blockers_by_base.get(base, []))
    blockers.extend(_string_list(comment.get("blockers")))
    if not blockers:
        blockers.append("report-only generic candidate; no body rewrite in this artifact")
    return _dedupe_strings(blockers)


def _comment_base(comment: dict[str, Any]) -> str:
    base = str(comment.get("base", "") or "").strip()
    if base:
        return base
    text = str(comment.get("text", "") or "")
    for prefix in (
        "Offset layout hint:",
        "Review-only struct candidate for",
        "Stack local region",
        "Stack array block",
    ):
        if prefix not in text:
            continue
        tail = text.split(prefix, 1)[1].strip()
        token = tail.split(" ", 1)[0].strip(":,")
        if token:
            return token
    return ""


def _comment_offsets(comment: dict[str, Any]) -> list[int]:
    offsets = []
    for key in ("offsets", "safe_offsets", "allowed_offsets"):
        value = comment.get(key)
        if isinstance(value, list):
            offsets.extend(_int_value(item, 0) for item in value)
    for field in comment.get("fields", []) or []:
        if isinstance(field, dict):
            offsets.append(_int_value(field.get("offset"), 0))
    text = str(comment.get("text", "") or "")
    for match in re.finditer(r"\+0x([0-9A-Fa-f]+)", text):
        try:
            offsets.append(int(match.group(1), 16))
        except ValueError:
            continue
    return sorted(dict.fromkeys(offset for offset in offsets if offset >= 0))


def _comment_access_count(comment: dict[str, Any]) -> int:
    text = str(comment.get("text", "") or "")
    match = re.search(r"(\d+)\s+typed dereference", text)
    if match:
        return _int_value(match.group(1), 0)
    match = re.search(r"(\d+)\s+indexed/callback access", text)
    if match:
        return _int_value(match.group(1), 0)
    return 0


def _layout_candidate_kind(kind: str) -> str:
    if kind in {"dense_accumulator_block", "dense_stack_local_region"}:
        return "local_region_candidate"
    if kind == "review_only_struct_candidate":
        return "strided_record_candidate"
    if kind == "inferred_offset_indexed_callback_table_evidence":
        return "indexed_table_candidate"
    if kind == "inferred_offset_parameter_indexed_element":
        return "parameter_indexed_element_candidate"
    if "rewrite" in kind:
        return "layout_rewrite_gate"
    return "offset_layout_candidate"


def _layout_evidence(comment: dict[str, Any]) -> list[str]:
    evidence = []
    kind = str(comment.get("kind", "") or "")
    if kind:
        evidence.append(kind)
    if comment.get("fields"):
        evidence.append("field_candidates")
    if comment.get("locals"):
        evidence.append("local_region")
    if comment.get("source_provenance"):
        evidence.append("source_provenance:%s" % str(comment.get("source_provenance")))
    if comment.get("domain_profile_id"):
        evidence.append("domain_profile:%s" % str(comment.get("domain_profile_id")))
    return _dedupe_strings(evidence)


def _field_evidence(kind: str, field: dict[str, Any]) -> list[str]:
    evidence = [kind]
    evidence.extend(_string_list(field.get("evidence")))
    if field.get("profile_confidence"):
        evidence.append("domain_profile_field")
    return _dedupe_strings(evidence)


def _layout_candidate_table(candidates: list[Any]) -> list[str]:
    if not candidates:
        return ["No layout candidates."]
    lines = [
        "| Base | Kind | Confidence | Offsets | Accesses | Blockers |",
        "| --- | --- | ---: | --- | ---: | --- |",
    ]
    for item in candidates[:40]:
        candidate = item if isinstance(item, dict) else {}
        lines.append(
            "| `%s` | `%s` | %.2f | %s | %s | %s |"
            % (
                _md(candidate.get("base", "")),
                _md(candidate.get("kind", "")),
                float(candidate.get("confidence", 0.0) or 0.0),
                _offset_text(candidate.get("offsets", []) or []),
                _int_value(candidate.get("access_count"), 0),
                _list_text(candidate.get("blockers", []) or []),
            )
        )
    return lines


def _field_candidate_table(candidates: list[Any]) -> list[str]:
    if not candidates:
        return ["No field candidates."]
    lines = [
        "| Base | Offset | Name | Type | Confidence | Blockers |",
        "| --- | ---: | --- | --- | ---: | --- |",
    ]
    for item in candidates[:60]:
        candidate = item if isinstance(item, dict) else {}
        lines.append(
            "| `%s` | `+0x%X` | `%s` | `%s` | %.2f | %s |"
            % (
                _md(candidate.get("base", "")),
                _int_value(candidate.get("offset"), 0),
                _md(candidate.get("name", "")),
                _md(candidate.get("type", "")),
                float(candidate.get("confidence", 0.0) or 0.0),
                _list_text(candidate.get("blockers", []) or []),
            )
        )
    return lines


def _type_candidate_table(candidates: list[Any]) -> list[str]:
    if not candidates:
        return ["No type candidates."]
    lines = [
        "| Base | Type | Kind | Fields | Confidence | Blockers |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    for item in candidates[:40]:
        candidate = item if isinstance(item, dict) else {}
        lines.append(
            "| `%s` | `%s` | `%s` | %s | %.2f | %s |"
            % (
                _md(candidate.get("base", "")),
                _md(candidate.get("candidate_type", "")),
                _md(candidate.get("aggregate_kind", "")),
                _int_value(candidate.get("field_count"), 0),
                float(candidate.get("confidence", 0.0) or 0.0),
                _list_text(candidate.get("blockers", []) or []),
            )
        )
    return lines


def _offset_text(offsets: list[Any]) -> str:
    values = [_int_value(item, 0) for item in offsets[:8]]
    if not values:
        return "none"
    text = ", ".join("`+0x%X`" % value for value in values)
    if len(offsets) > len(values):
        text += ", ..."
    return text


def _list_text(values: list[Any]) -> str:
    items = [str(item) for item in values if str(item)]
    if not items:
        return "none"
    shown = items[:3]
    text = ", ".join("`%s`" % _md(item) for item in shown)
    if len(items) > len(shown):
        text += ", ..."
    return text


def _md(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, tuple):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def _dedupe_strings(values: list[str]) -> list[str]:
    return list(dict.fromkeys(str(item) for item in values if str(item)))


def _int_value(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)

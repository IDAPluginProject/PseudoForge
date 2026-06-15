from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


_OFFSET_DEREF_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[A-Za-z_][A-Za-z0-9_:\s]*?)\s*\*\s*\)\s*"
    r"\(\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
)

_SCALAR_BASE_WORDS = {
    "count",
    "flags",
    "flag",
    "index",
    "length",
    "result",
    "size",
    "status",
    "value",
}

_GENERIC_BASE_NAMES = {
    "context",
    "entry",
    "item",
    "node",
    "object",
    "parameters",
    "params",
    "record",
}


@dataclass(slots=True)
class _LayoutEvidence:
    base: str
    offsets: dict[int, set[str]] = field(default_factory=dict)
    access_count: int = 0


def field_layout_comments(text: str, max_comments: int = 4) -> list[dict[str, Any]]:
    layouts = _collect_layouts(text or "")
    candidates = [
        item
        for item in layouts.values()
        if _has_enough_layout_evidence(item)
    ]
    candidates.sort(key=lambda item: (-len(item.offsets), -item.access_count, item.base.lower()))
    comments = []
    for item in candidates[:max(0, int(max_comments or 0))]:
        comments.append(_comment_from_layout(item))
        preview = _field_preview_comment_from_layout(item)
        if preview:
            comments.append(preview)
    return comments


def _collect_layouts(text: str) -> dict[str, _LayoutEvidence]:
    layouts: dict[str, _LayoutEvidence] = {}
    for match in _OFFSET_DEREF_RE.finditer(text):
        base = match.group("base")
        if _is_scalar_like_base(base):
            continue
        offset = _parse_offset(match.group("offset"))
        if offset is None or offset <= 0:
            continue
        type_name = _normalize_type_name(match.group("type"))
        if not type_name:
            continue
        layout = layouts.setdefault(base, _LayoutEvidence(base=base))
        layout.access_count += 1
        layout.offsets.setdefault(offset, set()).add(type_name)
    return layouts


def _has_enough_layout_evidence(layout: _LayoutEvidence) -> bool:
    distinct_offsets = len(layout.offsets)
    if _is_decompiler_temp_base(layout.base) or _is_generic_named_base(layout.base):
        return distinct_offsets >= 8 and layout.access_count >= 12
    if distinct_offsets >= 3 and layout.access_count >= 3:
        return True
    return distinct_offsets >= 2 and layout.access_count >= 6


def _comment_from_layout(layout: _LayoutEvidence) -> dict[str, Any]:
    offsets = sorted(layout.offsets)
    shown_offsets = offsets[:8]
    offset_text = ", ".join("+0x%X" % offset for offset in shown_offsets)
    if len(offsets) > len(shown_offsets):
        offset_text += ", ..."
    type_names = sorted({type_name for types in layout.offsets.values() for type_name in types})
    type_text = ", ".join(type_names[:4])
    if len(type_names) > 4:
        type_text += ", ..."
    base_kind = _layout_base_kind(layout.base)
    confidence = min(
        _confidence_cap_for_base_kind(base_kind),
        0.68 + len(offsets) * 0.03 + min(layout.access_count, 12) * 0.005,
    )
    return {
        "kind": "inferred_offset_layout",
        "text": (
            "Offset layout hint: %s has %d typed dereference(s) across %d offset(s) "
            "%s; observed types: %s. %s"
            % (layout.base, layout.access_count, len(offsets), offset_text, type_text, _review_text_for_base_kind(base_kind))
        ),
        "confidence": round(confidence, 2),
        "base_kind": base_kind,
    }


def _field_preview_comment_from_layout(layout: _LayoutEvidence) -> dict[str, Any] | None:
    base_kind = _layout_base_kind(layout.base)
    if base_kind == "named":
        if len(layout.offsets) < 5 or layout.access_count < 5:
            return None
    elif len(layout.offsets) < 8 or layout.access_count < 12:
        return None
    fields = _preview_fields(layout)
    if not fields:
        return None
    field_text = "; ".join("+0x%X %s %s" % (item["offset"], item["type"], item["name"]) for item in fields[:8])
    if len(fields) > 8:
        field_text += "; ..."
    confidence = min(
        _field_preview_confidence_cap_for_base_kind(base_kind),
        0.62 + len(layout.offsets) * 0.025 + min(layout.access_count, 12) * 0.005,
    )
    return {
        "kind": "inferred_offset_field_preview",
        "text": _field_preview_text(layout.base, base_kind, field_text),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "fields": fields,
    }


def _preview_fields(layout: _LayoutEvidence) -> list[dict[str, Any]]:
    fields = []
    for offset in sorted(layout.offsets):
        fields.append(
            {
                "offset": offset,
                "name": "field_%X" % offset,
                "type": _preview_type_name(layout.offsets[offset]),
            }
        )
    return fields


def _preview_type_name(type_names: set[str]) -> str:
    cleaned = [item for item in sorted(type_names) if item]
    if not cleaned:
        return "unknown"
    if len(cleaned) == 1:
        return cleaned[0]
    return "mixed(%s)" % "/".join(cleaned[:3])


def _parse_offset(value: str) -> int | None:
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
    except ValueError:
        return None


def _normalize_type_name(type_name: str) -> str:
    text = " ".join(str(type_name or "").replace("const ", "").split())
    if not text:
        return ""
    if len(text) > 48:
        return ""
    return text


def _is_scalar_like_base(name: str) -> bool:
    lower = str(name or "").lower()
    if _is_generic_argument_base(lower) or _is_bugcheck_parameter_base(lower):
        return True
    if lower in _SCALAR_BASE_WORDS:
        return True
    return any(lower.endswith(word) for word in _SCALAR_BASE_WORDS)


def _is_decompiler_temp_base(name: str) -> bool:
    return re.fullmatch(r"[av]\d+", str(name or "")) is not None


def _is_generic_named_base(name: str) -> bool:
    return str(name or "").lower() in _GENERIC_BASE_NAMES


def _is_generic_argument_base(name: str) -> bool:
    return re.fullmatch(r"argument\d+", str(name or "")) is not None


def _is_bugcheck_parameter_base(name: str) -> bool:
    return re.fullmatch(r"bugcheckparameter\d+", str(name or "")) is not None


def _layout_base_kind(name: str) -> str:
    if _is_decompiler_temp_base(name):
        return "temp"
    if _is_generic_named_base(name):
        return "generic"
    return "named"


def _confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.74
    if base_kind == "generic":
        return 0.78
    return 0.86


def _field_preview_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.7
    if base_kind == "generic":
        return 0.74
    return 0.82


def _field_preview_text(base: str, base_kind: str, field_text: str) -> str:
    if base_kind == "temp":
        return (
            "Review fields for %s (temporary base): %s. Review only; no IDB type or pseudocode rewrite was applied."
            % (base, field_text)
        )
    if base_kind == "generic":
        return (
            "Review fields for %s (generic base): %s. Review only; no IDB type or pseudocode rewrite was applied."
            % (base, field_text)
        )
    return (
        "Preview fields for %s: %s. Preview only; no IDB type or pseudocode rewrite was applied."
        % (base, field_text)
    )


def _review_text_for_base_kind(base_kind: str) -> str:
    if base_kind == "temp":
        return "Review as a high-evidence temporary base before inferring a structure."
    if base_kind == "generic":
        return "Review as a generic base before inferring a structure."
    return "Review as an inferred structure base."

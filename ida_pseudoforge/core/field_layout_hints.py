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

_REWRITE_OFFSET_THRESHOLD_BLOCKER = "rewrite offset threshold requires at least 8 offsets"
_REWRITE_ACCESS_THRESHOLD_BLOCKER = "rewrite access threshold requires at least 12 accesses"
_REWRITE_THRESHOLD_BLOCKERS = {
    _REWRITE_OFFSET_THRESHOLD_BLOCKER,
    _REWRITE_ACCESS_THRESHOLD_BLOCKER,
}
_NARROW_SUBFIELD_OVERLAY_BLOCKER = "one or more offsets mix narrow subfield access widths"
_WIDE_SUBFIELD_OVERLAY_BLOCKER = "one or more offsets mix wide overlay access widths"
_IRREGULAR_SUBFIELD_OVERLAY_BLOCKER = "one or more offsets mix irregular field access widths"


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
            alias_preview = _field_alias_comment_from_layout(item)
            if alias_preview:
                comments.append(alias_preview)
                overlay_preview = _field_subfield_overlay_comment_from_layout(text or "", item)
                if overlay_preview:
                    comments.append(overlay_preview)
                    narrow_preview = _field_narrow_subfield_comment_from_layout(text or "", item)
                    if narrow_preview:
                        comments.append(narrow_preview)
                blocker = _field_rewrite_blocker_comment(text or "", item)
                if blocker:
                    comments.append(blocker)
                    near_ready = _field_rewrite_near_ready_comment(item, blocker)
                    if near_ready:
                        comments.append(near_ready)
                else:
                    ready = _field_rewrite_ready_comment(item)
                    if ready:
                        comments.append(ready)
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


def _field_alias_comment_from_layout(layout: _LayoutEvidence) -> dict[str, Any] | None:
    base_kind = _layout_base_kind(layout.base)
    if base_kind == "named":
        if len(layout.offsets) < 5 or layout.access_count < 5:
            return None
    elif len(layout.offsets) < 8 or layout.access_count < 12:
        return None
    fields = _preview_fields(layout)
    if not fields:
        return None
    alias_text = "; ".join(
        "%s=+0x%X %s" % (item["name"], item["offset"], item["type"])
        for item in fields[:8]
    )
    if len(fields) > 8:
        alias_text += "; ..."
    confidence = min(
        _field_alias_confidence_cap_for_base_kind(base_kind),
        0.58 + len(layout.offsets) * 0.025 + min(layout.access_count, 12) * 0.005,
    )
    return {
        "kind": "inferred_offset_field_aliases",
        "text": _field_alias_text(layout.base, base_kind, alias_text),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "fields": fields,
    }


def _field_subfield_overlay_comment_from_layout(text: str, layout: _LayoutEvidence) -> dict[str, Any] | None:
    overlays = _subfield_overlay_fields(layout, text)
    if not overlays:
        return None
    base_kind = _layout_base_kind(layout.base)
    overlay_text = "; ".join(
        _subfield_overlay_field_text(item)
        for item in overlays[:6]
    )
    if len(overlays) > 6:
        overlay_text += "; ..."
    confidence = min(
        _field_subfield_overlay_confidence_cap_for_base_kind(base_kind),
        0.6 + len(overlays) * 0.04 + min(layout.access_count, 12) * 0.005,
    )
    return {
        "kind": "inferred_offset_subfield_overlays",
        "text": _field_subfield_overlay_text(layout.base, base_kind, overlay_text),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "overlays": overlays,
    }


def _field_narrow_subfield_comment_from_layout(text: str, layout: _LayoutEvidence) -> dict[str, Any] | None:
    fields = [
        item
        for item in _subfield_overlay_fields(layout, text)
        if item.get("policy_class") == "narrow_subfield"
    ]
    if not fields:
        return None
    base_kind = _layout_base_kind(layout.base)
    field_text = "; ".join(
        _subfield_overlay_field_text(item)
        for item in fields[:6]
    )
    if len(fields) > 6:
        field_text += "; ..."
    confidence = min(
        _field_narrow_subfield_confidence_cap_for_base_kind(base_kind),
        0.62 + len(fields) * 0.04 + min(layout.access_count, 12) * 0.005,
    )
    return {
        "kind": "inferred_offset_narrow_subfields",
        "text": _field_narrow_subfield_text(layout.base, base_kind, field_text),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "fields": fields,
    }


def _field_rewrite_blocker_comment(text: str, layout: _LayoutEvidence) -> dict[str, Any] | None:
    blockers = _field_rewrite_blockers(text, layout)
    if not blockers:
        return None
    base_kind = _layout_base_kind(layout.base)
    confidence = min(
        _field_rewrite_blocker_confidence_cap_for_base_kind(base_kind),
        0.64 + min(len(blockers), 4) * 0.03 + min(layout.access_count, 12) * 0.005,
    )
    return {
        "kind": "inferred_offset_rewrite_blockers",
        "text": (
            "Offset field rewrite blocked for %s: %s. Review-only aliases remain available."
            % (layout.base, "; ".join(blockers[:6]))
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "blockers": blockers,
    }


def _field_rewrite_ready_comment(layout: _LayoutEvidence) -> dict[str, Any] | None:
    base_kind = _layout_base_kind(layout.base)
    if base_kind != "named":
        return None
    if len(layout.offsets) < 8 or layout.access_count < 12:
        return None
    confidence = min(
        0.8,
        0.66 + len(layout.offsets) * 0.02 + min(layout.access_count, 16) * 0.005,
    )
    return {
        "kind": "inferred_offset_rewrite_ready",
        "text": (
            "Offset field rewrite candidate for %s: %d typed dereference(s) across %d offset(s), no rewrite blockers found. Audit only; body rewrite was not applied."
            % (layout.base, layout.access_count, len(layout.offsets))
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "offset_count": len(layout.offsets),
        "access_count": layout.access_count,
    }


def _field_rewrite_near_ready_comment(
    layout: _LayoutEvidence,
    blocker: dict[str, Any],
) -> dict[str, Any] | None:
    base_kind = _layout_base_kind(layout.base)
    if base_kind != "named":
        return None
    blockers = {
        str(item)
        for item in blocker.get("blockers", []) or []
        if str(item)
    }
    if len(blockers) != 1 or not blockers.issubset(_REWRITE_THRESHOLD_BLOCKERS):
        return None
    missing = "offset" if _REWRITE_OFFSET_THRESHOLD_BLOCKER in blockers else "access"
    if missing == "offset" and (len(layout.offsets) < 5 or layout.access_count < 12):
        return None
    if missing == "access" and (len(layout.offsets) < 8 or layout.access_count < 8):
        return None
    confidence = min(
        0.76,
        0.61 + len(layout.offsets) * 0.02 + min(layout.access_count, 16) * 0.005,
    )
    return {
        "kind": "inferred_offset_rewrite_near_ready",
        "text": (
            "Offset field rewrite near-ready for %s: %d typed dereference(s) across %d offset(s), missing %s threshold only. Audit only; body rewrite was not applied."
            % (layout.base, layout.access_count, len(layout.offsets), missing)
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "missing_threshold": missing,
        "offset_count": len(layout.offsets),
        "access_count": layout.access_count,
    }


def _field_rewrite_blockers(text: str, layout: _LayoutEvidence) -> list[str]:
    blockers: list[str] = []
    base_kind = _layout_base_kind(layout.base)
    if base_kind == "temp":
        blockers.append("base is a decompiler temporary")
    elif base_kind == "generic":
        blockers.append("base name is generic")
    blockers.extend(_field_rewrite_threshold_blockers(layout))
    blockers.extend(_mixed_offset_type_blockers(layout))
    if _has_volatile_access_type(layout):
        blockers.append("volatile-looking access type is present")
    if _has_unaligned_field_access(layout):
        blockers.append("one or more typed offsets are not naturally aligned")
    if _is_mmio_like_base(layout.base):
        blockers.append("base name looks MMIO/register-backed")
    blockers.extend(_base_change_blockers(text, layout.base))
    if _base_address_taken(text, layout.base):
        blockers.append("base address is taken")
    if _base_has_array_index_use(text, layout.base):
        blockers.append("base is also indexed like an array")
    return list(dict.fromkeys(blockers))


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


def _subfield_overlay_fields(layout: _LayoutEvidence, text: str = "") -> list[dict[str, Any]]:
    fields = []
    for offset, type_names in sorted(layout.offsets.items()):
        sizes = sorted({
            size
            for size in (_field_type_storage_size(type_name) for type_name in type_names)
            if size > 0
        })
        if len(sizes) <= 1:
            continue
        if any(_field_type_storage_size(type_name) <= 0 for type_name in type_names):
            continue
        size_class = _subfield_overlay_size_class(sizes)
        interpretation = _subfield_overlay_interpretation(text, layout.base, offset, size_class)
        fields.append(
            {
                "offset": offset,
                "name": "field_%X" % offset,
                "sizes": sizes,
                "size_class": size_class,
                "policy_class": _subfield_overlay_policy_class(size_class),
                "interpretation": interpretation,
                "types": sorted(type_names),
            }
        )
    return fields


def _subfield_overlay_field_text(item: dict[str, Any]) -> str:
    text = "+0x%X %s uses %s-byte accesses (%s)" % (
        item["offset"],
        item["name"],
        "/".join(str(size) for size in item["sizes"]),
        "/".join(item["types"][:4]),
    )
    interpretation = str(item.get("interpretation", "") or "")
    if interpretation:
        text += " [%s]" % interpretation
    return text


def _subfield_overlay_size_class(sizes: list[int]) -> str:
    normalized = sorted({int(size) for size in sizes if int(size) > 0})
    if normalized == [1, 2]:
        return "byte_word"
    if normalized == [1, 4]:
        return "byte_dword"
    if normalized == [2, 4]:
        return "word_dword"
    if normalized == [4, 8]:
        return "dword_qword"
    if normalized == [8, 16]:
        return "qword_oword"
    return "mixed_width"


def _subfield_overlay_policy_class(size_class: str) -> str:
    if size_class in {"byte_word", "byte_dword", "word_dword"}:
        return "narrow_subfield"
    if size_class in {"dword_qword", "qword_oword"}:
        return "wide_overlay"
    return "irregular_overlay"


def _subfield_overlay_interpretation(text: str, base: str, offset: int, size_class: str) -> str:
    if _subfield_overlay_has_bitwise_access(text, base, offset):
        return "bitfield_candidate"
    policy_class = _subfield_overlay_policy_class(size_class)
    if policy_class == "narrow_subfield":
        return "packed_field_candidate"
    if policy_class == "wide_overlay":
        return "union_overlay_candidate"
    return "ambiguous_overlay"


def _subfield_overlay_has_bitwise_access(text: str, base: str, offset: int) -> bool:
    if not text:
        return False
    for match in _OFFSET_DEREF_RE.finditer(text):
        if match.group("base") != base:
            continue
        parsed_offset = _parse_offset(match.group("offset"))
        if parsed_offset != offset:
            continue
        line = _line_at(text, match.start(), match.end())
        if _line_has_bitwise_field_operation(line):
            return True
    return False


def _line_at(text: str, start: int, end: int) -> str:
    line_start = text.rfind("\n", 0, max(0, start)) + 1
    line_end = text.find("\n", max(0, end))
    if line_end < 0:
        line_end = len(text)
    return text[line_start:line_end]


def _line_has_bitwise_field_operation(line: str) -> bool:
    return re.search(r"(&=|\|=|\^=|<<|>>|\s[&|^]\s|_bittest|_interlockedbittest)", line or "") is not None


def _preview_type_name(type_names: set[str]) -> str:
    cleaned = [item for item in sorted(type_names) if item]
    if not cleaned:
        return "unknown"
    if len(cleaned) == 1:
        return cleaned[0]
    return "mixed(%s)" % "/".join(cleaned[:3])


def _field_rewrite_threshold_blockers(layout: _LayoutEvidence) -> list[str]:
    blockers: list[str] = []
    if len(layout.offsets) < 8:
        blockers.append(_REWRITE_OFFSET_THRESHOLD_BLOCKER)
    if layout.access_count < 12:
        blockers.append(_REWRITE_ACCESS_THRESHOLD_BLOCKER)
    return blockers


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


def _field_alias_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.66
    if base_kind == "generic":
        return 0.7
    return 0.78


def _field_subfield_overlay_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.66
    if base_kind == "generic":
        return 0.7
    return 0.76


def _field_narrow_subfield_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.68
    if base_kind == "generic":
        return 0.72
    return 0.78


def _field_rewrite_blocker_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.74
    if base_kind == "generic":
        return 0.76
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


def _field_alias_text(base: str, base_kind: str, alias_text: str) -> str:
    if base_kind == "temp":
        return (
            "Review aliases for %s (temporary base): %s. Review-only shorthand; do not treat as a recovered structure type."
            % (base, alias_text)
        )
    if base_kind == "generic":
        return (
            "Review aliases for %s (generic base): %s. Review-only shorthand; do not treat as a recovered structure type."
            % (base, alias_text)
        )
    return (
        "Alias map for %s: %s. Use as review-only shorthand for repeated offset dereferences."
        % (base, alias_text)
    )


def _field_subfield_overlay_text(base: str, base_kind: str, overlay_text: str) -> str:
    if base_kind == "temp":
        return (
            "Review subfield overlays for %s (temporary base): %s. Review-only evidence; field rewrite remains blocked for mixed-width offsets."
            % (base, overlay_text)
        )
    if base_kind == "generic":
        return (
            "Review subfield overlays for %s (generic base): %s. Review-only evidence; field rewrite remains blocked for mixed-width offsets."
            % (base, overlay_text)
        )
    return (
        "Subfield overlay evidence for %s: %s. Review-only; field rewrite remains blocked for mixed-width offsets."
        % (base, overlay_text)
    )


def _field_narrow_subfield_text(base: str, base_kind: str, field_text: str) -> str:
    if base_kind == "temp":
        return (
            "Review narrow subfields for %s (temporary base): %s. Audit-only; body rewrite remains disabled until the parent structure is trusted."
            % (base, field_text)
        )
    if base_kind == "generic":
        return (
            "Review narrow subfields for %s (generic base): %s. Audit-only; body rewrite remains disabled until the parent structure is trusted."
            % (base, field_text)
        )
    return (
        "Narrow subfield candidates for %s: %s. Audit-only; body rewrite remains disabled until the parent structure is trusted."
        % (base, field_text)
    )


def _review_text_for_base_kind(base_kind: str) -> str:
    if base_kind == "temp":
        return "Review as a high-evidence temporary base before inferring a structure."
    if base_kind == "generic":
        return "Review as a generic base before inferring a structure."
    return "Review as an inferred structure base."


def _mixed_offset_type_blockers(layout: _LayoutEvidence) -> list[str]:
    blockers: list[str] = []
    partial_width_blockers: set[str] = set()
    has_incompatible_type_conflict = False
    for types in layout.offsets.values():
        storage_classes = {_field_type_storage_class(type_name) for type_name in types}
        if len(storage_classes) <= 1:
            continue
        if all(item.startswith("size:") for item in storage_classes):
            sizes = [
                _field_type_storage_size(type_name)
                for type_name in types
            ]
            size_class = _subfield_overlay_size_class(sizes)
            partial_width_blockers.add(_subfield_overlay_policy_blocker(size_class))
        else:
            has_incompatible_type_conflict = True
    for blocker in (
        _NARROW_SUBFIELD_OVERLAY_BLOCKER,
        _WIDE_SUBFIELD_OVERLAY_BLOCKER,
        _IRREGULAR_SUBFIELD_OVERLAY_BLOCKER,
    ):
        if blocker in partial_width_blockers:
            blockers.append(blocker)
    if has_incompatible_type_conflict:
        blockers.append("one or more offsets have incompatible access type classes")
    return blockers


def _subfield_overlay_policy_blocker(size_class: str) -> str:
    policy_class = _subfield_overlay_policy_class(size_class)
    if policy_class == "narrow_subfield":
        return _NARROW_SUBFIELD_OVERLAY_BLOCKER
    if policy_class == "wide_overlay":
        return _WIDE_SUBFIELD_OVERLAY_BLOCKER
    return _IRREGULAR_SUBFIELD_OVERLAY_BLOCKER


def _has_volatile_access_type(layout: _LayoutEvidence) -> bool:
    return any(
        "volatile" in type_name.lower()
        for types in layout.offsets.values()
        for type_name in types
    )


def _has_unaligned_field_access(layout: _LayoutEvidence) -> bool:
    for offset, types in layout.offsets.items():
        for type_name in types:
            alignment = _natural_type_alignment(type_name)
            if alignment and offset % alignment != 0:
                return True
    return False


def _field_type_storage_class(type_name: str) -> str:
    normalized = " ".join(str(type_name or "").replace("volatile ", "").replace("const ", "").split())
    lowered = normalized.lower()
    if lowered in {"char", "signed char", "unsigned char", "_byte", "byte", "uchar", "boolean", "bool"}:
        return "size:1"
    if lowered in {
        "__int16",
        "unsigned __int16",
        "short",
        "unsigned short",
        "_word",
        "word",
        "ushort",
        "wchar_t",
    }:
        return "size:2"
    if lowered in {
        "__int32",
        "unsigned __int32",
        "int",
        "unsigned int",
        "long",
        "unsigned long",
        "_dword",
        "dword",
        "ulong",
        "ntstatus",
    }:
        return "size:4"
    if lowered in {"__int64", "unsigned __int64", "_qword", "qword", "ulong64", "size_t", "ssize_t"}:
        return "size:8"
    if lowered in {"__int128", "unsigned __int128", "_oword", "oword", "xmmword"}:
        return "size:16"
    if re.fullmatch(r"P[A-Z0-9_]+", normalized):
        return "size:8"
    return "type:%s" % lowered


def _field_type_storage_size(type_name: str) -> int:
    storage_class = _field_type_storage_class(type_name)
    if not storage_class.startswith("size:"):
        return 0
    try:
        return int(storage_class.split(":", 1)[1])
    except ValueError:
        return 0


def _natural_type_alignment(type_name: str) -> int:
    normalized = " ".join(str(type_name or "").replace("volatile ", "").split())
    lowered = normalized.lower()
    if lowered in {"char", "signed char", "unsigned char", "_byte", "byte", "uchar", "boolean"}:
        return 1
    if lowered in {"short", "unsigned short", "_word", "word", "ushort", "wchar_t"}:
        return 2
    if lowered in {"int", "unsigned int", "long", "unsigned long", "_dword", "dword", "ulong", "ntstatus"}:
        return 4
    if lowered in {"__int64", "unsigned __int64", "_qword", "qword", "ulong64", "size_t"}:
        return 8
    if re.fullmatch(r"P[A-Z0-9_]+", normalized):
        return 8
    return 0


def _is_mmio_like_base(name: str) -> bool:
    lowered = str(name or "").lower()
    return any(token in lowered for token in ("mmio", "mappedio", "register", "bar", "csr", "port"))


def _base_change_blockers(text: str, base: str) -> list[str]:
    blockers: list[str] = []
    if _base_is_incremented(text, base):
        blockers.append("base is incremented or decremented")
    assignments = _base_direct_assignments(text, base)
    if not assignments:
        return blockers
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        blockers.append("base assignment order cannot be proven")
        return blockers
    simple_assignments = [item for item in assignments if item.group("op") == "="]
    if len(simple_assignments) != len(assignments):
        blockers.append("base uses compound assignment")
    pre_access_rhs = [
        _normalize_assignment_rhs(item.group("rhs"))
        for item in simple_assignments
        if item.start() < first_access
    ]
    distinct_pre_access_rhs = {item for item in pre_access_rhs if item}
    if len(distinct_pre_access_rhs) > 1:
        blockers.append("base has multiple initializers before layout access")
    stable_rhs = pre_access_rhs[-1] if pre_access_rhs else ""
    stable_reload_sources = set()
    if stable_rhs:
        stable_reload_sources.add(stable_rhs)
    stable_reload_sources.update(_stable_aliases_for_base_before_access(text, base, first_access))
    for assignment in simple_assignments:
        if assignment.start() < first_access:
            continue
        rhs = _normalize_assignment_rhs(assignment.group("rhs"))
        if rhs in stable_reload_sources:
            continue
        blockers.append("base is reassigned after layout access")
        break
    return blockers


def _base_is_incremented(text: str, base: str) -> bool:
    escaped = re.escape(base)
    return bool(
        re.search(r"(?m)^\s*%s\s*(?:\+\+|--)" % escaped, text or "")
        or re.search(r"(?m)^\s*(?:\+\+|--)\s*%s\b" % escaped, text or "")
    )


def _base_direct_assignments(text: str, base: str) -> list[re.Match[str]]:
    pattern = re.compile(
        r"(?m)^\s*%s\s*(?P<op>\+=|-=|\*=|/=|%%=|&=|\|=|\^=|=)(?!=)\s*(?P<rhs>[^;\n]*);\s*(?://[^\n]*)?$"
        % re.escape(base)
    )
    return list(pattern.finditer(text or ""))


def _stable_aliases_for_base_before_access(text: str, base: str, first_access: int) -> set[str]:
    aliases: set[str] = set()
    if first_access < 0:
        return aliases
    pattern = re.compile(
        r"(?m)^\s*(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^;\n]*\)\s*)?%s\s*;\s*(?://[^\n]*)?$"
        % re.escape(base)
    )
    for match in pattern.finditer(text or ""):
        if match.start() >= first_access:
            continue
        alias = match.group("alias")
        if alias == base:
            continue
        alias_assignments = _base_direct_assignments(text, alias)
        if len(alias_assignments) != 1:
            continue
        if alias_assignments[0].start() != match.start():
            continue
        aliases.add(alias)
    return aliases


def _normalize_assignment_rhs(value: str) -> str:
    return " ".join(str(value or "").strip().split())


def _first_layout_access_start(text: str, base: str) -> int:
    for match in _OFFSET_DEREF_RE.finditer(text or ""):
        if match.group("base") == base:
            return match.start()
    return -1


def _base_address_taken(text: str, base: str) -> bool:
    return re.search(r"&\s*%s\b" % re.escape(base), text or "") is not None


def _base_has_array_index_use(text: str, base: str) -> bool:
    return re.search(r"\b%s\s*\[" % re.escape(base), text or "") is not None

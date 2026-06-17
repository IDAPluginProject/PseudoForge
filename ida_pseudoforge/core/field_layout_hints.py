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
_TRUSTED_STABLE_BASE_SOURCE_PROVENANCES = {
    "direct_argument_alias",
    "direct_call_result_alias",
    "named_call_result_alias",
    "parameter_field_pointer_alias",
    "parameter_indexed_pointer_alias",
    "parameter_subobject_pointer_alias",
}
_NARROW_SUBFIELD_OVERLAY_BLOCKER = "one or more offsets mix narrow subfield access widths"
_WIDE_SUBFIELD_OVERLAY_BLOCKER = "one or more offsets mix wide overlay access widths"
_IRREGULAR_SUBFIELD_OVERLAY_BLOCKER = "one or more offsets mix irregular field access widths"
_INCOMPATIBLE_ACCESS_TYPE_BLOCKER = "one or more offsets have incompatible access type classes"
_UNALIGNED_TYPED_OFFSET_BLOCKER = "one or more typed offsets are not naturally aligned"
_VOLATILE_ACCESS_TYPE_BLOCKER = "volatile-looking access type is present"
_OFFSET_LOCAL_TYPE_BLOCKERS = {
    _NARROW_SUBFIELD_OVERLAY_BLOCKER,
    _WIDE_SUBFIELD_OVERLAY_BLOCKER,
    _IRREGULAR_SUBFIELD_OVERLAY_BLOCKER,
    _INCOMPATIBLE_ACCESS_TYPE_BLOCKER,
    _UNALIGNED_TYPED_OFFSET_BLOCKER,
    _VOLATILE_ACCESS_TYPE_BLOCKER,
}
_BASE_STABILITY_BLOCKER_FRAGMENTS = (
    "multiple initializers",
    "reassigned after layout access",
    "assignment order cannot be proven",
    "compound assignment",
    "incremented or decremented",
    "address is taken",
    "indexed like an array",
)
_MAX_BASE_STABILITY_RHS_SAMPLES = 4
_LAYOUT_TYPE_STORAGE_SIZES = {
    "__int8": 1,
    "signed __int8": 1,
    "unsigned __int8": 1,
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "_byte": 1,
    "byte": 1,
    "uchar": 1,
    "boolean": 1,
    "bool": 1,
    "__int16": 2,
    "signed __int16": 2,
    "unsigned __int16": 2,
    "short": 2,
    "signed short": 2,
    "unsigned short": 2,
    "_word": 2,
    "word": 2,
    "ushort": 2,
    "wchar_t": 2,
    "__int32": 4,
    "signed __int32": 4,
    "unsigned __int32": 4,
    "int": 4,
    "signed int": 4,
    "unsigned int": 4,
    "long": 4,
    "signed long": 4,
    "unsigned long": 4,
    "_dword": 4,
    "dword": 4,
    "ulong": 4,
    "ntstatus": 4,
    "__int64": 8,
    "signed __int64": 8,
    "unsigned __int64": 8,
    "long long": 8,
    "signed long long": 8,
    "unsigned long long": 8,
    "_qword": 8,
    "qword": 8,
    "ulong64": 8,
    "size_t": 8,
    "ssize_t": 8,
    "__int128": 16,
    "signed __int128": 16,
    "unsigned __int128": 16,
    "_oword": 16,
    "oword": 16,
    "xmmword": 16,
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
            alias_preview = _field_alias_comment_from_layout(item)
            if alias_preview:
                comments.append(alias_preview)
                source_preview = _field_stable_base_source_comment_from_layout(text or "", item)
                if source_preview:
                    comments.append(source_preview)
                generic_base_evidence = _field_generic_base_evidence_comment_from_layout(text or "", item)
                if generic_base_evidence:
                    comments.append(generic_base_evidence)
                trust_candidate = _field_generic_base_trust_candidate_comment_from_layout(text or "", item)
                if trust_candidate:
                    comments.append(trust_candidate)
                overlay_preview = _field_subfield_overlay_comment_from_layout(text or "", item)
                if overlay_preview:
                    comments.append(overlay_preview)
                    narrow_preview = _field_narrow_subfield_comment_from_layout(text or "", item)
                    if narrow_preview:
                        comments.append(narrow_preview)
                    bitfield_alias_preview = _field_bitfield_alias_comment_from_layout(text or "", item)
                    if bitfield_alias_preview:
                        comments.append(bitfield_alias_preview)
                blocker = _field_rewrite_blocker_comment(text or "", item)
                if blocker:
                    comments.append(blocker)
                    stability = _field_base_stability_comment_from_layout(text or "", item, blocker)
                    if stability:
                        comments.append(stability)
                    near_ready = _field_rewrite_near_ready_comment(item, blocker)
                    if near_ready:
                        comments.append(near_ready)
                    partial_opportunity = _field_rewrite_partial_opportunity_comment(text or "", item, blocker)
                    if partial_opportunity:
                        comments.append(partial_opportunity)
                else:
                    ready = _field_rewrite_ready_comment(text or "", item)
                    if ready:
                        comments.append(ready)
                        rewrite_preview = _field_rewrite_preview_comment(text or "", item, ready)
                        if rewrite_preview:
                            comments.append(rewrite_preview)
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


def _field_bitfield_alias_comment_from_layout(text: str, layout: _LayoutEvidence) -> dict[str, Any] | None:
    fields = []
    for item in _subfield_overlay_fields(layout, text):
        if item.get("interpretation") != "bitfield_candidate":
            continue
        field_item = dict(item)
        field_item["aliases"] = _bitfield_aliases_for_field(item)
        fields.append(field_item)
    if not fields:
        return None
    base_kind = _layout_base_kind(layout.base)
    alias_text = "; ".join(
        _bitfield_alias_field_text(item)
        for item in fields[:6]
    )
    if len(fields) > 6:
        alias_text += "; ..."
    confidence = min(
        _field_bitfield_alias_confidence_cap_for_base_kind(base_kind),
        0.6 + len(fields) * 0.04 + min(layout.access_count, 12) * 0.005,
    )
    return {
        "kind": "inferred_offset_bitfield_aliases",
        "text": _field_bitfield_alias_text(layout.base, base_kind, alias_text),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "fields": fields,
    }


def _field_stable_base_source_comment_from_layout(text: str, layout: _LayoutEvidence) -> dict[str, Any] | None:
    base_kind = _layout_base_kind(layout.base)
    if base_kind == "named":
        return None
    identity = _stable_base_source_identity(text, layout.base)
    if not identity:
        return None
    source = identity["source"]
    source_kind = str(identity.get("source_kind", "") or _layout_source_kind(source))
    if (
        source_kind not in {"argument", "named"}
        and identity.get("source_provenance") not in _TRUSTED_STABLE_BASE_SOURCE_PROVENANCES
    ):
        return None
    confidence = min(
        _field_stable_base_source_confidence_cap_for_base_kind(base_kind, source_kind),
        0.58 + len(layout.offsets) * 0.02 + min(layout.access_count, 12) * 0.005,
    )
    comment = {
        "kind": "inferred_offset_stable_base_source",
        "text": _field_stable_base_source_text(
            layout.base,
            source,
            source_kind,
            identity["source_provenance"],
            layout.access_count,
            len(layout.offsets),
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "source": source,
        "source_kind": source_kind,
        "source_provenance": identity["source_provenance"],
        "source_rhs_kind": identity["source_rhs_kind"],
        "offset_count": len(layout.offsets),
        "access_count": layout.access_count,
    }
    if identity.get("source_offset"):
        comment["source_offset"] = identity["source_offset"]
    if identity.get("source_type"):
        comment["source_type"] = identity["source_type"]
    if identity.get("source_index"):
        comment["source_index"] = identity["source_index"]
    return comment


def _field_generic_base_evidence_comment_from_layout(text: str, layout: _LayoutEvidence) -> dict[str, Any] | None:
    base_kind = _layout_base_kind(layout.base)
    if base_kind != "generic":
        return None
    if _trusted_generic_parameter_layout_identity(text, layout):
        return None
    blockers = _field_rewrite_blockers(text, layout, allow_generic_parameter_trust=False)
    if "base name is generic" not in blockers:
        return None
    blocker_profile = _generic_base_blocker_profile(blockers)
    confidence = min(
        _field_generic_base_evidence_confidence_cap_for_profile(blocker_profile),
        0.58 + len(layout.offsets) * 0.02 + min(layout.access_count, 16) * 0.005,
    )
    return {
        "kind": "inferred_offset_generic_base_evidence",
        "text": _field_generic_base_evidence_text(
            layout.base,
            layout.access_count,
            len(layout.offsets),
            blocker_profile,
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "blocker_profile": blocker_profile,
        "offset_count": len(layout.offsets),
        "access_count": layout.access_count,
    }


def _field_generic_base_trust_candidate_comment_from_layout(text: str, layout: _LayoutEvidence) -> dict[str, Any] | None:
    base_kind = _layout_base_kind(layout.base)
    if base_kind != "generic":
        return None
    if len(layout.offsets) < 10 or layout.access_count < 16:
        return None
    blockers = _field_rewrite_blockers(text, layout, allow_generic_parameter_trust=False)
    if _generic_base_blocker_profile(blockers) != "generic_only":
        return None
    if not _base_is_function_parameter(text, layout.base):
        return None
    confidence = min(
        0.76,
        0.6 + len(layout.offsets) * 0.018 + min(layout.access_count, 20) * 0.005,
    )
    return {
        "kind": "inferred_offset_generic_base_trust_candidate",
        "text": _field_generic_base_trust_candidate_text(
            layout.base,
            layout.access_count,
            len(layout.offsets),
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "source_kind": "parameter",
        "blocker_profile": "generic_only",
        "offset_count": len(layout.offsets),
        "access_count": layout.access_count,
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


def _field_base_stability_comment_from_layout(
    text: str,
    layout: _LayoutEvidence,
    blocker: dict[str, Any],
) -> dict[str, Any] | None:
    blockers = [str(item) for item in blocker.get("blockers", []) or [] if str(item)]
    if not any(_is_base_stability_blocker_reason(item) for item in blockers):
        return None
    trace = _base_assignment_trace(text, layout.base)
    if not trace:
        return None
    rhs_samples = [
        str(item)
        for item in trace.get("distinct_pre_access_rhs", []) or []
        if str(item)
    ][:_MAX_BASE_STABILITY_RHS_SAMPLES]
    rhs_text = "none"
    if rhs_samples:
        rhs_text = "; ".join(rhs_samples)
        if int(trace.get("distinct_pre_access_rhs_count", 0) or 0) > len(rhs_samples):
            rhs_text += "; ..."
    confidence = min(
        0.76,
        0.62
        + min(int(trace.get("pre_access_assignment_count", 0) or 0), 4) * 0.025
        + min(int(trace.get("risky_post_access_assignment_count", 0) or 0), 3) * 0.025,
    )
    return {
        "kind": "inferred_offset_base_stability",
        "text": (
            "Base stability evidence for %s: %d initializer(s) before first layout access across "
            "%d distinct RHS (%s); %d post-access assignment(s), %d followed by later layout access. "
            "Review initializer dominance before enabling canonical rewrite."
            % (
                layout.base,
                int(trace.get("pre_access_assignment_count", 0) or 0),
                int(trace.get("distinct_pre_access_rhs_count", 0) or 0),
                rhs_text,
                int(trace.get("post_access_assignment_count", 0) or 0),
                int(trace.get("risky_post_access_assignment_count", 0) or 0),
            )
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "pre_access_assignment_count": int(trace.get("pre_access_assignment_count", 0) or 0),
        "distinct_pre_access_rhs_count": int(trace.get("distinct_pre_access_rhs_count", 0) or 0),
        "distinct_pre_access_rhs": rhs_samples,
        "post_access_assignment_count": int(trace.get("post_access_assignment_count", 0) or 0),
        "risky_post_access_assignment_count": int(trace.get("risky_post_access_assignment_count", 0) or 0),
    }


def _field_rewrite_ready_comment(text: str, layout: _LayoutEvidence) -> dict[str, Any] | None:
    base_kind = _layout_base_kind(layout.base)
    identity = _trusted_stable_base_source_identity(text, layout.base)
    if not identity:
        identity = _trusted_generic_parameter_layout_identity(text, layout)
    if base_kind != "named" and not identity:
        return None
    threshold_policy = _field_rewrite_threshold_policy(layout)
    if not threshold_policy:
        return None
    confidence = min(
        0.8,
        0.66 + len(layout.offsets) * 0.02 + min(layout.access_count, 16) * 0.005,
    )
    source_text = ""
    if identity:
        source_text = " Source provenance %s from %s." % (
            identity["source_provenance"],
            identity["source"],
        )
    threshold_text = ""
    if threshold_policy != "standard":
        threshold_text = " Threshold policy %s." % threshold_policy
    comment = {
        "kind": "inferred_offset_rewrite_ready",
        "text": (
            "Offset field rewrite candidate for %s: %d typed dereference(s) across %d offset(s), no rewrite blockers found.%s%s Audit only; body rewrite was not applied."
            % (layout.base, layout.access_count, len(layout.offsets), source_text, threshold_text)
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "offset_count": len(layout.offsets),
        "access_count": layout.access_count,
        "threshold_policy": threshold_policy,
    }
    if identity:
        comment.update(
            {
                "source": identity["source"],
                "source_kind": identity["source_kind"],
                "source_provenance": identity["source_provenance"],
                "source_rhs_kind": identity["source_rhs_kind"],
            }
        )
    return comment


def _field_rewrite_preview_comment(
    text: str,
    layout: _LayoutEvidence,
    ready: dict[str, Any],
) -> dict[str, Any] | None:
    fields = _preview_fields(layout)
    if not fields:
        return None
    rewrite_count = _layout_rewrite_access_count(text, layout)
    if rewrite_count <= 0:
        return None
    field_names = [str(item["name"]) for item in fields if str(item.get("name", ""))]
    if not field_names:
        return None
    field_text = ", ".join(field_names[:8])
    if len(field_names) > 8:
        field_text += ", ..."
    source_provenance = str(ready.get("source_provenance", "") or "none")
    source = str(ready.get("source", "") or "")
    source_text = ""
    if source_provenance != "none" and source:
        source_text = " Source provenance %s from %s." % (source_provenance, source)
    confidence = min(
        0.78,
        0.64 + len(fields) * 0.015 + min(rewrite_count, 24) * 0.004,
    )
    comment = {
        "kind": "inferred_offset_rewrite_preview",
        "text": (
            "Offset field rewrite preview for %s: %d dereference(s) can map to %d field alias(es) %s.%s Preview artifact only; body rewrite was not applied."
            % (layout.base, rewrite_count, len(fields), field_text, source_text)
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "field_count": len(fields),
        "access_count": rewrite_count,
        "source_provenance": source_provenance,
    }
    if source:
        comment["source"] = source
    return comment


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


def _field_rewrite_partial_opportunity_comment(
    text: str,
    layout: _LayoutEvidence,
    blocker: dict[str, Any],
) -> dict[str, Any] | None:
    blockers = [
        str(item)
        for item in blocker.get("blockers", []) or []
        if str(item)
    ]
    identity_blockers = {
        "base is a decompiler temporary",
        "base name is generic",
    }
    non_identity_blockers = [
        item
        for item in blockers
        if item not in identity_blockers
    ]
    if not non_identity_blockers or not any(item in _OFFSET_LOCAL_TYPE_BLOCKERS for item in non_identity_blockers):
        return None
    if any(item not in _OFFSET_LOCAL_TYPE_BLOCKERS for item in non_identity_blockers):
        return None
    identity = _trusted_partial_layout_rewrite_identity(text, layout)
    if _layout_base_kind(layout.base) != "named" and not identity:
        return None
    partition = _partial_rewrite_offset_partition(layout)
    safe_offsets = {
        int(item["offset"])
        for item in partition["safe_fields"]
    }
    excluded_offsets = {
        int(item["offset"])
        for item in partition["excluded_fields"]
    }
    if not safe_offsets or not excluded_offsets:
        return None
    safe_access_count = _layout_rewrite_access_count_for_offsets(text, layout, safe_offsets)
    excluded_access_count = _layout_rewrite_access_count_for_offsets(text, layout, excluded_offsets)
    if len(safe_offsets) < 8 or safe_access_count < 12:
        return None
    field_names = [
        str(item["name"])
        for item in partition["safe_fields"]
        if str(item.get("name", ""))
    ]
    if not field_names:
        return None
    field_text = ", ".join(field_names[:8])
    if len(field_names) > 8:
        field_text += ", ..."
    safe_offset_text = _offset_list_text(safe_offsets)
    excluded_offset_text = _offset_list_text(excluded_offsets)
    reason_text = "; ".join(partition["excluded_reasons"][:6])
    source_provenance = str(identity.get("source_provenance", "") or "none")
    source = str(identity.get("source", "") or "")
    source_text = ""
    if source_provenance != "none" and source:
        source_text = " Source provenance %s from %s." % (source_provenance, source)
    confidence = min(
        0.77,
        0.63 + len(safe_offsets) * 0.012 + min(safe_access_count, 24) * 0.003,
    )
    comment = {
        "kind": "inferred_offset_rewrite_partial_opportunity",
        "text": (
            "Offset field partial rewrite opportunity for %s: %d safe dereference(s) across %d safe offset(s), "
            "%d excluded dereference(s) across %d excluded offset(s), safe fields %s. "
            "Safe offsets %s; excluded offsets %s. Excluded reasons %s.%s "
            "Review-only; canonical body rewrite remains disabled until partial rewrite validation is implemented."
            % (
                layout.base,
                safe_access_count,
                len(safe_offsets),
                excluded_access_count,
                len(excluded_offsets),
                field_text,
                safe_offset_text,
                excluded_offset_text,
                reason_text,
                source_text,
            )
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "safe_fields": partition["safe_fields"],
        "excluded_fields": partition["excluded_fields"],
        "excluded_reasons": partition["excluded_reasons"],
        "safe_offset_count": len(safe_offsets),
        "safe_access_count": safe_access_count,
        "excluded_offset_count": len(excluded_offsets),
        "excluded_access_count": excluded_access_count,
        "safe_offsets": sorted(safe_offsets),
        "excluded_offsets": sorted(excluded_offsets),
        "source_provenance": source_provenance,
    }
    if source:
        comment["source"] = source
    return comment


def _offset_list_text(offsets: set[int]) -> str:
    return ", ".join("+0x%X" % offset for offset in sorted(offsets))


def _field_rewrite_blockers(
    text: str,
    layout: _LayoutEvidence,
    allow_generic_parameter_trust: bool = True,
) -> list[str]:
    blockers: list[str] = []
    base_kind = _layout_base_kind(layout.base)
    if base_kind == "temp":
        if not _trusted_stable_base_source_identity(text, layout.base):
            blockers.append("base is a decompiler temporary")
    elif base_kind == "generic":
        identity = _trusted_generic_parameter_layout_identity(text, layout)
        if not allow_generic_parameter_trust or not identity:
            blockers.append("base name is generic")
    blockers.extend(_non_identity_layout_rewrite_blockers(text, layout))
    return list(dict.fromkeys(blockers))


def _non_identity_layout_rewrite_blockers(text: str, layout: _LayoutEvidence) -> list[str]:
    blockers: list[str] = []
    blockers.extend(_field_rewrite_threshold_blockers(layout))
    blockers.extend(_mixed_offset_type_blockers(layout))
    if _has_volatile_access_type(layout):
        blockers.append(_VOLATILE_ACCESS_TYPE_BLOCKER)
    if _has_unaligned_field_access(layout):
        blockers.append(_UNALIGNED_TYPED_OFFSET_BLOCKER)
    if _is_mmio_like_base(layout.base):
        blockers.append("base name looks MMIO/register-backed")
    blockers.extend(_base_change_blockers(text, layout.base))
    if _base_address_taken(text, layout.base):
        blockers.append("base address is taken")
    if _base_has_array_index_use(text, layout.base):
        blockers.append("base is also indexed like an array")
    return list(dict.fromkeys(blockers))


def _trusted_generic_parameter_layout_identity(text: str, layout: _LayoutEvidence) -> dict[str, str] | None:
    return _trusted_generic_parameter_identity(
        text,
        layout,
        allow_offset_local_type_blockers=False,
    )


def _trusted_generic_parameter_identity(
    text: str,
    layout: _LayoutEvidence,
    allow_offset_local_type_blockers: bool = False,
) -> dict[str, str] | None:
    if _layout_base_kind(layout.base) != "generic":
        return None
    if len(layout.offsets) < 10 or layout.access_count < 16:
        return None
    if not _base_is_function_parameter(text, layout.base):
        return None
    blockers = _non_identity_layout_rewrite_blockers(text, layout)
    if blockers:
        if not allow_offset_local_type_blockers:
            return None
        if any(item not in _OFFSET_LOCAL_TYPE_BLOCKERS for item in blockers):
            return None
    return {
        "source": layout.base,
        "source_kind": "generic",
        "source_provenance": "generic_parameter_trust",
        "source_rhs_kind": "parameter",
    }


def _trusted_layout_rewrite_identity(text: str, layout: _LayoutEvidence) -> dict[str, str]:
    identity = _trusted_stable_base_source_identity(text, layout.base)
    if identity:
        return identity
    identity = _trusted_generic_parameter_layout_identity(text, layout)
    if identity:
        return identity
    return {}


def _trusted_partial_layout_rewrite_identity(text: str, layout: _LayoutEvidence) -> dict[str, str]:
    identity = _trusted_stable_base_source_identity(text, layout.base)
    if identity:
        return identity
    identity = _trusted_generic_parameter_identity(
        text,
        layout,
        allow_offset_local_type_blockers=True,
    )
    if identity:
        return identity
    return {}


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


def _layout_rewrite_access_count(text: str, layout: _LayoutEvidence) -> int:
    count = 0
    offsets = set(layout.offsets)
    for match in _OFFSET_DEREF_RE.finditer(text or ""):
        if match.group("base") != layout.base:
            continue
        offset = _parse_offset(match.group("offset"))
        if offset in offsets:
            count += 1
    return count


def _layout_rewrite_access_count_for_offsets(text: str, layout: _LayoutEvidence, offsets: set[int]) -> int:
    count = 0
    for match in _OFFSET_DEREF_RE.finditer(text or ""):
        if match.group("base") != layout.base:
            continue
        offset = _parse_offset(match.group("offset"))
        if offset in offsets:
            count += 1
    return count


def _partial_rewrite_offset_partition(layout: _LayoutEvidence) -> dict[str, Any]:
    safe_fields = []
    excluded_fields = []
    excluded_reasons: list[str] = []
    for offset in sorted(layout.offsets):
        reasons = _offset_local_type_blockers(layout, offset)
        field = {
            "offset": offset,
            "name": "field_%X" % offset,
            "type": _preview_type_name(layout.offsets[offset]),
        }
        if reasons:
            field["reasons"] = reasons
            excluded_fields.append(field)
            for reason in reasons:
                if reason not in excluded_reasons:
                    excluded_reasons.append(reason)
        else:
            safe_fields.append(field)
    return {
        "safe_fields": safe_fields,
        "excluded_fields": excluded_fields,
        "excluded_reasons": excluded_reasons,
    }


def _offset_local_type_blockers(layout: _LayoutEvidence, offset: int) -> list[str]:
    type_names = layout.offsets.get(offset, set())
    blockers: list[str] = []
    storage_classes = {_field_type_storage_class(type_name) for type_name in type_names}
    if len(storage_classes) > 1:
        if all(item.startswith("size:") for item in storage_classes):
            sizes = [
                _field_type_storage_size(type_name)
                for type_name in type_names
            ]
            blockers.append(_subfield_overlay_policy_blocker(_subfield_overlay_size_class(sizes)))
        else:
            blockers.append(_INCOMPATIBLE_ACCESS_TYPE_BLOCKER)
    if any("volatile" in type_name.lower() for type_name in type_names):
        blockers.append(_VOLATILE_ACCESS_TYPE_BLOCKER)
    for type_name in type_names:
        alignment = _natural_type_alignment(type_name)
        if alignment and offset % alignment != 0:
            blockers.append(_UNALIGNED_TYPED_OFFSET_BLOCKER)
            break
    return list(dict.fromkeys(blockers))


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
        bitfield_evidence = _subfield_overlay_bitfield_evidence(text, layout.base, offset)
        interpretation = _subfield_overlay_interpretation(size_class, bitfield_evidence)
        fields.append(
            {
                "offset": offset,
                "name": "field_%X" % offset,
                "sizes": sizes,
                "size_class": size_class,
                "policy_class": _subfield_overlay_policy_class(size_class),
                "interpretation": interpretation,
                "bit_masks": bitfield_evidence["masks"],
                "bit_operations": bitfield_evidence["operations"],
                "mask_families": bitfield_evidence["families"],
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
        annotation_parts = [interpretation]
        bit_masks = [str(value) for value in item.get("bit_masks", []) or [] if str(value)]
        bit_operations = [str(value) for value in item.get("bit_operations", []) or [] if str(value)]
        mask_families = [str(value) for value in item.get("mask_families", []) or [] if str(value)]
        if bit_masks:
            annotation_parts.append("masks=%s" % ",".join(bit_masks[:4]))
        if bit_operations:
            annotation_parts.append("ops=%s" % ",".join(bit_operations[:4]))
        if mask_families:
            annotation_parts.append("families=%s" % ",".join(mask_families[:4]))
        text += " [%s]" % " ".join(annotation_parts)
    return text


def _bitfield_aliases_for_field(item: dict[str, Any]) -> list[str]:
    aliases = []
    for family in item.get("mask_families", []) or []:
        alias = "bitfield_%s" % str(family)
        if alias not in aliases:
            aliases.append(alias)
    if not aliases:
        aliases.append("bitfield_mask")
    return aliases


def _bitfield_alias_field_text(item: dict[str, Any]) -> str:
    masks = [str(value) for value in item.get("bit_masks", []) or [] if str(value)]
    mask_text = ",".join(masks[:4]) if masks else "unknown"
    return "%s=+0x%X %s masks=%s" % (
        item["name"],
        item["offset"],
        "/".join(item.get("aliases", []) or ["bitfield_mask"]),
        mask_text,
    )


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


def _subfield_overlay_interpretation(size_class: str, bitfield_evidence: dict[str, list[str]]) -> str:
    if bitfield_evidence["operations"]:
        return "bitfield_candidate"
    policy_class = _subfield_overlay_policy_class(size_class)
    if policy_class == "narrow_subfield":
        return "packed_field_candidate"
    if policy_class == "wide_overlay":
        return "union_overlay_candidate"
    return "ambiguous_overlay"


def _subfield_overlay_bitfield_evidence(text: str, base: str, offset: int) -> dict[str, list[str]]:
    masks: set[str] = set()
    operations: set[str] = set()
    if not text:
        return {"masks": [], "operations": [], "families": []}
    for match in _OFFSET_DEREF_RE.finditer(text):
        if match.group("base") != base:
            continue
        parsed_offset = _parse_offset(match.group("offset"))
        if parsed_offset != offset:
            continue
        line = _line_at(text, match.start(), match.end())
        if not _line_has_bitwise_field_operation(line):
            continue
        masks.update(_bitwise_masks_from_line(line))
        operations.update(_bitwise_operations_from_line(line))
    return {
        "masks": sorted(masks, key=_bit_mask_sort_key),
        "operations": [item for item in _BIT_OPERATION_ORDER if item in operations],
        "families": _bit_mask_families(masks, operations),
    }


def _line_at(text: str, start: int, end: int) -> str:
    line_start = text.rfind("\n", 0, max(0, start)) + 1
    line_end = text.find("\n", max(0, end))
    if line_end < 0:
        line_end = len(text)
    return text[line_start:line_end]


def _line_has_bitwise_field_operation(line: str) -> bool:
    return re.search(r"(&=|\|=|\^=|<<|>>|\s[&|^]\s|_bittest|_interlockedbittest)", line or "") is not None


_BIT_OPERATION_ORDER = [
    "test_mask",
    "clear_mask",
    "set_mask",
    "toggle_mask",
    "shift",
    "test_bit",
    "set_bit",
    "clear_bit",
]


def _bitwise_operations_from_line(line: str) -> set[str]:
    operations: set[str] = set()
    value = line or ""
    if re.search(r"\s&\s*(?:0x[0-9A-Fa-f]+|\d+)", value):
        operations.add("test_mask")
    if "&=" in value:
        operations.add("clear_mask")
    if "|=" in value:
        operations.add("set_mask")
    if "^=" in value:
        operations.add("toggle_mask")
    if "<<" in value or ">>" in value:
        operations.add("shift")
    lowered = value.lower()
    if "_bittestandset" in lowered or "_interlockedbittestandset" in lowered:
        operations.add("set_bit")
    elif "_bittestandreset" in lowered or "_interlockedbittestandreset" in lowered:
        operations.add("clear_bit")
    elif "_bittest" in lowered or "_interlockedbittest" in lowered:
        operations.add("test_bit")
    return operations


def _bitwise_masks_from_line(line: str) -> set[str]:
    masks: set[str] = set()
    for match in re.finditer(r"(?:&=|\|=|\^=|\s[&|^]\s*)\s*(?P<mask>0x[0-9A-Fa-f]+|\d+)(?:u|U|l|L)*", line or ""):
        masks.add(_normalize_bit_mask(match.group("mask")))
    return masks


def _bit_mask_families(masks: set[str], operations: set[str]) -> list[str]:
    families = []
    for mask in sorted(masks, key=_bit_mask_sort_key):
        family = _bit_mask_family(mask, operations)
        if family and family not in families:
            families.append(family)
    return families


def _bit_mask_family(mask: str, operations: set[str]) -> str:
    value = _parse_bit_mask(mask)
    if value is None:
        return "unknown_mask"
    if value != 0 and value & (value - 1) == 0:
        return "single_bit"
    if _is_low_bits_mask(value):
        return "low_nibble" if value == 0xF else "low_bits"
    if "clear_mask" in operations and _is_clear_low_nibble_mask(value):
        return "clear_low_nibble"
    if _has_preserved_outer_nibbles(value):
        return "preserve_outer_nibbles"
    return "sparse_mask"


def _parse_bit_mask(mask: str) -> int | None:
    try:
        return int(str(mask), 16) if str(mask).lower().startswith("0x") else int(str(mask), 10)
    except ValueError:
        return None


def _is_low_bits_mask(value: int) -> bool:
    return value > 0 and (value & (value + 1)) == 0


def _is_clear_low_nibble_mask(value: int) -> bool:
    return value > 0 and value & 0xF == 0 and _is_low_bits_mask(value | 0xF)


def _has_preserved_outer_nibbles(value: int) -> bool:
    if value <= 0 or value & 0xF != 0xF:
        return False
    nibbles = []
    item = value
    while item:
        nibbles.append(item & 0xF)
        item >>= 4
    if len(nibbles) < 3 or nibbles[-1] == 0:
        return False
    return any(nibble == 0 for nibble in nibbles[1:-1])


def _normalize_bit_mask(value: str) -> str:
    text = str(value or "").strip()
    try:
        number = int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return text
    return "0x%X" % number


def _bit_mask_sort_key(value: str) -> tuple[int, str]:
    try:
        return int(str(value), 16), str(value)
    except ValueError:
        return 0, str(value)


def _preview_type_name(type_names: set[str]) -> str:
    cleaned = [item for item in sorted(type_names) if item]
    if not cleaned:
        return "unknown"
    if len(cleaned) == 1:
        return cleaned[0]
    return "mixed(%s)" % "/".join(cleaned[:3])


def _field_rewrite_threshold_blockers(layout: _LayoutEvidence) -> list[str]:
    blockers: list[str] = []
    if _field_rewrite_threshold_policy(layout):
        return blockers
    if len(layout.offsets) < 8:
        blockers.append(_REWRITE_OFFSET_THRESHOLD_BLOCKER)
    if layout.access_count < 12:
        blockers.append(_REWRITE_ACCESS_THRESHOLD_BLOCKER)
    return blockers


def _field_rewrite_threshold_policy(layout: _LayoutEvidence) -> str:
    if len(layout.offsets) >= 8 and layout.access_count >= 12:
        return "standard"
    if _field_rewrite_named_threshold_grace(layout):
        return "named_threshold_grace"
    return ""


def _field_rewrite_named_threshold_grace(layout: _LayoutEvidence) -> bool:
    if _layout_base_kind(layout.base) != "named":
        return False
    if len(layout.offsets) >= 8 and layout.access_count >= 10:
        return True
    if len(layout.offsets) >= 6 and layout.access_count >= 12:
        return True
    return False


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


def _field_bitfield_alias_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.66
    if base_kind == "generic":
        return 0.7
    return 0.74


def _field_stable_base_source_confidence_cap_for_base_kind(base_kind: str, source_kind: str) -> float:
    if base_kind == "temp":
        return 0.72 if source_kind == "named" else 0.68
    if base_kind == "generic":
        return 0.68 if source_kind == "named" else 0.64
    return 0.74


def _field_generic_base_evidence_confidence_cap_for_profile(blocker_profile: str) -> float:
    if blocker_profile == "generic_only":
        return 0.74
    return 0.7


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


def _field_bitfield_alias_text(base: str, base_kind: str, alias_text: str) -> str:
    if base_kind == "temp":
        return (
            "Review bitfield aliases for %s (temporary base): %s. Review-only names; body rewrite remains disabled until the parent structure is trusted."
            % (base, alias_text)
        )
    if base_kind == "generic":
        return (
            "Review bitfield aliases for %s (generic base): %s. Review-only names; body rewrite remains disabled until the parent structure is trusted."
            % (base, alias_text)
        )
    return (
        "Bitfield aliases for %s: %s. Review-only names; body rewrite remains disabled until the parent structure is trusted."
        % (base, alias_text)
    )


def _field_stable_base_source_text(
    base: str,
    source: str,
    source_kind: str,
    source_provenance: str,
    access_count: int,
    offset_count: int,
) -> str:
    return (
        "Stable base source for %s: %s (%s source, %s), %d typed dereference(s) across %d offset(s). "
        "Review-only source identity evidence for temp/generic base promotion."
        % (base, source, source_kind, source_provenance, access_count, offset_count)
    )


def _field_generic_base_evidence_text(
    base: str,
    access_count: int,
    offset_count: int,
    blocker_profile: str,
) -> str:
    return (
        "Generic base evidence for %s: %d typed dereference(s) across %d offset(s), blocker profile %s. "
        "Review-only; rewrite remains blocked until the base identity is trusted."
        % (base, access_count, offset_count, blocker_profile)
    )


def _field_generic_base_trust_candidate_text(
    base: str,
    access_count: int,
    offset_count: int,
) -> str:
    return (
        "Generic base trust candidate for %s: parameter source, generic-only blockers, "
        "%d typed dereference(s) across %d offset(s). Promotion eligible only when no other "
        "rewrite blocker is present; canonical rewrite still requires explicit validation-gated export."
        % (base, access_count, offset_count)
    )


def _generic_base_blocker_profile(blockers: list[str]) -> str:
    blocker_set = {str(item) for item in blockers if str(item)}
    if blocker_set == {"base name is generic"}:
        return "generic_only"
    return "generic_with_other_blockers"


def _base_is_function_parameter(text: str, base: str) -> bool:
    return str(base or "") in _function_parameter_names(text)


def _function_parameter_names(text: str) -> set[str]:
    signature = str(text or "")
    brace_index = signature.find("{")
    if brace_index >= 0:
        signature = signature[:brace_index]
    open_index = signature.rfind("(")
    close_index = signature.rfind(")")
    if open_index < 0 or close_index <= open_index:
        return set()
    parameter_text = signature[open_index + 1 : close_index]
    names = set()
    for parameter in _split_top_level_parameters(parameter_text):
        identifiers = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", parameter)
        if not identifiers:
            continue
        name = identifiers[-1]
        if _looks_like_parameter_type_token(name):
            continue
        names.add(name)
    return names


def _split_top_level_parameters(text: str) -> list[str]:
    parts = []
    start = 0
    depth = 0
    for index, char in enumerate(text or ""):
        if char in "([{<":
            depth += 1
            continue
        if char in ")]}>":
            depth = max(0, depth - 1)
            continue
        if char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    tail = str(text or "")[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _looks_like_parameter_type_token(name: str) -> bool:
    return str(name or "") in {
        "PVOID",
        "VOID",
        "bool",
        "char",
        "double",
        "float",
        "int",
        "long",
        "short",
        "size_t",
        "unsigned",
        "void",
    }


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
        blockers.append(_INCOMPATIBLE_ACCESS_TYPE_BLOCKER)
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
    size = _LAYOUT_TYPE_STORAGE_SIZES.get(lowered)
    if size:
        return "size:%d" % size
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
    normalized = " ".join(str(type_name or "").replace("volatile ", "").replace("const ", "").split())
    lowered = normalized.lower()
    size = _LAYOUT_TYPE_STORAGE_SIZES.get(lowered)
    if size:
        return size
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
        if _next_layout_access_start(text, base, assignment.end()) < 0:
            continue
        blockers.append("base is reassigned after layout access")
        break
    return blockers


def _is_base_stability_blocker_reason(reason: str) -> bool:
    lowered = str(reason or "").lower()
    return any(fragment in lowered for fragment in _BASE_STABILITY_BLOCKER_FRAGMENTS)


def _base_assignment_trace(text: str, base: str) -> dict[str, Any]:
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        return {}
    assignments = _base_direct_assignments(text, base)
    pre_access = [item for item in assignments if item.start() < first_access]
    post_access = [item for item in assignments if item.start() >= first_access]
    simple_pre_rhs = [
        _normalize_assignment_rhs(item.group("rhs"))
        for item in pre_access
        if item.group("op") == "="
    ]
    distinct_pre_rhs = list(dict.fromkeys(item for item in simple_pre_rhs if item))
    stable_reload_sources = set()
    if simple_pre_rhs:
        stable_reload_sources.add(simple_pre_rhs[-1])
    stable_reload_sources.update(_stable_aliases_for_base_before_access(text, base, first_access))
    risky_post_access_count = 0
    for assignment in post_access:
        if assignment.group("op") != "=":
            risky_post_access_count += 1
            continue
        rhs = _normalize_assignment_rhs(assignment.group("rhs"))
        if rhs in stable_reload_sources:
            continue
        if _next_layout_access_start(text, base, assignment.end()) >= 0:
            risky_post_access_count += 1
    return {
        "pre_access_assignment_count": len(pre_access),
        "distinct_pre_access_rhs_count": len(distinct_pre_rhs),
        "distinct_pre_access_rhs": distinct_pre_rhs,
        "post_access_assignment_count": len(post_access),
        "risky_post_access_assignment_count": risky_post_access_count,
    }


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


def _stable_base_source_before_layout_access(text: str, base: str) -> str:
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        return ""
    assignments = _base_direct_assignments(text, base)
    pre_access_assignments = [
        item
        for item in assignments
        if item.start() < first_access
    ]
    if not pre_access_assignments:
        return ""
    if any(item.group("op") != "=" for item in pre_access_assignments):
        return ""
    pre_access_rhs = [
        _normalize_assignment_rhs(item.group("rhs"))
        for item in pre_access_assignments
    ]
    distinct_pre_access_rhs = {item for item in pre_access_rhs if item}
    if len(distinct_pre_access_rhs) != 1:
        return ""
    return pre_access_rhs[-1] if pre_access_rhs else ""


def _stable_base_source_identity(text: str, base: str) -> dict[str, Any]:
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        return {}
    source = _stable_base_source_before_layout_access(text, base)
    if not source:
        return {}
    base_assignments = [
        item
        for item in _base_direct_assignments(text, base)
        if item.start() < first_access
        and item.group("op") == "="
        and _normalize_assignment_rhs(item.group("rhs")) == source
    ]
    field_pointer_identity = _field_pointer_source_identity(
        text,
        base,
        source,
        len(base_assignments),
    )
    if field_pointer_identity:
        return field_pointer_identity
    parameter_derived_identity = _parameter_derived_source_identity(
        text,
        base,
        source,
        len(base_assignments),
    )
    if parameter_derived_identity:
        return parameter_derived_identity
    direct_call_result_identity = _direct_call_result_source_identity(
        base,
        source,
        len(base_assignments),
    )
    if direct_call_result_identity:
        return direct_call_result_identity
    source_kind = _layout_source_kind(source)
    source_assignments = [
        item
        for item in _base_direct_assignments(text, source)
        if item.start() < first_access and item.group("op") == "="
    ]
    source_rhs_kinds = {
        _layout_rhs_kind(_normalize_assignment_rhs(item.group("rhs")))
        for item in source_assignments
    }
    source_rhs_kind = next(iter(source_rhs_kinds), "none")
    if len(source_rhs_kinds) > 1:
        source_rhs_kind = "mixed"
    source_provenance = _stable_source_provenance_class(
        source_kind,
        len(base_assignments),
        len(source_assignments),
        source_rhs_kind,
    )
    return {
        "source": source,
        "source_kind": source_kind,
        "source_provenance": source_provenance,
        "source_rhs_kind": source_rhs_kind,
        "base_alias_assignments": len(base_assignments),
        "source_assignments": len(source_assignments),
    }


def _field_pointer_source_identity(
    text: str,
    base: str,
    source: str,
    base_alias_assignment_count: int,
) -> dict[str, Any]:
    if base_alias_assignment_count <= 0:
        return {}
    if _layout_base_kind(base) != "temp":
        return {}
    match = _parse_field_pointer_source(source)
    if not match:
        return {}
    parent = str(match["parent"])
    if not _base_is_function_parameter(text, parent):
        return {}
    type_name = str(match["type"])
    if _field_type_storage_size(type_name) != 8:
        return {}
    source_kind = _layout_source_kind(parent)
    if source_kind == "temporary":
        source_kind = "argument"
    return {
        "source": parent,
        "source_kind": source_kind,
        "source_provenance": "parameter_field_pointer_alias",
        "source_rhs_kind": "field_pointer",
        "source_offset": "0x%X" % int(match["offset"]),
        "source_type": type_name,
        "base_alias_assignments": base_alias_assignment_count,
        "source_assignments": 0,
    }


def _parse_field_pointer_source(source: str) -> dict[str, Any]:
    match = re.fullmatch(
        r"\*\s*\(\s*(?P<type>[^()]+?)\s*\*\s*\)\s*"
        r"\(\s*(?P<parent>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
        r"(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)",
        str(source or ""),
    )
    if not match:
        return {}
    try:
        offset = int(
            match.group("offset"),
            16 if match.group("offset").lower().startswith("0x") else 10,
        )
    except ValueError:
        return {}
    if offset <= 0:
        return {}
    return {
        "parent": match.group("parent"),
        "offset": offset,
        "type": _normalize_type_name(match.group("type")),
    }


def _parameter_derived_source_identity(
    text: str,
    base: str,
    source: str,
    base_alias_assignment_count: int,
) -> dict[str, Any]:
    if base_alias_assignment_count <= 0:
        return {}
    if _layout_base_kind(base) != "temp":
        return {}
    indexed = _parse_parameter_indexed_source(source)
    if indexed and _base_is_function_parameter(text, str(indexed["parent"])):
        return _parameter_source_identity(
            indexed,
            "parameter_indexed_pointer_alias",
            "parameter_indexed_pointer",
            base_alias_assignment_count,
        )
    subobject = _parse_parameter_subobject_source(source)
    if subobject and _base_is_function_parameter(text, str(subobject["parent"])):
        return _parameter_source_identity(
            subobject,
            "parameter_subobject_pointer_alias",
            "parameter_pointer_arithmetic",
            base_alias_assignment_count,
        )
    return {}


def _parameter_source_identity(
    match: dict[str, Any],
    provenance: str,
    rhs_kind: str,
    base_alias_assignment_count: int,
) -> dict[str, Any]:
    parent = str(match["parent"])
    source_kind = _layout_source_kind(parent)
    if source_kind == "temporary":
        source_kind = "argument"
    identity: dict[str, Any] = {
        "source": parent,
        "source_kind": source_kind,
        "source_provenance": provenance,
        "source_rhs_kind": rhs_kind,
        "base_alias_assignments": base_alias_assignment_count,
        "source_assignments": 0,
    }
    if "offset" in match:
        identity["source_offset"] = "0x%X" % int(match["offset"])
    if "index" in match:
        identity["source_index"] = int(match["index"])
    return identity


def _parse_parameter_subobject_source(source: str) -> dict[str, Any]:
    match = re.fullmatch(
        r"(?P<parent>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
        r"(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?",
        str(source or ""),
    )
    if not match:
        return {}
    try:
        offset = int(
            match.group("offset"),
            16 if match.group("offset").lower().startswith("0x") else 10,
        )
    except ValueError:
        return {}
    if offset <= 0:
        return {}
    return {
        "parent": match.group("parent"),
        "offset": offset,
    }


def _parse_parameter_indexed_source(source: str) -> dict[str, Any]:
    match = re.fullmatch(
        r"(?P<parent>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*"
        r"(?P<index>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\]",
        str(source or ""),
    )
    if not match:
        return {}
    try:
        index = int(
            match.group("index"),
            16 if match.group("index").lower().startswith("0x") else 10,
        )
    except ValueError:
        return {}
    if index <= 0:
        return {}
    return {
        "parent": match.group("parent"),
        "index": index,
    }


def _direct_call_result_source_identity(
    base: str,
    source: str,
    base_alias_assignment_count: int,
) -> dict[str, Any]:
    if base_alias_assignment_count <= 0:
        return {}
    if _layout_base_kind(base) != "temp":
        return {}
    if _layout_rhs_kind(source) != "call_result":
        return {}
    if not _parse_direct_call_result_name(source):
        return {}
    return {
        "source": _normalize_assignment_rhs(source),
        "source_kind": "call_result",
        "source_provenance": "direct_call_result_alias",
        "source_rhs_kind": "call_result",
        "base_alias_assignments": base_alias_assignment_count,
        "source_assignments": 0,
    }


def _parse_direct_call_result_name(source: str) -> str:
    match = re.fullmatch(
        r"(?P<name>[A-Za-z_][A-Za-z0-9_:~]*)\s*\([^;\n]*\)",
        str(source or "").strip(),
    )
    if not match:
        return ""
    name = match.group("name")
    if name.startswith("sub_") or name.startswith("guard_dispatch_"):
        return ""
    return name


def _trusted_stable_base_source_identity(text: str, base: str) -> dict[str, Any]:
    identity = _stable_base_source_identity(text, base)
    if not identity:
        return {}
    if identity.get("source_provenance") in _TRUSTED_STABLE_BASE_SOURCE_PROVENANCES:
        return identity
    return {}


def _stable_source_provenance_class(
    source_kind: str,
    base_alias_assignment_count: int,
    source_assignment_count: int,
    source_rhs_kind: str,
) -> str:
    if base_alias_assignment_count <= 0:
        return "missing_alias_assignment"
    if source_kind == "argument":
        return "direct_argument_alias"
    if source_kind == "named":
        if source_assignment_count == 1 and source_rhs_kind == "call_result":
            return "named_call_result_alias"
        if source_assignment_count == 1 and source_rhs_kind == "direct_identifier":
            return "named_direct_alias"
        if source_assignment_count == 1 and source_rhs_kind in {"address", "deref", "pointer_arithmetic"}:
            return "named_derived_pointer_alias"
        if source_assignment_count > 1:
            return "named_multi_assignment_alias"
        return "named_existing_alias"
    if source_kind == "generic":
        return "generic_source_alias"
    if source_kind == "temporary":
        return "temporary_source_alias"
    return "unknown_source_alias"


def _layout_rhs_kind(rhs: str) -> str:
    value = _normalize_assignment_rhs(rhs)
    if not value:
        return "empty"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        return "direct_identifier"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n]*\)", value):
        return "call_result"
    if value.startswith("&"):
        return "address"
    if value.startswith("*"):
        return "deref"
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\b\s*(?:\+|-)", value):
        return "pointer_arithmetic"
    return "expression"


def _layout_source_kind(source: str) -> str:
    value = str(source or "").strip()
    if _is_generic_argument_base(value):
        return "argument"
    if _is_decompiler_temp_base(value):
        return "temporary"
    if _is_generic_named_base(value):
        return "generic"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        if _is_scalar_like_base(value):
            return "scalar"
        return "named"
    return "expression"


def _normalize_assignment_rhs(value: str) -> str:
    text = " ".join(str(value or "").strip().split())
    while True:
        previous = text
        text = _strip_assignment_cast_prefix(text)
        text = _strip_redundant_outer_parentheses(text)
        if text == previous:
            return text


def _strip_assignment_cast_prefix(value: str) -> str:
    text = str(value or "").strip()
    while True:
        match = re.match(r"^\((?P<type>[^()]+)\)\s*(?P<rest>.+)$", text)
        if match is None:
            return text
        type_text = " ".join(match.group("type").strip().split())
        if not _looks_like_cast_type(type_text):
            return text
        text = match.group("rest").strip()


def _looks_like_cast_type(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if any(token in text for token in "+-/=%[]{}.,"):
        return False
    stripped = text.replace("*", " ").replace("&", " ")
    words = [word for word in stripped.split() if word]
    if not words:
        return True
    lowered = {word.lower() for word in words}
    type_words = {
        "__int64",
        "_byte",
        "_dword",
        "_qword",
        "_word",
        "char",
        "const",
        "dword",
        "int",
        "long",
        "short",
        "signed",
        "size_t",
        "uint64",
        "ulong",
        "unsigned",
        "void",
        "word",
    }
    if lowered.intersection(type_words):
        return True
    return bool(re.fullmatch(r"P[A-Z0-9_]+", words[-1]))


def _strip_redundant_outer_parentheses(value: str) -> str:
    text = str(value or "").strip()
    while text.startswith("(") and text.endswith(")") and _outer_parentheses_wrap_all(text):
        text = text[1:-1].strip()
    return text


def _outer_parentheses_wrap_all(value: str) -> bool:
    text = str(value or "")
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(text) - 1:
                return False
            if depth < 0:
                return False
    return depth == 0


def _first_layout_access_start(text: str, base: str) -> int:
    for match in _OFFSET_DEREF_RE.finditer(text or ""):
        if match.group("base") == base:
            return match.start()
    return -1


def _next_layout_access_start(text: str, base: str, start: int) -> int:
    for match in _OFFSET_DEREF_RE.finditer(text or "", max(0, int(start))):
        if match.group("base") == base:
            return match.start()
    return -1


def _base_address_taken(text: str, base: str) -> bool:
    return re.search(r"&\s*%s\b" % re.escape(base), text or "") is not None


def _base_has_array_index_use(text: str, base: str) -> bool:
    return re.search(r"\b%s\s*\[" % re.escape(base), text or "") is not None

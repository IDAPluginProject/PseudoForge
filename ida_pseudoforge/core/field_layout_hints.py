from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from ida_pseudoforge.core.domain_identity import (
    MODE_CANONICAL_REWRITE_ELIGIBLE,
    MODE_PREVIEW_REWRITE,
    MODE_REPORT_ONLY,
    DomainIdentityField,
    DomainIdentityMatch,
    domain_identity_match_for_base,
    domain_identity_matches,
    domain_identity_profiles_available,
    domain_identity_role_matches,
)
from ida_pseudoforge.core.event_builder_patterns import etw_event_builder_append_counts
from ida_pseudoforge.core.plan_schema import CorrectedParameterMapEntry


_OFFSET_DEREF_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[A-Za-z_][A-Za-z0-9_:\s]*?)\s*"
    r"(?P<pointer_stars>\*+)\s*\)\s*"
    r"\(\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
)
_OFFSET_INDEXED_DEREF_RE = re.compile(
    r"\*\s*\(\s*\(\s*(?P<type>[A-Za-z_][A-Za-z0-9_:\s]*?)\s*"
    r"(?P<pointer_stars>\*+)\s*\)\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<index>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
)
_INDEXED_ACCESS_RE = re.compile(
    r"\b(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\[\s*(?P<index>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\]"
)
_CALLBACK_TABLE_SLOT_RE = re.compile(
    r"\*\s*\(\s*\([^;\n]*\*\s*\*[^;\n]*\)\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<slot>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
)
_DIRECT_ASSIGNMENT_RE = re.compile(
    r"(?m)^\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?P<op>\+=|-=|\*=|/=|%=|&=|\|=|\^=|=)(?!=)\s*"
    r"(?P<rhs>[^;\n]*);\s*(?://[^\n]*)?$"
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
    "named_branch_call_result_alias",
    "local_out_parameter_alias",
    "named_call_result_alias",
    "named_parameter_direct_alias",
    "parameter_field_pointer_alias",
    "parameter_indirect_pointer_alias",
    "parameter_back_container_alias",
    "parameter_direct_alias",
    "parameter_indexed_pointer_alias",
    "parameter_subobject_pointer_alias",
    "allocation_subobject_pointer_alias",
    "temporary_parameter_direct_alias",
    "temporary_call_result_alias",
}
_DOMAIN_IDENTITY_ALIAS_SOURCE_PROVENANCES = {
    "named_parameter_direct_alias",
    "parameter_direct_alias",
    "temporary_parameter_direct_alias",
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
_HOT_FIELD_CLUSTER_MIN_OFFSETS = 2
_HOT_FIELD_CLUSTER_MAX_OFFSETS = 7
_HOT_FIELD_CLUSTER_MIN_ACCESSES = 16
_HOT_FIELD_CLUSTER_MIN_TOP_OFFSET_ACCESSES = 6
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
    offset_access_counts: Counter[int] = field(default_factory=Counter)
    access_count: int = 0


@dataclass(slots=True)
class _IndexedLayoutEvidence:
    base: str
    scalar_indexes: Counter[int] = field(default_factory=Counter)
    callback_slots: Counter[int] = field(default_factory=Counter)
    alias_bases: set[str] = field(default_factory=set)


def field_layout_comments(
    text: str,
    max_comments: int = 4,
    profile_context: dict[str, Any] | None = None,
    corrected_parameter_map: list[CorrectedParameterMapEntry] | None = None,
) -> list[dict[str, Any]]:
    layouts = _collect_layouts(text or "")
    profile_matches = _domain_identity_matches_for_layouts(
        text or "",
        layouts,
        profile_context,
        corrected_parameter_map=corrected_parameter_map,
    )
    suppressed_layout_bases = {
        base
        for base, match in profile_matches.items()
        if _domain_identity_suppresses_layout_inference(match)
    }
    candidates = [
        item
        for item in layouts.values()
        if item.base not in suppressed_layout_bases
        and (_has_enough_layout_evidence(item) or item.base in profile_matches)
    ]
    candidates.sort(key=lambda item: (-len(item.offsets), -item.access_count, item.base.lower()))
    comments = []
    selected_candidates = candidates[:max(0, int(max_comments or 0))]
    selected_bases = {item.base for item in selected_candidates}
    for item in selected_candidates:
        domain_identity = profile_matches.get(item.base)
        comments.append(_comment_from_layout(item))
        identity_comment = _domain_identity_comment_from_match(text or "", domain_identity, item)
        if identity_comment:
            comments.append(identity_comment)
        append_pattern = _domain_identity_append_pattern_comment(text or "", domain_identity, item)
        if append_pattern:
            comments.append(append_pattern)
        preview = _field_preview_comment_from_layout(item, domain_identity)
        if preview:
            comments.append(preview)
        alias_preview = _field_alias_comment_from_layout(
            text or "",
            item,
            domain_identity,
            require_preview=domain_identity is None or domain_identity.ambiguous,
        )
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
            overlay_preview = _field_subfield_overlay_comment_from_layout(text or "", item, domain_identity)
            if overlay_preview:
                comments.append(overlay_preview)
                narrow_preview = _field_narrow_subfield_comment_from_layout(text or "", item, domain_identity)
                if narrow_preview:
                    comments.append(narrow_preview)
                bitfield_alias_preview = _field_bitfield_alias_comment_from_layout(
                    text or "",
                    item,
                    domain_identity,
                )
                if bitfield_alias_preview:
                    comments.append(bitfield_alias_preview)
            unaligned_preview = _field_unaligned_subfield_comment_from_layout(item, domain_identity)
            if unaligned_preview:
                comments.append(unaligned_preview)
        blocker = _field_rewrite_blocker_comment(
            text or "",
            item,
            profile_context,
            corrected_parameter_map=corrected_parameter_map,
        )
        if blocker:
            comments.append(blocker)
            stability = _field_base_stability_comment_from_layout(text or "", item, blocker)
            if stability:
                comments.append(stability)
                merge = _field_base_merge_evidence_comment(text or "", item, blocker, stability)
                if merge:
                    comments.append(merge)
                    allocation_null = _field_allocation_null_merge_dominance_comment(
                        text or "",
                        item,
                        merge,
                    )
                    if allocation_null:
                        comments.append(allocation_null)
                    same_source_dominance = _field_same_source_family_merge_dominance_comment(
                        text or "",
                        item,
                        merge,
                    )
                    if same_source_dominance:
                        comments.append(same_source_dominance)
                        same_family_provenance = _field_same_family_merge_provenance_comment(
                            item,
                            same_source_dominance,
                        )
                        if same_family_provenance:
                            comments.append(same_family_provenance)
                    call_result_equivalence = _field_call_result_merge_equivalence_comment(
                        text or "",
                        item,
                        merge,
                    )
                    if call_result_equivalence:
                        comments.append(call_result_equivalence)
                    parameter_provenance = _field_call_result_parameter_merge_provenance_comment(
                        text or "",
                        item,
                        merge,
                    )
                    if parameter_provenance:
                        comments.append(parameter_provenance)
                        parameter_dominance = _field_call_result_parameter_dominance_comment(
                            item,
                            parameter_provenance,
                        )
                        if parameter_dominance:
                            comments.append(parameter_dominance)
                    bugcheck_identity = _field_bugcheck_parameter_merge_identity_comment(
                        text or "",
                        item,
                        merge,
                    )
                    if bugcheck_identity:
                        comments.append(bugcheck_identity)
                    temporary_provenance = _field_call_result_temporary_merge_provenance_comment(
                        text or "",
                        item,
                        merge,
                    )
                    if temporary_provenance:
                        comments.append(temporary_provenance)
                relocation = _field_base_relocation_evidence_comment(text or "", item, blocker, stability)
                if relocation:
                    comments.append(relocation)
                post_access_mutation = _field_post_access_mutation_blocker_comment(
                    item,
                    blocker,
                    stability,
                )
                if post_access_mutation:
                    comments.append(post_access_mutation)
            expression_source = _field_stable_expression_source_comment_from_layout(text or "", item, blocker)
            if expression_source:
                comments.append(expression_source)
            near_ready = _field_rewrite_near_ready_comment(item, blocker)
            if near_ready:
                comments.append(near_ready)
            partial_opportunity = _field_rewrite_partial_opportunity_comment(text or "", item, blocker)
            if partial_opportunity:
                comments.append(partial_opportunity)
            temp_trace = _field_temp_provenance_trace_comment_from_layout(text or "", item, blocker=blocker)
            if temp_trace:
                comments.append(temp_trace)
                temp_blocked = _field_temp_promotion_blocked_comment_from_trace(temp_trace)
                if temp_blocked:
                    comments.append(temp_blocked)
        else:
            ready = _field_rewrite_ready_comment(
                text or "",
                item,
                profile_context,
                corrected_parameter_map=corrected_parameter_map,
            )
            if ready:
                comments.append(ready)
                rewrite_preview = _field_rewrite_preview_comment(text or "", item, ready, domain_identity)
                if rewrite_preview:
                    comments.append(rewrite_preview)
                temp_trace = _field_temp_provenance_trace_comment_from_layout(text or "", item)
                if temp_trace:
                    comments.append(temp_trace)
                    trusted_temp = _field_trusted_temp_source_comment_from_trace(temp_trace)
                    if trusted_temp:
                        comments.append(trusted_temp)
    hot_clusters = [
        item
        for item in layouts.values()
        if item.base not in selected_bases
        and item.base not in suppressed_layout_bases
        and _has_hot_field_cluster_evidence(item)
    ]
    hot_clusters.sort(
        key=lambda item: (
            -item.access_count,
            -_hot_field_cluster_top_offset_access_count(item),
            -len(item.offsets),
            item.base.lower(),
        )
    )
    for item in hot_clusters[:max(0, int(max_comments or 0))]:
        comments.append(_field_hot_cluster_comment_from_layout(item))
    indexed_evidence = [
        item
        for item in _collect_indexed_layout_evidence(text or "").values()
        if _has_indexed_layout_evidence(item)
    ]
    indexed_evidence.sort(
        key=lambda item: (
            -_indexed_layout_access_count(item),
            -_indexed_layout_slot_count(item),
            item.base.lower(),
        )
    )
    for item in indexed_evidence[:max(0, int(max_comments or 0))]:
        comments.append(_indexed_layout_comment_from_evidence(item))
    return comments


def domain_identity_role_comments(
    text: str,
    profile_context: dict[str, Any] | None = None,
    exclude_bases: set[str] | None = None,
) -> list[dict[str, Any]]:
    excluded = {str(item) for item in (exclude_bases or set()) if str(item)}
    comments = []
    for match in domain_identity_role_matches(text or "", profile_context=profile_context):
        if match.base in excluded:
            continue
        comments.append(_domain_identity_role_comment_from_match(match))
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
        type_name = _normalize_offset_access_type(
            match.group("type"),
            match.group("pointer_stars"),
        )
        if not type_name:
            continue
        layout = layouts.setdefault(base, _LayoutEvidence(base=base))
        layout.access_count += 1
        layout.offset_access_counts[offset] += 1
        layout.offsets.setdefault(offset, set()).add(type_name)
    for match in _OFFSET_INDEXED_DEREF_RE.finditer(text):
        base = match.group("base")
        if _is_scalar_like_base(base):
            continue
        offset = _indexed_deref_byte_offset(match)
        if offset is None:
            continue
        layout = layouts.setdefault(base, _LayoutEvidence(base=base))
        layout.access_count += 1
        layout.offset_access_counts[offset] += 1
        type_name = _normalize_offset_access_type(
            match.group("type"),
            match.group("pointer_stars"),
        )
        layout.offsets.setdefault(offset, set()).add(type_name)
    return layouts


def _collect_indexed_layout_evidence(text: str) -> dict[str, _IndexedLayoutEvidence]:
    aliases = _direct_identifier_aliases(text)
    evidence_by_base: dict[str, _IndexedLayoutEvidence] = {}
    for match in _INDEXED_ACCESS_RE.finditer(text or ""):
        raw_base = match.group("base")
        index = _parse_offset(match.group("index"))
        base = _indexed_layout_canonical_base(text, raw_base, aliases, match.start())
        if not base or index is None or index <= 0:
            continue
        evidence = evidence_by_base.setdefault(base, _IndexedLayoutEvidence(base=base))
        evidence.scalar_indexes[index] += 1
        if raw_base != base:
            evidence.alias_bases.add(raw_base)
    for match in _CALLBACK_TABLE_SLOT_RE.finditer(text or ""):
        raw_base = match.group("base")
        slot = _parse_offset(match.group("slot"))
        base = _indexed_layout_canonical_base(text, raw_base, aliases, match.start())
        if not base or slot is None or slot <= 0:
            continue
        evidence = evidence_by_base.setdefault(base, _IndexedLayoutEvidence(base=base))
        evidence.callback_slots[slot] += 1
        if raw_base != base:
            evidence.alias_bases.add(raw_base)
    return evidence_by_base


def _indexed_layout_canonical_base(
    text: str,
    raw_base: str,
    aliases: dict[str, str],
    position: int = -1,
) -> str:
    base = str(raw_base or "")
    if not base or _is_scalar_like_base(base):
        return ""
    if _base_is_function_parameter(text, base):
        return base
    if position >= 0:
        return _indexed_layout_alias_base_before(text, base, position, {base})
    seen = {base}
    current = base
    for _ in range(4):
        source = aliases.get(current, "")
        if not source or source in seen:
            return ""
        if _base_is_function_parameter(text, source):
            return source
        seen.add(source)
        current = source
    return ""


def _indexed_layout_alias_base_before(
    text: str,
    base: str,
    before: int,
    seen: set[str],
) -> str:
    assignments = [
        item
        for item in _base_direct_assignments(text, base)
        if item.start() < before
    ]
    if not assignments:
        return ""
    assignment = assignments[-1]
    if assignment.group("op") != "=":
        return ""
    source = _normalize_assignment_rhs(assignment.group("rhs"))
    if not _is_identifier_expression(source) or source in seen:
        return ""
    if _base_is_function_parameter(text, source):
        return source
    seen.add(source)
    return _indexed_layout_alias_base_before(text, source, assignment.start(), seen)


def _direct_identifier_aliases(text: str) -> dict[str, str]:
    assignments_by_lhs: dict[str, list[re.Match[str]]] = {}
    for match in _DIRECT_ASSIGNMENT_RE.finditer(text or ""):
        lhs = match.group("lhs")
        assignments_by_lhs.setdefault(lhs, []).append(match)
    aliases: dict[str, str] = {}
    for lhs, assignments in assignments_by_lhs.items():
        if not assignments or _base_is_function_parameter(text, lhs):
            continue
        if any(item.group("op") != "=" for item in assignments):
            continue
        rhs_values = [
            _normalize_assignment_rhs(item.group("rhs"))
            for item in assignments
        ]
        if any(not _is_identifier_expression(item) for item in rhs_values):
            continue
        distinct_rhs = {item for item in rhs_values if item and item != lhs}
        if len(distinct_rhs) != 1:
            continue
        aliases[lhs] = next(iter(distinct_rhs))
    return aliases


def _has_enough_layout_evidence(layout: _LayoutEvidence) -> bool:
    distinct_offsets = len(layout.offsets)
    if _layout_base_kind(layout.base) in {"temp", "generic", "argument", "bugcheck"}:
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


def _has_indexed_layout_evidence(evidence: _IndexedLayoutEvidence) -> bool:
    slot_count = _indexed_layout_slot_count(evidence)
    access_count = _indexed_layout_access_count(evidence)
    callback_slot_count = len(evidence.callback_slots)
    if slot_count >= 5 and access_count >= 5:
        return True
    return callback_slot_count >= 2 and slot_count >= 3 and access_count >= 3


def _indexed_layout_access_count(evidence: _IndexedLayoutEvidence) -> int:
    return int(sum(evidence.scalar_indexes.values()) + sum(evidence.callback_slots.values()))


def _indexed_layout_slot_count(evidence: _IndexedLayoutEvidence) -> int:
    return len(set(evidence.scalar_indexes) | set(evidence.callback_slots))


def _indexed_slot_text(prefix: str, slots: list[int]) -> str:
    if not slots:
        return "none"
    shown = slots[:8]
    text = ", ".join("%s_%d" % (prefix, item) for item in shown)
    if len(slots) > len(shown):
        text += ", ..."
    return text


def _indexed_layout_comment_from_evidence(evidence: _IndexedLayoutEvidence) -> dict[str, Any]:
    scalar_indexes = sorted(evidence.scalar_indexes)
    callback_slots = sorted(evidence.callback_slots)
    scalar_text = _indexed_slot_text("index", scalar_indexes)
    callback_text = _indexed_slot_text("slot", callback_slots)
    alias_text = ""
    if evidence.alias_bases:
        alias_text = " Alias bases %s." % ", ".join(sorted(evidence.alias_bases))
    base_kind = _layout_base_kind(evidence.base)
    access_count = _indexed_layout_access_count(evidence)
    slot_count = _indexed_layout_slot_count(evidence)
    confidence = min(
        _field_indexed_layout_confidence_cap_for_base_kind(base_kind),
        0.56 + slot_count * 0.02 + min(access_count, 12) * 0.008 + len(callback_slots) * 0.015,
    )
    return {
        "kind": "inferred_offset_indexed_callback_table_evidence",
        "text": (
            "Indexed layout evidence for %s (%s base): %d indexed/callback access(es) across %d slot(s); "
            "scalar indexes %s; callback slots %s.%s Review-only; indexed table access is not used for canonical field rewrite."
            % (
                evidence.base,
                _field_hot_cluster_base_kind_label(base_kind),
                access_count,
                slot_count,
                scalar_text,
                callback_text,
                alias_text,
            )
        ),
        "confidence": round(confidence, 2),
        "base": evidence.base,
        "base_kind": base_kind,
        "access_count": access_count,
        "slot_count": slot_count,
        "scalar_access_count": sum(evidence.scalar_indexes.values()),
        "callback_access_count": sum(evidence.callback_slots.values()),
        "scalar_indexes": scalar_indexes,
        "callback_slots": callback_slots,
        "alias_bases": sorted(evidence.alias_bases),
    }


def _domain_identity_matches_for_layouts(
    text: str,
    layouts: dict[str, _LayoutEvidence],
    profile_context: dict[str, Any] | None = None,
    corrected_parameter_map: list[CorrectedParameterMapEntry] | None = None,
) -> dict[str, DomainIdentityMatch]:
    if not domain_identity_profiles_available() and not corrected_parameter_map:
        return {}
    non_identity_blockers_by_base = {
        base: _non_identity_layout_rewrite_blockers(text or "", layout)
        for base, layout in layouts.items()
    }
    matches = {}
    if domain_identity_profiles_available():
        matches = domain_identity_matches(
            text or "",
            set(layouts),
            non_identity_blockers_by_base=non_identity_blockers_by_base,
            profile_context=profile_context,
        )
    for base in sorted(set(layouts) - set(matches)):
        corrected_match = _corrected_parameter_domain_identity_for_layout(
            layouts[base],
            corrected_parameter_map,
        )
        if corrected_match:
            matches[base] = corrected_match
    direct_matches = dict(matches)
    for base in sorted(set(layouts) - set(matches)):
        identity = _trusted_stable_base_source_identity(text or "", base)
        if identity.get("source_provenance") not in _DOMAIN_IDENTITY_ALIAS_SOURCE_PROVENANCES:
            continue
        source = str(identity.get("source", "") or "")
        source_match = direct_matches.get(source)
        if not source_match:
            continue
        matches[base] = _domain_identity_match_for_alias(source_match, base, identity)
    return matches


def _domain_identity_for_layout(
    text: str,
    layout: _LayoutEvidence,
    non_identity_blockers: list[str] | None = None,
    profile_context: dict[str, Any] | None = None,
    corrected_parameter_map: list[CorrectedParameterMapEntry] | None = None,
) -> DomainIdentityMatch | None:
    blockers = non_identity_blockers
    if blockers is None:
        blockers = _non_identity_layout_rewrite_blockers(text or "", layout)
    match = domain_identity_match_for_base(
        text or "",
        layout.base,
        non_identity_blockers=blockers,
        profile_context=profile_context,
    )
    if match:
        return match
    return _corrected_parameter_domain_identity_for_layout(layout, corrected_parameter_map)


def _corrected_parameter_domain_identity_for_layout(
    layout: _LayoutEvidence,
    corrected_parameter_map: list[CorrectedParameterMapEntry] | None,
) -> DomainIdentityMatch | None:
    for entry in sorted(corrected_parameter_map or [], key=lambda item: (item.parameter_index, item.profile_id)):
        if layout.base not in _corrected_parameter_base_names(entry):
            continue
        if not entry.body_canonical_rewrite:
            continue
        fields = tuple(
            DomainIdentityField(
                offset=field.offset,
                name=field.name,
                type_text=field.type_text,
                size=field.size,
                confidence=field.confidence,
                source=field.source,
                provenance=field.provenance,
                note=field.note,
            )
            for field in entry.fields
        )
        if not fields:
            continue
        return DomainIdentityMatch(
            profile_id=entry.profile_id,
            base=layout.base,
            role=entry.role,
            structure=entry.structure,
            mode=MODE_CANONICAL_REWRITE_ELIGIBLE,
            effective_mode=MODE_CANONICAL_REWRITE_ELIGIBLE,
            confidence=round(min(entry.confidence, 0.86), 2),
            parameter_index=entry.parameter_index,
            parameter_name=entry.new_name or entry.old_name or layout.base,
            fields=fields,
            match_reason="corrected parameter map from profile %s" % entry.profile_id,
            profile_source=entry.source,
            profile_metadata=(
                ("corrected_type", entry.display_type or entry.canonical_type),
                ("old_type", entry.old_type),
                ("provenance", entry.provenance),
            ),
        )
    return None


def _corrected_parameter_base_names(entry: CorrectedParameterMapEntry) -> set[str]:
    return {
        item
        for item in set(entry.base_names or []) | {entry.old_name, entry.new_name}
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(item or ""))
    }


def _domain_identity_match_for_alias(
    match: DomainIdentityMatch,
    base: str,
    identity: dict[str, Any],
) -> DomainIdentityMatch:
    source_alias = str(identity.get("source_alias", "") or "")
    source_text = str(identity.get("source", "") or match.base)
    reason = "%s via stable source %s" % (match.match_reason, source_text)
    if source_alias and source_alias != source_text:
        reason += " through %s" % source_alias
    return DomainIdentityMatch(
        profile_id=match.profile_id,
        base=base,
        role=match.role,
        structure=match.structure,
        mode=match.mode,
        effective_mode=match.effective_mode,
        confidence=round(min(match.confidence, 0.70), 2),
        parameter_index=match.parameter_index,
        parameter_name=match.parameter_name,
        fields=match.fields,
        match_reason=reason,
        forced_report_only_reasons=match.forced_report_only_reasons,
        ambiguous_profile_ids=match.ambiguous_profile_ids,
        profile_source=match.profile_source,
        profile_version=match.profile_version,
        profile_metadata=match.profile_metadata,
        suppress_layout_inference=match.suppress_layout_inference,
    )


def _domain_identity_suppresses_layout_inference(domain_identity: DomainIdentityMatch) -> bool:
    return domain_identity.suppress_layout_inference


def _domain_identity_comment_from_match(
    text: str,
    domain_identity: DomainIdentityMatch | None,
    layout: _LayoutEvidence,
) -> dict[str, Any] | None:
    if domain_identity is None:
        return None
    field_text = _domain_identity_field_text(text, domain_identity, layout)
    if domain_identity.ambiguous:
        detail = "ambiguous profiles %s" % ", ".join(domain_identity.ambiguous_profile_ids[:6])
        mode_text = "report-only"
    else:
        detail = domain_identity.match_reason
        mode_text = domain_identity.effective_mode
    forced_text = ""
    if domain_identity.forced_report_only_reasons:
        forced_text = " Forced report-only by %s." % ", ".join(domain_identity.forced_report_only_reasons)
    return {
        "kind": "domain_structure_identity",
        "text": (
            "Domain identity for %s: role %s, structure %s, mode %s, %s. Fields %s.%s "
            "Canonical rewrite still requires existing validation-gated layout export."
            % (
                layout.base,
                domain_identity.role,
                domain_identity.structure,
                mode_text,
                detail,
                field_text,
                forced_text,
            )
        ),
        "confidence": domain_identity.confidence,
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "profile_id": domain_identity.profile_id,
        "matched_profile_id": domain_identity.profile_id,
        "role": domain_identity.role,
        "trusted_role": domain_identity.role,
        "structure": domain_identity.structure,
        "structure_name": domain_identity.structure,
        "mode": domain_identity.mode,
        "effective_mode": domain_identity.effective_mode,
        "parameter_index": domain_identity.parameter_index,
        "parameter_name": domain_identity.parameter_name,
        "fields": _domain_identity_observed_fields(text, domain_identity, layout),
        "ambiguous_profile_ids": list(domain_identity.ambiguous_profile_ids),
        "forced_report_only_reasons": list(domain_identity.forced_report_only_reasons),
        "blockers": _domain_identity_structured_blockers(domain_identity),
        "profile_source": domain_identity.profile_source,
        "profile_version": domain_identity.profile_version,
        "profile_metadata": dict(domain_identity.profile_metadata),
        "suppress_layout_inference": domain_identity.suppress_layout_inference,
    }


def _domain_identity_structured_blockers(domain_identity: DomainIdentityMatch) -> list[str]:
    blockers = list(domain_identity.forced_report_only_reasons)
    if domain_identity.ambiguous:
        blockers.append("ambiguous_profile_match")
    elif domain_identity.effective_mode == MODE_REPORT_ONLY:
        blockers.append("profile_report_only")
    elif domain_identity.effective_mode == MODE_PREVIEW_REWRITE:
        blockers.append("profile_preview_only")
    elif domain_identity.effective_mode != MODE_CANONICAL_REWRITE_ELIGIBLE:
        blockers.append("unsupported_profile_mode")
    return list(dict.fromkeys(blockers))


def _domain_identity_role_comment_from_match(domain_identity: DomainIdentityMatch) -> dict[str, Any]:
    if domain_identity.ambiguous:
        detail = "ambiguous profiles %s" % ", ".join(domain_identity.ambiguous_profile_ids[:6])
        mode_text = "report-only"
    else:
        detail = domain_identity.match_reason
        mode_text = domain_identity.effective_mode
    forced_text = ""
    if domain_identity.forced_report_only_reasons:
        forced_text = " Forced report-only by %s." % ", ".join(domain_identity.forced_report_only_reasons)
    return {
        "kind": "domain_structure_identity",
        "text": (
            "Domain identity for %s: role %s, structure %s, mode %s, %s. Fields none observed.%s "
            "Role-only evidence; no field rewrite was applied."
            % (
                domain_identity.base,
                domain_identity.role,
                domain_identity.structure,
                mode_text,
                detail,
                forced_text,
            )
        ),
        "confidence": domain_identity.confidence,
        "base": domain_identity.base,
        "base_kind": "role",
        "profile_id": domain_identity.profile_id,
        "matched_profile_id": domain_identity.profile_id,
        "role": domain_identity.role,
        "trusted_role": domain_identity.role,
        "structure": domain_identity.structure,
        "structure_name": domain_identity.structure,
        "mode": domain_identity.mode,
        "effective_mode": domain_identity.effective_mode,
        "parameter_index": domain_identity.parameter_index,
        "parameter_name": domain_identity.parameter_name,
        "fields": [],
        "ambiguous_profile_ids": list(domain_identity.ambiguous_profile_ids),
        "forced_report_only_reasons": list(domain_identity.forced_report_only_reasons),
        "blockers": _domain_identity_structured_blockers(domain_identity),
        "profile_source": domain_identity.profile_source,
        "profile_version": domain_identity.profile_version,
        "profile_metadata": dict(domain_identity.profile_metadata),
        "suppress_layout_inference": domain_identity.suppress_layout_inference,
        "role_only": True,
    }


def _domain_identity_field_text(text: str, domain_identity: DomainIdentityMatch, layout: _LayoutEvidence) -> str:
    fields = _domain_identity_observed_fields(text, domain_identity, layout)
    if not fields:
        return "none observed"
    text = "; ".join(
        _domain_identity_field_item_text(item)
        for item in fields[:8]
    )
    if len(fields) > 8:
        text += "; ..."
    return text


def _domain_identity_field_item_text(item: dict[str, Any]) -> str:
    text = "+0x%X %s %s" % (item["offset"], item["type"], item["name"])
    note = str(item.get("note", "") or "")
    if note:
        text += " (%s)" % note
    return text


def _domain_identity_observed_fields(
    text: str,
    domain_identity: DomainIdentityMatch,
    layout: _LayoutEvidence,
) -> list[dict[str, Any]]:
    fields = []
    observed_offsets = set(layout.offsets)
    if _domain_identity_direct_base_access_exists(text, domain_identity, layout.base):
        observed_offsets.add(0)
    for offset in sorted(observed_offsets):
        field_item = domain_identity.field_for_offset(offset)
        if not field_item:
            continue
        fields.append(
            {
                "offset": offset,
                "name": field_item.name,
                "type": field_item.type_text,
                "size": field_item.size,
                "confidence": field_item.confidence,
                "source": field_item.source,
                "provenance": field_item.provenance,
                "note": field_item.note,
            }
        )
    return fields


def _domain_identity_direct_base_access_exists(
    text: str,
    domain_identity: DomainIdentityMatch,
    base: str,
) -> bool:
    if domain_identity.field_for_offset(0) is None:
        return False
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", base or ""):
        return False
    return (
        re.search(
            r"\*\s*\(\s*[^)]*\*\s*\)\s*%s\b" % re.escape(base),
            text or "",
        )
        is not None
    )


def _domain_identity_append_pattern_comment(
    text: str,
    domain_identity: DomainIdentityMatch | None,
    layout: _LayoutEvidence,
) -> dict[str, Any] | None:
    if domain_identity is None:
        return None
    if domain_identity.structure != "SMST_ETW_EVENT_BUILDER":
        return None
    base = layout.base
    counts = etw_event_builder_append_counts(text or "", base)
    if (
        counts["payload_buffer_targets"] <= 0
        or counts["descriptor_table_slots"] <= 0
        or counts["item_count_updates"] <= 0
        or counts["payload_offset_updates"] <= 0
    ):
        return None
    minimum_count = min(
        counts["payload_buffer_targets"],
        counts["descriptor_table_slots"],
        counts["item_count_updates"],
        counts["payload_offset_updates"],
    )
    confidence = min(0.84, 0.66 + min(minimum_count, 8) * 0.02)
    return {
        "kind": "domain_event_builder_append_pattern",
        "text": (
            "ETW append pattern for %s: payloadBuffer target(s)=%d, descriptorTable slot(s)=%d, "
            "itemCount update(s)=%d, payloadWriteOffset update(s)=%d. Review-only; each item writes "
            "payload data, stores a pointer/size descriptor, increments itemCount, and advances payloadWriteOffset."
            % (
                base,
                counts["payload_buffer_targets"],
                counts["descriptor_table_slots"],
                counts["item_count_updates"],
                counts["payload_offset_updates"],
            )
        ),
        "confidence": round(confidence, 2),
        "base": base,
        "base_kind": _layout_base_kind(base),
        "profile_id": domain_identity.profile_id,
        "role": domain_identity.role,
        "structure": domain_identity.structure,
        **counts,
    }

def _field_preview_comment_from_layout(
    layout: _LayoutEvidence,
    domain_identity: DomainIdentityMatch | None = None,
) -> dict[str, Any] | None:
    base_kind = _layout_base_kind(layout.base)
    if base_kind == "named":
        if len(layout.offsets) < 5 or layout.access_count < 5:
            return None
    elif len(layout.offsets) < 8 or layout.access_count < 12:
        return None
    fields = _preview_fields(layout, domain_identity)
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


def _field_alias_comment_from_layout(
    text: str,
    layout: _LayoutEvidence,
    domain_identity: DomainIdentityMatch | None = None,
    require_preview: bool = True,
) -> dict[str, Any] | None:
    base_kind = _layout_base_kind(layout.base)
    if domain_identity is None or require_preview:
        if base_kind == "named":
            if len(layout.offsets) < 5 or layout.access_count < 5:
                return None
        elif len(layout.offsets) < 8 or layout.access_count < 12:
            return None
    fields = _preview_fields(layout, domain_identity, text=text)
    if domain_identity is not None and not require_preview:
        fields = [item for item in fields if item.get("profile_confidence", 0.0)]
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


def _field_hot_cluster_comment_from_layout(layout: _LayoutEvidence) -> dict[str, Any]:
    base_kind = _layout_base_kind(layout.base)
    fields = _hot_field_cluster_fields(layout)
    field_text = "; ".join(
        "%s=+0x%X %s x%d" % (
            item["name"],
            item["offset"],
            item["type"],
            item["access_count"],
        )
        for item in fields[:6]
    )
    if len(fields) > 6:
        field_text += "; ..."
    confidence = min(
        _field_hot_cluster_confidence_cap_for_base_kind(base_kind),
        (
            0.58
            + min(layout.access_count, 40) * 0.004
            + min(_hot_field_cluster_top_offset_access_count(layout), 16) * 0.006
            + len(layout.offsets) * 0.005
        ),
    )
    return {
        "kind": "inferred_offset_field_hot_cluster",
        "text": _field_hot_cluster_text(
            layout.base,
            base_kind,
            layout.access_count,
            len(layout.offsets),
            field_text,
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": base_kind,
        "access_count": layout.access_count,
        "offset_count": len(layout.offsets),
        "fields": fields,
    }


def _field_subfield_overlay_comment_from_layout(
    text: str,
    layout: _LayoutEvidence,
    domain_identity: DomainIdentityMatch | None = None,
) -> dict[str, Any] | None:
    overlays = _subfield_overlay_fields(layout, text, domain_identity)
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


def _field_narrow_subfield_comment_from_layout(
    text: str,
    layout: _LayoutEvidence,
    domain_identity: DomainIdentityMatch | None = None,
) -> dict[str, Any] | None:
    fields = [
        item
        for item in _subfield_overlay_fields(layout, text, domain_identity)
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


def _field_bitfield_alias_comment_from_layout(
    text: str,
    layout: _LayoutEvidence,
    domain_identity: DomainIdentityMatch | None = None,
) -> dict[str, Any] | None:
    fields = []
    for item in _subfield_overlay_fields(layout, text, domain_identity):
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


def _field_unaligned_subfield_comment_from_layout(
    layout: _LayoutEvidence,
    domain_identity: DomainIdentityMatch | None = None,
) -> dict[str, Any] | None:
    fields = _unaligned_subfield_fields(layout, domain_identity)
    if not fields:
        return None
    base_kind = _layout_base_kind(layout.base)
    field_text = "; ".join(_unaligned_subfield_text(item) for item in fields[:6])
    if len(fields) > 6:
        field_text += "; ..."
    confidence = min(
        _field_narrow_subfield_confidence_cap_for_base_kind(base_kind),
        0.62 + len(fields) * 0.035 + min(layout.access_count, 12) * 0.005,
    )
    structure_text = ""
    if domain_identity:
        structure_text = "%s " % domain_identity.structure
    return {
        "kind": "inferred_offset_unaligned_subfields",
        "text": (
            "%ssubfield alignment evidence for %s: %s. Review-only; body rewrite remains blocked for unaligned typed offsets."
            % (structure_text, layout.base, field_text)
        ),
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
    if identity.get("source_container_offset"):
        comment["source_container_offset"] = identity["source_container_offset"]
    if identity.get("source_type"):
        comment["source_type"] = identity["source_type"]
    if identity.get("source_index"):
        comment["source_index"] = identity["source_index"]
    if identity.get("source_call"):
        comment["source_call"] = identity["source_call"]
    if identity.get("source_calls"):
        comment["source_calls"] = list(identity["source_calls"])
    if identity.get("source_call_names"):
        comment["source_call_names"] = list(identity["source_call_names"])
    if identity.get("source_alias"):
        comment["source_alias"] = identity["source_alias"]
    if identity.get("base_alias_assignments") is not None:
        comment["base_alias_assignments"] = int(identity["base_alias_assignments"])
    if identity.get("source_assignments") is not None:
        comment["source_assignments"] = int(identity["source_assignments"])
    return comment


def _field_stable_expression_source_comment_from_layout(
    text: str,
    layout: _LayoutEvidence,
    blocker: dict[str, Any],
) -> dict[str, Any] | None:
    if _layout_base_kind(layout.base) != "temp":
        return None
    blockers = {
        str(item)
        for item in blocker.get("blockers", []) or []
        if str(item)
    }
    if blockers != {"base is a decompiler temporary"}:
        return None
    threshold_policy = _field_rewrite_threshold_policy(layout)
    if not threshold_policy:
        return None
    identity = _stable_base_source_identity(text, layout.base)
    if identity.get("source_provenance") != "unknown_source_alias":
        return None
    source = str(identity.get("source", "") or "")
    source_profile = _stable_expression_source_profile(source)
    if not source_profile:
        return None
    source_kind = str(identity.get("source_kind", "") or _layout_source_kind(source))
    confidence = min(
        0.66,
        0.52 + len(layout.offsets) * 0.012 + min(layout.access_count, 16) * 0.004,
    )
    comment = {
        "kind": "inferred_offset_stable_expression_source",
        "text": _field_stable_expression_source_text(
            layout.base,
            source,
            str(source_profile["source_expression_kind"]),
            layout.access_count,
            len(layout.offsets),
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": "temp",
        "source": source,
        "source_kind": source_kind,
        "source_provenance": identity["source_provenance"],
        "source_rhs_kind": identity["source_rhs_kind"],
        "source_expression_kind": source_profile["source_expression_kind"],
        "threshold_policy": threshold_policy,
        "blocker_profile": "temporary_only",
        "offset_count": len(layout.offsets),
        "access_count": layout.access_count,
    }
    for key in ("source_parent", "source_offset", "source_container_offset", "source_index", "source_type"):
        if source_profile.get(key) not in {None, ""}:
            comment[key] = source_profile[key]
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
    threshold_policy = _generic_parameter_trust_threshold_policy(layout)
    if not threshold_policy:
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
        "threshold_policy": threshold_policy,
    }


def _field_temp_provenance_trace_comment_from_layout(
    text: str,
    layout: _LayoutEvidence,
    blocker: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    record = _temp_base_provenance_record(text, layout, blocker=blocker)
    if not record:
        return None
    confidence = min(
        0.78,
        0.58 + len(layout.offsets) * 0.014 + min(layout.access_count, 20) * 0.004,
    )
    if record["promotion_eligible"]:
        confidence = max(confidence, 0.72)
    elif record["trust_class"] in {
        "same_family_merge_review",
        "call_result_parameter_review",
        "call_result_temporary_review",
    }:
        confidence = max(confidence, 0.66)
    source = str(record.get("source", "") or "none")
    source_kind = str(record.get("source_kind", "") or "unknown")
    source_provenance = str(record.get("source_provenance", "") or "unknown")
    return {
        "kind": "inferred_offset_temp_provenance_trace",
        "text": (
            "Temp-base provenance trace for %s: trust class %s, source %s (%s/%s), "
            "origin %s, first layout access line %d, pre-access initializers %d/%d, "
            "post-access assignments %d risky %d, pointer mutation %s, address-taken %s, "
            "array-indexed %s, call-mutation-risk %s, branch merge %s, guard dominance %s."
            % (
                layout.base,
                record["trust_class"],
                source,
                source_kind,
                source_provenance,
                record["source_origin"],
                int(record["first_layout_access_line"]),
                int(record["pre_access_assignment_count"]),
                int(record["distinct_pre_access_rhs_count"]),
                int(record["post_access_assignment_count"]),
                int(record["risky_post_access_assignment_count"]),
                _yes_no(bool(record["pointer_mutation"])),
                _yes_no(bool(record["address_taken"])),
                _yes_no(bool(record["array_indexed"])),
                _yes_no(bool(record["call_mutation_risk"])),
                record["branch_merge_shape"],
                record["guard_dominance"],
            )
        ),
        "confidence": round(confidence, 2),
        **record,
    }


def _field_trusted_temp_source_comment_from_trace(trace: dict[str, Any]) -> dict[str, Any] | None:
    if trace.get("base_kind") != "temp":
        return None
    if trace.get("trust_class") != "trusted_stable_temp":
        return None
    source = str(trace.get("source", "") or "none")
    source_kind = str(trace.get("source_kind", "") or "unknown")
    source_provenance = str(trace.get("source_provenance", "") or "unknown")
    return {
        "kind": "inferred_offset_trusted_temp_source",
        "text": (
            "Trusted temp-base source for %s: source %s (%s/%s), origin %s, "
            "promotion ready yes, first layout access line %d. "
            "Single-source lifetime, blocker-free mutation, and threshold gates are satisfied."
            % (
                trace["base"],
                source,
                source_kind,
                source_provenance,
                trace["source_origin"],
                int(trace.get("first_layout_access_line", -1) or -1),
            )
        ),
        "confidence": min(0.8, max(0.72, float(trace.get("confidence", 0.72) or 0.72))),
        "base": trace["base"],
        "base_kind": trace["base_kind"],
        "source": source,
        "source_kind": source_kind,
        "source_provenance": source_provenance,
        "source_origin": trace["source_origin"],
        "trust_class": trace["trust_class"],
        "promotion_eligible": True,
        "offset_count": int(trace.get("offset_count", 0) or 0),
        "access_count": int(trace.get("access_count", 0) or 0),
    }


def _field_temp_promotion_blocked_comment_from_trace(trace: dict[str, Any]) -> dict[str, Any] | None:
    if trace.get("promotion_eligible"):
        return None
    reasons = [
        str(item)
        for item in trace.get("block_reasons", []) or []
        if str(item)
    ]
    if not reasons:
        reasons = [str(trace.get("trust_class", "") or "review_required")]
    reason_text = ", ".join(reasons[:8])
    blocker_text = "; ".join(str(item) for item in trace.get("blockers", []) or [] if str(item))
    if not blocker_text:
        blocker_text = "none"
    return {
        "kind": "inferred_offset_temp_promotion_blocked",
        "text": (
            "Temp-base promotion blocked for %s: trust class %s, reasons %s. "
            "Rewrite blockers %s. Canonical rewrite remains disabled until provenance, dominance, and mutation gates are clear."
            % (
                trace["base"],
                trace["trust_class"],
                reason_text,
                blocker_text,
            )
        ),
        "confidence": min(0.78, max(0.6, float(trace.get("confidence", 0.6) or 0.6))),
        "base": trace["base"],
        "base_kind": trace["base_kind"],
        "trust_class": trace["trust_class"],
        "block_reasons": reasons,
        "blockers": list(trace.get("blockers", []) or []),
        "source_origin": str(trace.get("source_origin", "") or "unknown"),
        "branch_merge_shape": str(trace.get("branch_merge_shape", "") or "none"),
    }


def _field_same_family_merge_provenance_comment(
    layout: _LayoutEvidence,
    dominance: dict[str, Any],
) -> dict[str, Any] | None:
    if dominance.get("merge_shape") != "same_source_family":
        return None
    guard_state = "present" if dominance.get("first_layout_access_guarded") else "missing"
    branch_shapes = ", ".join(
        "%s=%d" % (key, int(value))
        for key, value in sorted(_coerce_counter_dict(dominance.get("branch_shape_counts")).items())
    )
    if not branch_shapes:
        branch_shapes = "unknown"
    return {
        "kind": "inferred_offset_same_family_merge_provenance",
        "text": (
            "Same-family merge provenance for %s: root %s (%s), candidate count %d, "
            "branch shapes %s, guard dominance %s, trust class same_family_merge_review. "
            "Review-only until path-specific initializer dominance is validated."
            % (
                layout.base,
                str(dominance.get("source_root", "") or "unknown"),
                str(dominance.get("source_root_kind", "") or "unknown"),
                int(dominance.get("candidate_count", 0) or 0),
                branch_shapes,
                guard_state,
            )
        ),
        "confidence": min(0.72, max(0.64, float(dominance.get("confidence", 0.64) or 0.64))),
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "trust_class": "same_family_merge_review",
        "merge_shape": "same_source_family",
        "source_root": str(dominance.get("source_root", "") or ""),
        "source_root_kind": str(dominance.get("source_root_kind", "") or ""),
        "candidate_count": int(dominance.get("candidate_count", 0) or 0),
        "branch_shape_counts": _coerce_counter_dict(dominance.get("branch_shape_counts")),
        "first_layout_access_guarded": bool(dominance.get("first_layout_access_guarded")),
    }


def _field_call_result_parameter_dominance_comment(
    layout: _LayoutEvidence,
    provenance: dict[str, Any],
) -> dict[str, Any] | None:
    if provenance.get("merge_shape") != "call_result_parameter_branch":
        return None
    guard_state = "present" if provenance.get("first_layout_access_guarded") else "missing"
    parameter_roots = ", ".join(str(item) for item in provenance.get("parameter_roots", []) or [] if str(item))
    if not parameter_roots:
        parameter_roots = "unknown"
    linked_count = int(provenance.get("linked_call_result_parameter_root_count", 0) or 0)
    trust_class = "call_result_parameter_review"
    return {
        "kind": "inferred_offset_call_result_parameter_dominance",
        "text": (
            "Call-result parameter dominance for %s: linked call-result initializers %d, "
            "parameter roots %s, guard dominance %s, trust class %s. "
            "Review-only until parameter/call-result path dominance is validated."
            % (
                layout.base,
                linked_count,
                parameter_roots,
                guard_state,
                trust_class,
            )
        ),
        "confidence": min(0.72, max(0.62, float(provenance.get("confidence", 0.62) or 0.62))),
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "trust_class": trust_class,
        "merge_shape": "call_result_parameter_branch",
        "linked_call_result_parameter_root_count": linked_count,
        "parameter_roots": list(provenance.get("parameter_roots", []) or []),
        "first_layout_access_guarded": bool(provenance.get("first_layout_access_guarded")),
        "provenance_class": str(provenance.get("provenance_class", "") or ""),
    }


def _field_post_access_mutation_blocker_comment(
    layout: _LayoutEvidence,
    blocker: dict[str, Any],
    stability: dict[str, Any],
) -> dict[str, Any] | None:
    blockers = [
        str(item)
        for item in blocker.get("blockers", []) or []
        if str(item)
    ]
    mutation_reasons = [
        item
        for item in blockers
        if item in {
            "base is reassigned after layout access",
            "base is incremented or decremented",
            "base uses compound assignment",
            "base address is taken",
            "base is also indexed like an array",
        }
    ]
    risky_count = int(stability.get("risky_post_access_assignment_count", 0) or 0)
    if not mutation_reasons and risky_count <= 0:
        return None
    post_count = int(stability.get("post_access_assignment_count", 0) or 0)
    reload_count = int(stability.get("stable_post_access_reload_count", 0) or 0)
    reason_text = "; ".join(mutation_reasons[:6]) if mutation_reasons else "post-access assignment risk"
    trust_class = "reassignment_blocked"
    if any(reason in mutation_reasons for reason in (
        "base is incremented or decremented",
        "base uses compound assignment",
        "base address is taken",
        "base is also indexed like an array",
    )):
        trust_class = "mutation_blocked"
    return {
        "kind": "inferred_offset_post_access_mutation_blocker",
        "text": (
            "Post-access mutation blocker for %s: post-access assignments %d, risky %d, "
            "stable reloads %d, reasons %s, trust class %s. "
            "Canonical rewrite remains blocked until later layout accesses are proven to use the same base object."
            % (
                layout.base,
                post_count,
                risky_count,
                reload_count,
                reason_text,
                trust_class,
            )
        ),
        "confidence": min(0.76, 0.62 + min(post_count + risky_count, 6) * 0.02),
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "trust_class": trust_class,
        "post_access_assignment_count": post_count,
        "risky_post_access_assignment_count": risky_count,
        "stable_post_access_reload_count": reload_count,
        "reasons": mutation_reasons,
    }


def _temp_base_provenance_record(
    text: str,
    layout: _LayoutEvidence,
    blocker: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base_kind = _layout_base_kind(layout.base)
    if base_kind not in {"temp", "generic", "argument", "bugcheck"}:
        return {}
    blockers = [
        str(item)
        for item in (blocker or {}).get("blockers", []) or []
        if str(item)
    ]
    if blocker is None:
        blockers = _field_rewrite_blockers(text, layout)
    trace = _base_assignment_trace(text, layout.base)
    first_access = _first_layout_access_start(text, layout.base)
    identity = _stable_base_source_identity(text, layout.base)
    trusted_identity = _trusted_stable_base_source_identity(text, layout.base)
    if not identity and base_kind == "generic":
        identity = _trusted_generic_parameter_layout_identity(text, layout) or {}
        trusted_identity = identity if identity else {}
    if not identity and base_kind == "argument":
        identity = _trusted_decompiler_parameter_layout_identity(text, layout) or {}
        trusted_identity = identity if identity else {}
    source = str(identity.get("source", "") or trace.get("stable_source", "") or "")
    source_kind = str(identity.get("source_kind", "") or trace.get("stable_source_kind", "") or "")
    if source and not source_kind:
        source_kind = _layout_source_kind(source)
    source_provenance = str(identity.get("source_provenance", "") or "unknown_source_alias")
    source_rhs_kind = str(identity.get("source_rhs_kind", "") or trace.get("stable_source_rhs_kind", "") or "")
    merge_shape = _temp_base_merge_shape_from_blockers(text, layout, blockers, trace)
    guard = _truthiness_guard_dominating_offset(text, layout.base, first_access)
    pointer_mutation = _base_is_incremented(text, layout.base) or _base_uses_compound_assignment(text, layout.base)
    address_taken = _base_address_taken(text, layout.base)
    array_indexed = _base_has_array_index_use(text, layout.base)
    call_mutation_risk = _base_call_mutation_risk(text, layout.base)
    origin = _temp_base_source_origin(text, layout.base, base_kind, source, source_kind, source_provenance)
    block_reasons = _temp_provenance_block_reasons(
        blockers,
        origin,
        source,
        source_kind,
        source_provenance,
        merge_shape,
        pointer_mutation,
        address_taken,
        array_indexed,
        call_mutation_risk,
    )
    trust_class = _temp_provenance_trust_class(
        base_kind,
        bool(trusted_identity),
        blockers,
        block_reasons,
        origin,
        merge_shape,
    )
    promotion_eligible = (
        trust_class in {"trusted_stable_temp", "trusted_stable_source"}
        and not blockers
        and bool(_field_rewrite_threshold_policy(layout))
    )
    return {
        "base": layout.base,
        "base_kind": base_kind,
        "trust_class": trust_class,
        "source": source,
        "source_kind": source_kind or "unknown",
        "source_provenance": source_provenance,
        "source_rhs_kind": source_rhs_kind or "unknown",
        "source_origin": origin,
        "first_layout_access": first_access,
        "first_layout_access_line": _line_number_at(text, first_access),
        "pre_access_assignment_count": int(trace.get("pre_access_assignment_count", 0) or 0),
        "distinct_pre_access_rhs_count": int(trace.get("distinct_pre_access_rhs_count", 0) or 0),
        "distinct_pre_access_rhs": list(trace.get("distinct_pre_access_rhs", []) or []),
        "post_access_assignment_count": int(trace.get("post_access_assignment_count", 0) or 0),
        "risky_post_access_assignment_count": int(trace.get("risky_post_access_assignment_count", 0) or 0),
        "stable_post_access_reload_count": int(trace.get("stable_post_access_reload_count", 0) or 0),
        "pointer_mutation": bool(pointer_mutation),
        "address_taken": bool(address_taken),
        "array_indexed": bool(array_indexed),
        "call_mutation_risk": bool(call_mutation_risk),
        "branch_merge_shape": merge_shape,
        "guard_dominance": "present" if guard else "missing",
        "guard_condition": str(guard.get("condition", "") if guard else ""),
        "same_source_family": merge_shape == "same_source_family",
        "blockers": blockers,
        "block_reasons": block_reasons,
        "promotion_eligible": promotion_eligible,
        "offset_count": len(layout.offsets),
        "access_count": layout.access_count,
    }


def _temp_base_merge_shape_from_blockers(
    text: str,
    layout: _LayoutEvidence,
    blockers: list[str],
    trace: dict[str, Any],
) -> str:
    if "base has multiple initializers before layout access" not in blockers:
        return "none"
    rhs_values = _trace_rhs_samples(trace.get("distinct_pre_access_rhs", []))
    if len(rhs_values) < 2:
        return "branch_merge"
    families = Counter(_base_merge_source_family(text, item) for item in rhs_values)
    kinds = Counter(_base_merge_source_candidate_kind(text, item) for item in rhs_values)
    return _base_merge_shape(families, kinds)


def _temp_base_source_origin(
    text: str,
    base: str,
    base_kind: str,
    source: str,
    source_kind: str,
    source_provenance: str,
) -> str:
    if _is_mmio_like_base(base) or _is_mmio_like_base(source):
        return "global_mmio_register"
    if base_kind == "bugcheck" or source_kind == "bugcheck":
        return "bugcheck_debug_parameter"
    if source_provenance in {"parameter_direct_alias", "temporary_parameter_direct_alias", "direct_argument_alias"}:
        return "function_parameter"
    if source_provenance in {"parameter_indirect_pointer_alias"}:
        return "parameter_deref"
    if source_provenance in {"parameter_field_pointer_alias"}:
        return "field_load_from_trusted_base"
    if source_provenance in {"parameter_back_container_alias", "parameter_subobject_pointer_alias"}:
        return "parameter_subobject"
    if source_provenance in {"parameter_indexed_pointer_alias"}:
        return "parameter_indexed"
    if source_provenance in {"allocation_subobject_pointer_alias"}:
        return "allocation_call_result"
    if source_provenance in {"temporary_call_result_alias"}:
        return "call_result_temporary"
    if source_provenance in {"local_out_parameter_alias"}:
        return "call_result_parameter"
    if source_provenance in {"direct_call_result_alias", "named_call_result_alias", "named_branch_call_result_alias"}:
        call_name = _parse_any_direct_call_result_name(source)
        if _is_allocation_like_call_result_name(call_name):
            return "allocation_call_result"
        if call_name.startswith("sub_") or call_name.startswith("guard_dispatch_"):
            return "opaque_call_result"
        return "call_result"
    if source_kind == "temporary":
        return "saved_alias_reload"
    if source_kind in {"argument", "parameter"}:
        return "function_parameter"
    if source_kind == "named":
        return "stack_local_aggregate"
    if source_kind == "call_result":
        call_name = _parse_any_direct_call_result_name(source)
        if _is_allocation_like_call_result_name(call_name):
            return "allocation_call_result"
        if call_name.startswith("sub_") or call_name.startswith("guard_dispatch_"):
            return "opaque_call_result"
        return "call_result"
    if source_kind == "generic":
        return "domain_identity"
    return "unknown"


def _temp_provenance_block_reasons(
    blockers: list[str],
    origin: str,
    source: str,
    source_kind: str,
    source_provenance: str,
    merge_shape: str,
    pointer_mutation: bool,
    address_taken: bool,
    array_indexed: bool,
    call_mutation_risk: bool,
) -> list[str]:
    reasons: list[str] = []
    if "base has multiple initializers before layout access" in blockers:
        reasons.append("branch_merge")
    if "base is reassigned after layout access" in blockers:
        reasons.append("post_access_reassignment")
    if pointer_mutation or "base uses compound assignment" in blockers or "base is incremented or decremented" in blockers:
        reasons.append("pointer_mutation")
    if address_taken or "base address is taken" in blockers:
        reasons.append("address_taken")
    if array_indexed or "base is also indexed like an array" in blockers:
        reasons.append("array_indexed")
    if call_mutation_risk:
        reasons.append("call_mutation_risk")
    if "rewrite offset threshold requires at least 8 offsets" in blockers:
        reasons.append("offset_threshold_gap")
    if "rewrite access threshold requires at least 12 accesses" in blockers:
        reasons.append("access_threshold_gap")
    if merge_shape in {"call_result_parameter_branch", "call_result_temporary_branch", "same_source_family"}:
        reasons.append(merge_shape)
    if origin in {"opaque_call_result", "global_mmio_register"}:
        reasons.append(origin)
    if not source or source_kind in {"", "expression", "scalar"} or source_provenance in {
        "unknown_source_alias",
        "missing_alias_assignment",
        "temporary_source_alias",
        "generic_source_alias",
    }:
        reasons.append("weak_or_unknown_source")
    return list(dict.fromkeys(reasons))


def _temp_provenance_trust_class(
    base_kind: str,
    has_trusted_identity: bool,
    blockers: list[str],
    block_reasons: list[str],
    origin: str,
    merge_shape: str,
) -> str:
    if any(item in block_reasons for item in ("pointer_mutation", "address_taken", "array_indexed", "call_mutation_risk")):
        return "mutation_blocked"
    if "post_access_reassignment" in block_reasons:
        return "reassignment_blocked"
    if merge_shape == "same_source_family":
        return "same_family_merge_review"
    if merge_shape == "call_result_parameter_branch":
        return "call_result_parameter_review"
    if merge_shape == "call_result_temporary_branch":
        return "call_result_temporary_review"
    if "branch_merge" in block_reasons:
        return "branch_merge_blocked"
    if origin == "opaque_call_result":
        return "opaque_source_blocked"
    if origin == "global_mmio_register":
        return "opaque_source_blocked"
    if "weak_or_unknown_source" in block_reasons:
        return "weak_or_unknown_source_blocked"
    if has_trusted_identity and not blockers:
        if base_kind == "temp":
            return "trusted_stable_temp"
        return "trusted_stable_source"
    if has_trusted_identity:
        return "stable_review_only"
    if base_kind in {"generic", "argument", "bugcheck"}:
        return "stable_review_only"
    return "weak_or_unknown_source_blocked"


def _base_uses_compound_assignment(text: str, base: str) -> bool:
    return any(item.group("op") != "=" for item in _base_direct_assignments(text, base))


def _base_call_mutation_risk(text: str, base: str) -> bool:
    if not base:
        return False
    escaped = re.escape(base)
    return bool(
        re.search(
            r"\b[A-Za-z_][A-Za-z0-9_:~]*\s*\([^;\n]*&\s*%s\b[^;\n]*\)" % escaped,
            text or "",
        )
    )


def _line_number_at(text: str, offset: int) -> int:
    if offset < 0:
        return -1
    return str(text or "")[:offset].count("\n") + 1


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _field_rewrite_blocker_comment(
    text: str,
    layout: _LayoutEvidence,
    profile_context: dict[str, Any] | None = None,
    corrected_parameter_map: list[CorrectedParameterMapEntry] | None = None,
) -> dict[str, Any] | None:
    blockers = _field_rewrite_blockers(
        text,
        layout,
        profile_context=profile_context,
        corrected_parameter_map=corrected_parameter_map,
    )
    if not blockers:
        return None
    base_kind = _layout_base_kind(layout.base)
    confidence = min(
        _field_rewrite_blocker_confidence_cap_for_base_kind(base_kind),
        0.64 + min(len(blockers), 4) * 0.03 + min(layout.access_count, 12) * 0.005,
    )
    comment = {
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
    domain_identity = _domain_identity_for_layout(
        text,
        layout,
        _non_identity_layout_rewrite_blockers(text, layout),
        profile_context=profile_context,
        corrected_parameter_map=corrected_parameter_map,
    )
    if domain_identity:
        comment["domain_effective_mode"] = domain_identity.effective_mode
        comment["domain_profile_id"] = domain_identity.profile_id
        comment["domain_role"] = domain_identity.role
        comment["domain_structure"] = domain_identity.structure
        comment["domain_profile_blockers"] = _domain_identity_structured_blockers(domain_identity)
    return comment


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
    stable_reload_rhs_samples = _trace_rhs_samples(trace.get("stable_post_access_reload_rhs", []))
    risky_rhs_samples = _trace_rhs_samples(trace.get("risky_post_access_rhs", []))
    reload_text = ""
    if stable_reload_rhs_samples or risky_rhs_samples:
        reload_parts = []
        if stable_reload_rhs_samples:
            reload_parts.append("stable reload RHS %s" % "; ".join(stable_reload_rhs_samples))
        if risky_rhs_samples:
            reload_parts.append("risky RHS %s" % "; ".join(risky_rhs_samples))
        reload_text = "Post-access assignment samples: %s. " % "; ".join(reload_parts)
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
            "%sReview initializer dominance before enabling canonical rewrite."
            % (
                layout.base,
                int(trace.get("pre_access_assignment_count", 0) or 0),
                int(trace.get("distinct_pre_access_rhs_count", 0) or 0),
                rhs_text,
                int(trace.get("post_access_assignment_count", 0) or 0),
                int(trace.get("risky_post_access_assignment_count", 0) or 0),
                reload_text,
            )
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "pre_access_assignment_count": int(trace.get("pre_access_assignment_count", 0) or 0),
        "distinct_pre_access_rhs_count": int(trace.get("distinct_pre_access_rhs_count", 0) or 0),
        "distinct_pre_access_rhs": rhs_samples,
        "post_access_assignment_count": int(trace.get("post_access_assignment_count", 0) or 0),
        "stable_post_access_reload_count": int(trace.get("stable_post_access_reload_count", 0) or 0),
        "risky_post_access_assignment_count": int(trace.get("risky_post_access_assignment_count", 0) or 0),
        "stable_post_access_reload_rhs": stable_reload_rhs_samples,
        "risky_post_access_rhs": risky_rhs_samples,
    }


def _field_base_relocation_evidence_comment(
    text: str,
    layout: _LayoutEvidence,
    blocker: dict[str, Any],
    stability: dict[str, Any],
) -> dict[str, Any] | None:
    blockers = {
        str(item)
        for item in blocker.get("blockers", []) or []
        if str(item)
    }
    if "base is reassigned after layout access" not in blockers:
        return None
    identity = _trusted_stable_base_source_identity(text, layout.base)
    if not identity:
        return None
    stable_rhs = _trace_rhs_samples(stability.get("stable_post_access_reload_rhs", []))
    relocation_rhs = _trace_rhs_samples(stability.get("risky_post_access_rhs", []))
    if not stable_rhs and not relocation_rhs:
        return None
    source = str(identity.get("source", "") or "")
    source_provenance = str(identity.get("source_provenance", "") or "")
    source_offset = str(identity.get("source_offset", "") or "")
    source_text = source
    if source_offset:
        source_text = "%s+%s" % (source, source_offset)
    rhs_parts = []
    if stable_rhs:
        rhs_parts.append("Stable reload RHS %s" % "; ".join(stable_rhs))
    if relocation_rhs:
        rhs_parts.append("relocation-sensitive RHS %s" % "; ".join(relocation_rhs))
    rhs_text = "; ".join(rhs_parts)
    confidence = min(
        0.74,
        0.62
        + min(int(stability.get("stable_post_access_reload_count", 0) or 0), 8) * 0.006
        + min(int(stability.get("risky_post_access_assignment_count", 0) or 0), 4) * 0.012,
    )
    comment = {
        "kind": "inferred_offset_base_relocation_evidence",
        "text": (
            "Base relocation evidence for %s: trusted source %s (%s), %d post-access assignment(s), "
            "%d stable reload(s), %d relocation-sensitive assignment(s). %s. "
            "Treat as a moving logical layout; keep canonical rewrite blocked until segment or relocation validation is available."
            % (
                layout.base,
                source_text,
                source_provenance,
                int(stability.get("post_access_assignment_count", 0) or 0),
                int(stability.get("stable_post_access_reload_count", 0) or 0),
                int(stability.get("risky_post_access_assignment_count", 0) or 0),
                rhs_text,
            )
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "source": source,
        "source_kind": str(identity.get("source_kind", "") or ""),
        "source_provenance": source_provenance,
        "source_rhs_kind": str(identity.get("source_rhs_kind", "") or ""),
        "post_access_assignment_count": int(stability.get("post_access_assignment_count", 0) or 0),
        "stable_post_access_reload_count": int(stability.get("stable_post_access_reload_count", 0) or 0),
        "relocation_sensitive_assignment_count": int(stability.get("risky_post_access_assignment_count", 0) or 0),
        "stable_post_access_reload_rhs": stable_rhs,
        "relocation_sensitive_rhs": relocation_rhs,
    }
    if source_offset:
        comment["source_offset"] = source_offset
    if identity.get("source_alias"):
        comment["source_alias"] = identity["source_alias"]
    return comment


def _field_base_merge_evidence_comment(
    text: str,
    layout: _LayoutEvidence,
    blocker: dict[str, Any],
    stability: dict[str, Any],
) -> dict[str, Any] | None:
    blockers = {
        str(item)
        for item in blocker.get("blockers", []) or []
        if str(item)
    }
    if "base has multiple initializers before layout access" not in blockers:
        return None
    rhs_values = _trace_rhs_samples(stability.get("distinct_pre_access_rhs", []))
    if len(rhs_values) < 2:
        return None
    rhs_classes = Counter(_base_merge_rhs_class(item) for item in rhs_values)
    class_text = ", ".join(
        "%s=%d" % (key, int(value))
        for key, value in sorted(rhs_classes.items())
    )
    source_families = [_base_merge_source_family(text, item) for item in rhs_values]
    source_family_counts = Counter(source_families)
    source_family_text = ", ".join(
        "%s=%d" % (key, int(value))
        for key, value in sorted(source_family_counts.items())
    )
    source_family_disposition = "distinct_source_family_review"
    if len(source_family_counts) == 1:
        source_family_disposition = "same_source_family_review"
    source_candidate_kinds = [_base_merge_source_candidate_kind(text, item) for item in rhs_values]
    source_candidate_kind_counts = Counter(source_candidate_kinds)
    source_candidate_kind_text = ", ".join(
        "%s=%d" % (key, int(value))
        for key, value in sorted(source_candidate_kind_counts.items())
    )
    merge_shape = _base_merge_shape(source_family_counts, source_candidate_kind_counts)
    merge_risk = _base_merge_shape_risk(merge_shape)
    recommended_next = _base_merge_recommended_next(merge_shape)
    source_text = "; ".join(rhs_values)
    confidence = min(
        0.76,
        0.63
        + min(len(rhs_values), 4) * 0.018
        + min(int(stability.get("pre_access_assignment_count", 0) or 0), 6) * 0.006,
    )
    return {
        "kind": "inferred_offset_base_merge_evidence",
        "text": (
            "Base merge evidence for %s: %d initializer(s) before first layout access across "
            "%d source candidate(s): %s. Candidate classes %s. "
            "Source families %s; disposition %s. Candidate kinds %s. "
            "Merge shape %s (%s risk); next %s. "
            "Treat as a branch-merged layout base; keep canonical rewrite blocked until path-sensitive dominance is available."
            % (
                layout.base,
                int(stability.get("pre_access_assignment_count", 0) or 0),
                int(stability.get("distinct_pre_access_rhs_count", 0) or 0),
                source_text,
                class_text,
                source_family_text,
                source_family_disposition,
                source_candidate_kind_text,
                merge_shape,
                merge_risk,
                recommended_next,
            )
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "pre_access_assignment_count": int(stability.get("pre_access_assignment_count", 0) or 0),
        "distinct_pre_access_rhs_count": int(stability.get("distinct_pre_access_rhs_count", 0) or 0),
        "source_candidates": rhs_values,
        "candidate_classes": dict(sorted(rhs_classes.items())),
        "source_families": source_families,
        "source_family_counts": dict(sorted(source_family_counts.items())),
        "source_family_disposition": source_family_disposition,
        "source_candidate_kinds": source_candidate_kinds,
        "source_candidate_kind_counts": dict(sorted(source_candidate_kind_counts.items())),
        "merge_shape": merge_shape,
        "merge_risk": merge_risk,
        "recommended_next": recommended_next,
    }


def _base_merge_rhs_class(value: str) -> str:
    rhs = _normalize_assignment_rhs(value)
    if _is_identifier_expression(rhs):
        return "identifier"
    if re.match(r"[A-Za-z_][A-Za-z0-9_:]*\s*\(", rhs):
        return "call_result"
    if _parse_parameter_subobject_source(rhs) or _parse_parameter_indexed_source(rhs):
        return "pointer_expression"
    return "expression"


def _base_merge_source_family(text: str, value: str) -> str:
    rhs = _normalize_assignment_rhs(value)
    root = _base_merge_source_family_root(rhs)
    if root:
        root_kind = _layout_source_kind(root)
        if _base_is_function_parameter(text, root):
            root_kind = "parameter"
        return "%s:%s" % (root_kind, root)
    call_name = _parse_direct_call_result_name(rhs)
    if call_name:
        return "call_result:%s" % call_name
    return "%s:%s" % (_base_merge_rhs_class(rhs), rhs[:64])


def _base_merge_source_candidate_kind(text: str, value: str) -> str:
    rhs = _normalize_assignment_rhs(value)
    if not rhs:
        return "empty"
    if _is_null_initializer(rhs):
        return "null"
    if _layout_rhs_kind(rhs) == "call_result":
        call_name = _parse_any_direct_call_result_name(rhs)
        if _is_allocation_like_call_result_name(call_name):
            return "allocation_call_result"
        if call_name.startswith("guard_dispatch_"):
            return "indirect_call_result"
        if call_name.startswith("sub_"):
            return "opaque_call_result"
        return "call_result"
    root = _base_merge_source_family_root(rhs)
    if root:
        root_kind = _layout_source_kind(root)
        if _base_is_function_parameter(text, root) and root_kind != "bugcheck":
            root_kind = "parameter"
        return "%s_root" % root_kind
    return _base_merge_rhs_class(rhs)


def _base_merge_shape(
    source_family_counts: Counter[str],
    source_candidate_kind_counts: Counter[str],
) -> str:
    kinds = set(source_candidate_kind_counts)
    non_null_kinds = kinds - {"null"}
    if len(source_family_counts) == 1:
        return "same_source_family"
    if kinds and non_null_kinds and non_null_kinds <= {"allocation_call_result"}:
        if "null" in kinds:
            return "allocation_null_branch"
        return "allocation_call_result_branch"
    call_kinds = {"allocation_call_result", "call_result", "indirect_call_result", "opaque_call_result"}
    if non_null_kinds and non_null_kinds <= call_kinds:
        return "call_result_branch"
    if kinds & call_kinds:
        if "parameter_root" in kinds:
            return "call_result_parameter_branch"
        if "temporary_root" in kinds:
            return "call_result_temporary_branch"
        if "named_root" in kinds:
            return "call_result_named_branch"
        return "call_result_mixed_branch"
    if "bugcheck_root" in kinds:
        return "bugcheck_parameter_branch"
    if non_null_kinds and non_null_kinds <= {"temporary_root"}:
        return "temporary_branch"
    if non_null_kinds and non_null_kinds <= {"parameter_root"}:
        return "parameter_branch"
    return "mixed_source_family"


def _base_merge_shape_risk(merge_shape: str) -> str:
    if merge_shape in {"same_source_family", "allocation_null_branch"}:
        return "medium"
    if merge_shape in {"allocation_call_result_branch", "call_result_branch"}:
        return "medium_high"
    return "high"


def _base_merge_recommended_next(merge_shape: str) -> str:
    if merge_shape == "same_source_family":
        return "review same-source-family branch dominance"
    if merge_shape == "allocation_null_branch":
        return "review allocation/null guard dominance"
    if merge_shape == "allocation_call_result_branch":
        return "review allocation result equivalence"
    if merge_shape == "call_result_branch":
        return "review call-result object equivalence"
    if merge_shape == "call_result_parameter_branch":
        return "review parameter/call-result path dominance"
    if merge_shape == "call_result_temporary_branch":
        return "trace temporary/call-result dominance"
    if merge_shape == "bugcheck_parameter_branch":
        return "resolve bugcheck parameter domain identity"
    return "review path-sensitive source dominance"


def _field_allocation_null_merge_dominance_comment(
    text: str,
    layout: _LayoutEvidence,
    merge: dict[str, Any],
) -> dict[str, Any] | None:
    if merge.get("merge_shape") != "allocation_null_branch":
        return None
    kind_counts = _coerce_counter_dict(merge.get("source_candidate_kind_counts"))
    allocation_count = int(kind_counts.get("allocation_call_result", 0) or 0)
    null_count = int(kind_counts.get("null", 0) or 0)
    if allocation_count <= 0 or null_count <= 0:
        return None
    first_access = _first_layout_access_start(text, layout.base)
    guard = _truthiness_guard_dominating_offset(text, layout.base, first_access)
    guarded_text = "is"
    guard_condition_text = ""
    confidence = 0.67
    if not guard:
        guarded_text = "is not"
        confidence = 0.63
    else:
        guard_condition_text = " Guard condition %s." % guard["condition"]
    return {
        "kind": "inferred_offset_allocation_null_merge_dominance",
        "text": (
            "Allocation/null merge dominance for %s: %d allocation initializer(s), "
            "%d null initializer(s), first layout access %s dominated by a base truthiness guard.%s "
            "Keep canonical rewrite blocked until allocation object equivalence and guard dominance are validated."
            % (
                layout.base,
                allocation_count,
                null_count,
                guarded_text,
                guard_condition_text,
            )
        ),
        "confidence": confidence,
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "allocation_initializer_count": allocation_count,
        "null_initializer_count": null_count,
        "first_layout_access_guarded": bool(guard),
        "guard_condition": str(guard.get("condition", "") if guard else ""),
        "guard_start": int(guard.get("start", -1) if guard else -1),
        "guard_end": int(guard.get("end", -1) if guard else -1),
        "merge_shape": "allocation_null_branch",
    }


def _field_same_source_family_merge_dominance_comment(
    text: str,
    layout: _LayoutEvidence,
    merge: dict[str, Any],
) -> dict[str, Any] | None:
    if merge.get("merge_shape") != "same_source_family":
        return None
    candidates = list(merge.get("source_candidates", []) or [])
    details = [
        item
        for item in (
            _same_source_family_candidate_detail(text, candidate)
            for candidate in candidates
        )
        if item
    ]
    if len(details) < 2 or len(details) != len(candidates):
        return None
    root_counts = Counter(str(item.get("source_root", "") or "") for item in details)
    if len(root_counts) != 1:
        return None
    shared_root = next(iter(root_counts))
    if not shared_root:
        return None
    root_kind_counts = Counter(str(item.get("source_root_kind", "") or "") for item in details)
    branch_shape_counts = Counter(str(item.get("branch_shape", "") or "") for item in details)
    source_offset_values = [
        str(item.get("source_offset", "") or "")
        for item in details
        if str(item.get("source_offset", "") or "")
    ]
    source_offsets = list(dict.fromkeys(source_offset_values))
    first_access = _first_layout_access_start(text, layout.base)
    guard = _truthiness_guard_dominating_offset(text, layout.base, first_access)
    dominance_class = _same_source_family_dominance_class(
        root_kind_counts,
        branch_shape_counts,
    )
    branch_shape_text = ", ".join(
        "%s=%d" % (key, int(value))
        for key, value in sorted(branch_shape_counts.items())
    )
    source_offset_text = ", ".join(source_offsets) if source_offsets else "none"
    candidate_text = "; ".join(
        "%s %s" % (
            _comment_safe_snippet(str(item.get("source", "") or "")),
            _same_source_family_candidate_suffix(item),
        )
        for item in details[:4]
    )
    guarded_text = "is"
    guard_condition_text = ""
    confidence = 0.65
    if not guard:
        guarded_text = "is not"
        confidence = 0.63
    else:
        guard_condition_text = " Guard condition %s." % guard["condition"]
        confidence = 0.67
    return {
        "kind": "inferred_offset_same_source_family_merge_dominance",
        "text": (
            "Same-source-family merge dominance for %s: %d initializer candidate(s) share "
            "%s root %s. Branch shapes %s; source offsets %s; first layout access %s "
            "dominated by a base truthiness guard.%s Candidate sources %s. "
            "Dominance class %s. Keep canonical rewrite blocked until path-specific "
            "initializer dominance is validated."
            % (
                layout.base,
                len(details),
                str(details[0].get("source_root_kind", "") or "unknown"),
                shared_root,
                branch_shape_text,
                source_offset_text,
                guarded_text,
                guard_condition_text,
                candidate_text,
                dominance_class,
            )
        ),
        "confidence": confidence,
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "merge_shape": "same_source_family",
        "source_root": shared_root,
        "source_root_kind": str(details[0].get("source_root_kind", "") or ""),
        "source_root_kind_counts": dict(sorted(root_kind_counts.items())),
        "candidate_count": len(details),
        "branch_shape_counts": dict(sorted(branch_shape_counts.items())),
        "source_offsets": source_offsets,
        "source_candidates": details,
        "first_layout_access_guarded": bool(guard),
        "guard_condition": str(guard.get("condition", "") if guard else ""),
        "guard_start": int(guard.get("start", -1) if guard else -1),
        "guard_end": int(guard.get("end", -1) if guard else -1),
        "dominance_class": dominance_class,
    }


def _same_source_family_candidate_detail(text: str, value: Any) -> dict[str, Any]:
    source = _normalize_assignment_rhs(str(value))
    root = _base_merge_source_family_root(source)
    if not source or not root:
        return {}
    root_kind = _layout_source_kind(root)
    if _base_is_function_parameter(text, root):
        root_kind = "parameter"
    detail: dict[str, Any] = {
        "source": source,
        "source_root": root,
        "source_root_kind": root_kind,
        "source_rhs_kind": _layout_rhs_kind(source),
        "candidate_kind": _base_merge_source_candidate_kind(text, source),
        "branch_shape": "expression",
    }
    if _is_identifier_expression(source) and source == root:
        detail["branch_shape"] = "direct_root"
        detail["source_offset"] = "0x0"
        return detail
    field_pointer = _parse_field_pointer_source(source)
    if field_pointer and str(field_pointer.get("parent", "") or "") == root:
        detail["branch_shape"] = "field_pointer"
        detail["source_offset"] = "0x%X" % int(field_pointer["offset"])
        detail["source_type"] = str(field_pointer.get("type", "") or "")
        return detail
    indexed = _parse_parameter_indexed_source(source)
    if indexed and str(indexed.get("parent", "") or "") == root:
        detail["branch_shape"] = "indexed_pointer"
        detail["source_index"] = int(indexed["index"])
        return detail
    back_container = _parse_parameter_back_container_source(source)
    if back_container and str(back_container.get("parent", "") or "") == root:
        detail["branch_shape"] = "back_container_pointer_arithmetic"
        detail["source_offset"] = "-0x%X" % int(back_container["offset"])
        detail["source_container_offset"] = "0x%X" % int(back_container["offset"])
        return detail
    subobject = _parse_parameter_subobject_source(source)
    if subobject and str(subobject.get("parent", "") or "") == root:
        detail["branch_shape"] = "pointer_arithmetic"
        detail["source_offset"] = "0x%X" % int(subobject["offset"])
        return detail
    indirect = _parse_parameter_indirect_pointer_source(source)
    if indirect and str(indirect.get("parent", "") or "") == root:
        detail["branch_shape"] = "pointer_deref"
        if indirect.get("type"):
            detail["source_type"] = str(indirect["type"])
        return detail
    detail["branch_shape"] = detail["source_rhs_kind"]
    return detail


def _same_source_family_candidate_suffix(item: dict[str, Any]) -> str:
    branch_shape = str(item.get("branch_shape", "") or "unknown")
    source_offset = str(item.get("source_offset", "") or "")
    if source_offset:
        return "[%s %s]" % (branch_shape, source_offset)
    if item.get("source_index") is not None:
        return "[%s index=%d]" % (branch_shape, int(item["source_index"]))
    return "[%s]" % branch_shape


def _same_source_family_dominance_class(
    root_kind_counts: Counter[str],
    branch_shape_counts: Counter[str],
) -> str:
    root_kind = "mixed"
    if len(root_kind_counts) == 1:
        root_kind = next(iter(root_kind_counts))
    shapes = set(branch_shape_counts)
    if shapes <= {"direct_root"}:
        return "%s_root_direct_branch" % root_kind
    if {"direct_root", "field_pointer"} <= shapes:
        return "%s_root_direct_field_branch" % root_kind
    if {"direct_root", "pointer_arithmetic"} <= shapes:
        return "%s_root_direct_subobject_branch" % root_kind
    if "back_container_pointer_arithmetic" in shapes:
        return "%s_root_back_container_branch" % root_kind
    if "indexed_pointer" in shapes:
        return "%s_root_indexed_branch" % root_kind
    if "pointer_deref" in shapes:
        return "%s_root_pointer_deref_branch" % root_kind
    return "%s_root_same_family_branch" % root_kind


def _field_call_result_merge_equivalence_comment(
    text: str,
    layout: _LayoutEvidence,
    merge: dict[str, Any],
) -> dict[str, Any] | None:
    if merge.get("merge_shape") != "call_result_branch":
        return None
    candidates = _call_result_merge_candidates(text, merge.get("source_candidates"))
    if len(candidates) < 2:
        return None
    call_name_counts = Counter(str(item["call_name"]) for item in candidates if item.get("call_name"))
    kind_counts = Counter(str(item["candidate_kind"]) for item in candidates if item.get("candidate_kind"))
    direct_names = [
        str(item["call_name"])
        for item in candidates
        if item.get("candidate_kind") == "call_result"
    ]
    equivalence_class = _call_result_merge_equivalence_class(kind_counts, direct_names)
    call_name_text = ", ".join(
        "%s=%d" % (key, int(value))
        for key, value in sorted(call_name_counts.items())
    )
    confidence = 0.66
    if equivalence_class == "single_direct_call_family":
        confidence = 0.70
    elif equivalence_class == "direct_call_with_indirect_fallback":
        confidence = 0.64
    return {
        "kind": "inferred_offset_call_result_merge_equivalence",
        "text": (
            "Call-result merge equivalence for %s: %d call-result initializer(s), "
            "%d direct call(s), %d indirect dispatch call(s), %d opaque call(s). "
            "Call families %s; equivalence class %s. "
            "Keep canonical rewrite blocked until call-result object equivalence is validated."
            % (
                layout.base,
                len(candidates),
                int(kind_counts.get("call_result", 0) or 0),
                int(kind_counts.get("indirect_call_result", 0) or 0),
                int(kind_counts.get("opaque_call_result", 0) or 0),
                call_name_text,
                equivalence_class,
            )
        ),
        "confidence": confidence,
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "merge_shape": "call_result_branch",
        "call_result_initializer_count": len(candidates),
        "direct_call_result_count": int(kind_counts.get("call_result", 0) or 0),
        "indirect_call_result_count": int(kind_counts.get("indirect_call_result", 0) or 0),
        "opaque_call_result_count": int(kind_counts.get("opaque_call_result", 0) or 0),
        "allocation_call_result_count": int(kind_counts.get("allocation_call_result", 0) or 0),
        "call_name_counts": dict(sorted(call_name_counts.items())),
        "candidate_kind_counts": dict(sorted(kind_counts.items())),
        "call_result_candidates": candidates,
        "direct_call_names": list(dict.fromkeys(direct_names)),
        "same_direct_call_family": len(set(direct_names)) == 1 and bool(direct_names),
        "equivalence_class": equivalence_class,
    }


def _field_call_result_parameter_merge_provenance_comment(
    text: str,
    layout: _LayoutEvidence,
    merge: dict[str, Any],
) -> dict[str, Any] | None:
    if merge.get("merge_shape") != "call_result_parameter_branch":
        return None
    candidates = list(merge.get("source_candidates", []) or [])
    call_candidates = _call_result_merge_candidates(text, candidates)
    parameter_candidates = _parameter_root_merge_candidates(text, candidates, layout.base)
    if not call_candidates or not parameter_candidates:
        return None
    temporary_candidates = _temporary_root_merge_candidates(text, candidates, layout.base)
    temporary_details = [
        _temporary_root_provenance_before_layout_access(text, layout.base, item)
        for item in temporary_candidates
    ]
    call_name_counts = Counter(str(item["call_name"]) for item in call_candidates if item.get("call_name"))
    call_kind_counts = Counter(str(item["candidate_kind"]) for item in call_candidates if item.get("candidate_kind"))
    parameter_roots = list(
        dict.fromkeys(
            str(item.get("source_root", "") or "")
            for item in parameter_candidates
            if item.get("source_root")
        )
    )
    parameter_shape_counts = Counter(
        str(item.get("branch_shape", "") or "")
        for item in parameter_candidates
    )
    linked_call_count = _call_result_parameter_root_reference_count(call_candidates, parameter_roots)
    provenance_class = _call_result_parameter_provenance_class(
        call_kind_counts,
        parameter_shape_counts,
        bool(temporary_details),
        linked_call_count,
    )
    call_name_text = ", ".join(
        "%s=%d" % (key, int(value))
        for key, value in sorted(call_name_counts.items())
    )
    parameter_text = "; ".join(
        "%s %s" % (
            _comment_safe_snippet(str(item.get("source", "") or "")),
            _same_source_family_candidate_suffix(item),
        )
        for item in parameter_candidates[:4]
    )
    temporary_text = "none"
    if temporary_details:
        temporary_text = "; ".join(
            "%s stable=%s" % (
                _comment_safe_snippet(str(item.get("temporary_root", "") or "")),
                _comment_safe_snippet(str(item.get("stable_source", "") or "unknown")),
            )
            for item in temporary_details[:4]
        )
    first_access = _first_layout_access_start(text, layout.base)
    guard = _truthiness_guard_dominating_offset(text, layout.base, first_access)
    guarded_text = "is"
    guard_condition_text = ""
    confidence = 0.62
    if not guard:
        guarded_text = "is not"
    else:
        guard_condition_text = " Guard condition %s." % guard["condition"]
        confidence = 0.64
    if linked_call_count:
        confidence = max(confidence, 0.65)
    return {
        "kind": "inferred_offset_call_result_parameter_merge_provenance",
        "text": (
            "Call-result/parameter merge provenance for %s: %d call-result initializer(s), "
            "%d parameter-root candidate(s), %d temporary-root candidate(s). Call families %s. "
            "Parameter roots %s. Parameter candidates %s. Temporary roots %s. "
            "%d call-result initializer(s) mention parameter root(s). First layout access %s "
            "dominated by a base truthiness guard.%s Provenance class %s. "
            "Keep canonical rewrite blocked until parameter/call-result path dominance is validated."
            % (
                layout.base,
                len(call_candidates),
                len(parameter_candidates),
                len(temporary_details),
                call_name_text,
                ", ".join(parameter_roots),
                parameter_text,
                temporary_text,
                linked_call_count,
                guarded_text,
                guard_condition_text,
                provenance_class,
            )
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "merge_shape": "call_result_parameter_branch",
        "call_result_initializer_count": len(call_candidates),
        "parameter_root_candidate_count": len(parameter_candidates),
        "temporary_root_candidate_count": len(temporary_details),
        "call_name_counts": dict(sorted(call_name_counts.items())),
        "call_candidate_kind_counts": dict(sorted(call_kind_counts.items())),
        "call_result_candidates": call_candidates,
        "parameter_root_candidates": parameter_candidates,
        "parameter_roots": parameter_roots,
        "parameter_branch_shape_counts": dict(sorted(parameter_shape_counts.items())),
        "temporary_root_candidates": temporary_details,
        "temporary_roots": [
            str(item.get("temporary_root", "") or "")
            for item in temporary_details
            if item.get("temporary_root")
        ],
        "linked_call_result_parameter_root_count": linked_call_count,
        "first_layout_access_guarded": bool(guard),
        "guard_condition": str(guard.get("condition", "") if guard else ""),
        "guard_start": int(guard.get("start", -1) if guard else -1),
        "guard_end": int(guard.get("end", -1) if guard else -1),
        "provenance_class": provenance_class,
    }


def _parameter_root_merge_candidates(
    text: str,
    values: Any,
    target_base: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for value in values or []:
        detail = _same_source_family_candidate_detail(text, value)
        if not detail:
            continue
        if detail.get("source_root") == target_base:
            continue
        if detail.get("candidate_kind") != "parameter_root":
            continue
        key = (
            str(detail.get("source", "") or ""),
            str(detail.get("source_root", "") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        candidates.append(detail)
    return candidates


def _call_result_parameter_root_reference_count(
    call_candidates: list[dict[str, Any]],
    parameter_roots: list[str],
) -> int:
    roots = [str(item or "") for item in parameter_roots if str(item or "")]
    count = 0
    for candidate in call_candidates:
        source = str(candidate.get("source", "") or "")
        if any(re.search(r"\b%s\b" % re.escape(root), source) for root in roots):
            count += 1
    return count


def _call_result_parameter_provenance_class(
    call_kind_counts: Counter[str],
    parameter_shape_counts: Counter[str],
    has_temporary_roots: bool,
    linked_call_count: int,
) -> str:
    call_kinds = set(call_kind_counts)
    parameter_shapes = set(parameter_shape_counts)
    if "opaque_call_result" in call_kinds:
        base_class = "opaque_call_with_parameter_root"
    elif "allocation_call_result" in call_kinds:
        base_class = "allocation_call_with_parameter_root"
    elif "indirect_call_result" in call_kinds:
        base_class = "indirect_call_with_parameter_root"
    else:
        base_class = "call_result_with_parameter_root"
    if linked_call_count:
        base_class += "_linked_arguments"
    if "pointer_deref" in parameter_shapes:
        base_class += "_pointer_deref"
    elif "field_pointer" in parameter_shapes:
        base_class += "_field_pointer"
    elif "pointer_arithmetic" in parameter_shapes:
        base_class += "_pointer_arithmetic"
    if has_temporary_roots:
        base_class += "_and_temporary_roots"
    return base_class


def _field_bugcheck_parameter_merge_identity_comment(
    text: str,
    layout: _LayoutEvidence,
    merge: dict[str, Any],
) -> dict[str, Any] | None:
    if merge.get("merge_shape") != "bugcheck_parameter_branch":
        return None
    candidates = list(merge.get("source_candidates", []) or [])
    bugcheck_candidates = _bugcheck_root_merge_candidates(text, candidates, layout.base)
    temporary_candidates = _temporary_root_merge_candidates(text, candidates, layout.base)
    if not bugcheck_candidates:
        return None
    temporary_details = [
        _temporary_root_provenance_before_layout_access(text, layout.base, item)
        for item in temporary_candidates
    ]
    bugcheck_roots = list(
        dict.fromkeys(
            str(item.get("source_root", "") or "")
            for item in bugcheck_candidates
            if item.get("source_root")
        )
    )
    ordinal_counts = Counter(
        _bugcheck_parameter_ordinal(str(item.get("source_root", "") or "unknown"))
        for item in bugcheck_candidates
    )
    temporary_stable_kinds = Counter(
        str(item.get("stable_source_kind", "") or "unresolved")
        for item in temporary_details
    )
    identity_class = _bugcheck_parameter_merge_identity_class(
        bugcheck_roots,
        temporary_details,
    )
    bugcheck_text = "; ".join(
        "%s %s" % (
            _comment_safe_snippet(str(item.get("source", "") or "")),
            _same_source_family_candidate_suffix(item),
        )
        for item in bugcheck_candidates[:4]
    )
    temporary_text = "none"
    if temporary_details:
        temporary_text = "; ".join(
            "%s stable=%s" % (
                _comment_safe_snippet(str(item.get("temporary_root", "") or "")),
                _comment_safe_snippet(str(item.get("stable_source", "") or "unknown")),
            )
            for item in temporary_details[:4]
        )
    first_access = _first_layout_access_start(text, layout.base)
    guard = _truthiness_guard_dominating_offset(text, layout.base, first_access)
    guarded_text = "is"
    guard_condition_text = ""
    confidence = 0.61
    if not guard:
        guarded_text = "is not"
    else:
        guard_condition_text = " Guard condition %s." % guard["condition"]
        confidence = 0.63
    if len(bugcheck_roots) == 1 and not temporary_details:
        confidence = max(confidence, 0.64)
    return {
        "kind": "inferred_offset_bugcheck_parameter_merge_identity",
        "text": (
            "Bugcheck-parameter merge identity for %s: %d bugcheck-root candidate(s), "
            "%d temporary-root candidate(s). Bugcheck roots %s. Bugcheck candidates %s. "
            "Temporary roots %s. First layout access %s dominated by a base truthiness guard.%s "
            "Identity class %s. Treat BugCheckParameter names as unresolved decompiler identity; "
            "keep canonical rewrite blocked until domain-specific pointer meaning is validated."
            % (
                layout.base,
                len(bugcheck_candidates),
                len(temporary_details),
                ", ".join(bugcheck_roots),
                bugcheck_text,
                temporary_text,
                guarded_text,
                guard_condition_text,
                identity_class,
            )
        ),
        "confidence": round(confidence, 2),
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "merge_shape": "bugcheck_parameter_branch",
        "bugcheck_root_candidate_count": len(bugcheck_candidates),
        "temporary_root_candidate_count": len(temporary_details),
        "bugcheck_root_candidates": bugcheck_candidates,
        "bugcheck_roots": bugcheck_roots,
        "bugcheck_parameter_ordinals": dict(sorted(ordinal_counts.items())),
        "temporary_root_candidates": temporary_details,
        "temporary_roots": [
            str(item.get("temporary_root", "") or "")
            for item in temporary_details
            if item.get("temporary_root")
        ],
        "temporary_stable_source_kind_counts": dict(sorted(temporary_stable_kinds.items())),
        "unresolved_temporary_root_count": sum(
            1
            for item in temporary_details
            if not str(item.get("stable_source", "") or "")
        ),
        "first_layout_access_guarded": bool(guard),
        "guard_condition": str(guard.get("condition", "") if guard else ""),
        "guard_start": int(guard.get("start", -1) if guard else -1),
        "guard_end": int(guard.get("end", -1) if guard else -1),
        "identity_class": identity_class,
    }


def _bugcheck_root_merge_candidates(
    text: str,
    values: Any,
    target_base: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for value in values or []:
        detail = _same_source_family_candidate_detail(text, value)
        if not detail:
            continue
        if detail.get("source_root") == target_base:
            continue
        if detail.get("candidate_kind") != "bugcheck_root":
            continue
        key = (
            str(detail.get("source", "") or ""),
            str(detail.get("source_root", "") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        candidates.append(detail)
    return candidates


def _bugcheck_parameter_ordinal(name: str) -> str:
    match = re.fullmatch(r"(?i)BugCheckParameter(?P<ordinal>\d+)", str(name or ""))
    if not match:
        return "unknown"
    return str(int(match.group("ordinal")))


def _bugcheck_parameter_merge_identity_class(
    bugcheck_roots: list[str],
    temporary_details: list[dict[str, Any]],
) -> str:
    root_count = len([item for item in bugcheck_roots if item])
    unresolved_temporary_count = sum(
        1
        for item in temporary_details
        if not str(item.get("stable_source", "") or "")
    )
    if root_count > 1:
        base_class = "multiple_bugcheck_roots"
    else:
        base_class = "single_bugcheck_root"
    if temporary_details:
        if unresolved_temporary_count:
            base_class += "_with_unresolved_temporary"
        else:
            base_class += "_with_stable_temporary"
    return base_class


def _field_call_result_temporary_merge_provenance_comment(
    text: str,
    layout: _LayoutEvidence,
    merge: dict[str, Any],
) -> dict[str, Any] | None:
    if merge.get("merge_shape") != "call_result_temporary_branch":
        return None
    candidates = list(merge.get("source_candidates", []) or [])
    call_candidates = _call_result_merge_candidates(text, candidates)
    temporary_candidates = _temporary_root_merge_candidates(text, candidates, layout.base)
    if not call_candidates or not temporary_candidates:
        return None
    call_name_counts = Counter(str(item["call_name"]) for item in call_candidates if item.get("call_name"))
    call_kind_counts = Counter(str(item["candidate_kind"]) for item in call_candidates if item.get("candidate_kind"))
    temporary_details = [
        _temporary_root_provenance_before_layout_access(text, layout.base, item)
        for item in temporary_candidates
    ]
    provenance_class = _call_result_temporary_provenance_class(call_kind_counts, temporary_details)
    call_name_text = ", ".join(
        "%s=%d" % (key, int(value))
        for key, value in sorted(call_name_counts.items())
    )
    temporary_text = "; ".join(
        "%s stable=%s" % (
            _comment_safe_snippet(str(item.get("temporary_root", "") or "")),
            _comment_safe_snippet(str(item.get("stable_source", "") or "unknown")),
        )
        for item in temporary_details[:4]
    )
    confidence = 0.64
    if provenance_class == "allocation_call_with_parameter_temporary":
        confidence = 0.66
    elif provenance_class == "call_result_with_unresolved_temporary":
        confidence = 0.61
    return {
        "kind": "inferred_offset_call_result_temporary_merge_provenance",
        "text": (
            "Call-result/temporary merge provenance for %s: %d call-result initializer(s), "
            "%d temporary-root candidate(s). Call families %s. Temporary roots %s. "
            "Provenance class %s. Keep canonical rewrite blocked until temporary source dominance is validated."
            % (
                layout.base,
                len(call_candidates),
                len(temporary_details),
                call_name_text,
                temporary_text,
                provenance_class,
            )
        ),
        "confidence": confidence,
        "base": layout.base,
        "base_kind": _layout_base_kind(layout.base),
        "merge_shape": "call_result_temporary_branch",
        "call_result_initializer_count": len(call_candidates),
        "temporary_root_candidate_count": len(temporary_details),
        "call_name_counts": dict(sorted(call_name_counts.items())),
        "call_candidate_kind_counts": dict(sorted(call_kind_counts.items())),
        "call_result_candidates": call_candidates,
        "temporary_root_candidates": temporary_details,
        "temporary_roots": [
            str(item.get("temporary_root", "") or "")
            for item in temporary_details
            if item.get("temporary_root")
        ],
        "unresolved_temporary_root_count": sum(
            1
            for item in temporary_details
            if not str(item.get("stable_source", "") or "")
        ),
        "provenance_class": provenance_class,
    }


def _temporary_root_merge_candidates(
    text: str,
    values: Any,
    target_base: str,
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for value in values or []:
        source = _normalize_assignment_rhs(str(value))
        root = _base_merge_source_family_root(source)
        if not root or root == target_base:
            continue
        root_kind = _layout_source_kind(root)
        if _base_is_function_parameter(text, root):
            root_kind = "parameter"
        if root_kind != "temporary":
            continue
        key = (source, root)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "source": source,
                "temporary_root": root,
                "source_rhs_kind": _layout_rhs_kind(source),
                "candidate_kind": "temporary_root",
            }
        )
    return candidates


def _temporary_root_provenance_before_layout_access(
    text: str,
    target_base: str,
    candidate: dict[str, str],
) -> dict[str, Any]:
    temporary_root = str(candidate.get("temporary_root", "") or "")
    first_access = _first_layout_access_start(text, target_base)
    trace = _stable_assignment_source_before_offset(text, temporary_root, first_access)
    detail: dict[str, Any] = dict(candidate)
    detail.update(trace)
    trusted_identity = _trusted_stable_base_source_identity(text, temporary_root)
    if trusted_identity:
        detail["trusted_source"] = str(trusted_identity.get("source", "") or "")
        detail["trusted_source_kind"] = str(trusted_identity.get("source_kind", "") or "")
        detail["trusted_source_provenance"] = str(trusted_identity.get("source_provenance", "") or "")
    return detail


def _stable_assignment_source_before_offset(text: str, name: str, before: int) -> dict[str, Any]:
    if not name or before < 0:
        return {
            "pre_access_assignment_count": 0,
            "distinct_pre_access_rhs_count": 0,
            "distinct_pre_access_rhs": [],
            "stable_source": "",
            "stable_source_kind": "",
            "stable_source_rhs_kind": "",
            "immediate_source": "",
            "has_stable_source": False,
        }
    assignments = [
        item
        for item in _base_direct_assignments(text, name)
        if item.start() < before and item.group("op") == "="
    ]
    rhs_values = [
        _canonical_pre_access_initializer_rhs(text, item.group("rhs"), item.start(), {name})
        for item in assignments
    ]
    effective_rhs = _effective_pre_access_initializer_rhs(rhs_values)
    distinct_rhs = list(dict.fromkeys(item for item in effective_rhs if item))
    stable_source = ""
    if len(distinct_rhs) == 1:
        stable_source = distinct_rhs[0]
    elif distinct_rhs:
        stable_source = _same_call_result_family_pre_access_rhs(effective_rhs)
    if _is_null_initializer(stable_source):
        stable_source = ""
    immediate_source = ""
    if assignments:
        immediate_source = _normalize_assignment_rhs(assignments[-1].group("rhs"))
    stable_source_kind = _layout_source_kind(stable_source) if stable_source else ""
    if stable_source and _base_is_function_parameter(text, stable_source):
        stable_source_kind = "parameter"
    stable_source_rhs_kind = _layout_rhs_kind(stable_source) if stable_source else ""
    return {
        "pre_access_assignment_count": len(assignments),
        "distinct_pre_access_rhs_count": len(distinct_rhs),
        "distinct_pre_access_rhs": distinct_rhs[:_MAX_BASE_STABILITY_RHS_SAMPLES],
        "stable_source": stable_source,
        "stable_source_kind": stable_source_kind,
        "stable_source_rhs_kind": stable_source_rhs_kind,
        "immediate_source": immediate_source,
        "has_stable_source": bool(stable_source),
    }


def _call_result_temporary_provenance_class(
    call_kind_counts: Counter[str],
    temporary_details: list[dict[str, Any]],
) -> str:
    call_kinds = set(call_kind_counts)
    stable_kinds = {
        str(item.get("stable_source_kind", "") or "")
        for item in temporary_details
        if str(item.get("stable_source", "") or "")
    }
    unresolved_count = sum(
        1
        for item in temporary_details
        if not str(item.get("stable_source", "") or "")
    )
    if "opaque_call_result" in call_kinds:
        return "opaque_call_with_temporary"
    if "allocation_call_result" in call_kinds:
        if stable_kinds.intersection({"argument", "parameter", "named"}):
            return "allocation_call_with_parameter_temporary"
        if unresolved_count:
            return "allocation_call_with_unresolved_temporary"
        return "allocation_call_with_temporary"
    if stable_kinds.intersection({"argument", "parameter", "named"}):
        return "call_result_with_parameter_temporary"
    if unresolved_count:
        return "call_result_with_unresolved_temporary"
    return "call_result_with_temporary"


def _comment_safe_snippet(value: str) -> str:
    text = str(value or "").replace("/*", "/ *").replace("*/", "* /")

    def replace_offset_deref(match: re.Match[str]) -> str:
        type_text = _normalize_type_name(match.group("type"))
        base = match.group("base")
        op = match.group("op")
        offset_text = match.group("offset")
        try:
            offset = int(
                offset_text,
                16 if offset_text.lower().startswith("0x") else 10,
            )
        except ValueError:
            return match.group(0)
        if op == "-":
            offset = -offset
        if offset < 0:
            rendered_offset = "-0x%X" % abs(offset)
        else:
            rendered_offset = "0x%X" % offset
        return "deref(%s,%s@%s)" % (type_text, base, rendered_offset)

    return re.sub(
        r"\*\s*\(\s*(?P<type>[^()]+?)\s*\*\s*\)\s*"
        r"\(\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*"
        r"(?P<op>[+-])\s*"
        r"(?P<offset>0x[0-9A-Fa-f]+|\d+)"
        r"(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)",
        replace_offset_deref,
        text,
    )


def _call_result_merge_candidates(text: str, values: Any) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for value in values or []:
        rhs = _normalize_assignment_rhs(str(value))
        if _layout_rhs_kind(rhs) != "call_result":
            continue
        call_name = _parse_any_direct_call_result_name(rhs)
        if not call_name:
            continue
        candidates.append(
            {
                "source": rhs,
                "call_name": call_name,
                "candidate_kind": _base_merge_source_candidate_kind(text, rhs),
            }
        )
    return candidates


def _call_result_merge_equivalence_class(
    kind_counts: Counter[str],
    direct_names: list[str],
) -> str:
    kinds = set(kind_counts)
    if kinds == {"call_result"} and len(set(direct_names)) == 1:
        return "single_direct_call_family"
    if "indirect_call_result" in kinds and "call_result" in kinds:
        return "direct_call_with_indirect_fallback"
    if "opaque_call_result" in kinds and "call_result" in kinds:
        return "direct_call_with_opaque_fallback"
    if kinds == {"call_result"} and len(set(direct_names)) > 1:
        return "mixed_direct_call_families"
    if "allocation_call_result" in kinds:
        return "allocation_call_result_mixed"
    return "mixed_call_result_sources"


def _coerce_counter_dict(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, int] = {}
    for key, item in value.items():
        try:
            result[str(key)] = int(item)
        except (TypeError, ValueError):
            continue
    return result


def _base_merge_source_family_root(value: str) -> str:
    rhs = _normalize_assignment_rhs(value)
    if _is_identifier_expression(rhs):
        return rhs
    for parser in (
        _parse_parameter_indexed_source,
        _parse_parameter_back_container_source,
        _parse_parameter_subobject_source,
        _parse_field_pointer_source,
        _parse_parameter_indirect_pointer_source,
    ):
        match = parser(rhs)
        if match and match.get("parent"):
            return str(match["parent"])
    return ""


def _trace_rhs_samples(values: Any, limit: int = _MAX_BASE_STABILITY_RHS_SAMPLES) -> list[str]:
    samples = [
        str(item)
        for item in values or []
        if str(item)
    ]
    return list(dict.fromkeys(samples))[:limit]


def _domain_identity_rewrite_source(domain_identity: DomainIdentityMatch) -> tuple[str, str]:
    if str(domain_identity.match_reason or "").startswith("corrected parameter map"):
        return "corrected_parameter_map", "corrected_parameter_type"
    return "domain_identity", "parameter_profile"


def _field_rewrite_ready_comment(
    text: str,
    layout: _LayoutEvidence,
    profile_context: dict[str, Any] | None = None,
    corrected_parameter_map: list[CorrectedParameterMapEntry] | None = None,
) -> dict[str, Any] | None:
    base_kind = _layout_base_kind(layout.base)
    identity = _trusted_stable_base_source_identity(text, layout.base)
    if not identity:
        identity = _trusted_decompiler_parameter_layout_identity(text, layout)
    if not identity:
        identity = _trusted_generic_parameter_layout_identity(text, layout)
    if not identity:
        non_identity_blockers = _non_identity_layout_rewrite_blockers(text, layout)
        domain_identity = _domain_identity_for_layout(
            text,
            layout,
            non_identity_blockers,
            profile_context=profile_context,
            corrected_parameter_map=corrected_parameter_map,
        )
        if domain_identity and domain_identity.effective_mode == MODE_CANONICAL_REWRITE_ELIGIBLE:
            source_provenance, source_rhs_kind = _domain_identity_rewrite_source(domain_identity)
            identity = {
                "source": domain_identity.base,
                "source_kind": "domain",
                "source_provenance": source_provenance,
                "source_rhs_kind": source_rhs_kind,
                "domain_profile_id": domain_identity.profile_id,
                "domain_role": domain_identity.role,
                "domain_structure": domain_identity.structure,
            }
    threshold_policy = _field_rewrite_threshold_policy(layout, text=text)
    if not identity and threshold_policy == "allocation_alias_group_grace":
        identity = _allocation_alias_group_identity(text, layout)
    if base_kind != "named" and not identity:
        return None
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
        if identity.get("source_call"):
            comment["source_call"] = identity["source_call"]
        if identity.get("source_alias"):
            comment["source_alias"] = identity["source_alias"]
        if identity.get("source_offset"):
            comment["source_offset"] = identity["source_offset"]
        if identity.get("source_container_offset"):
            comment["source_container_offset"] = identity["source_container_offset"]
        if identity.get("source_index"):
            comment["source_index"] = identity["source_index"]
        if identity.get("source_type"):
            comment["source_type"] = identity["source_type"]
        if identity.get("source_threshold_policy"):
            comment["source_threshold_policy"] = identity["source_threshold_policy"]
        if identity.get("domain_profile_id"):
            comment["domain_profile_id"] = identity["domain_profile_id"]
            comment["domain_role"] = identity.get("domain_role", "")
            comment["domain_structure"] = identity.get("domain_structure", "")
    return comment


def _field_rewrite_preview_comment(
    text: str,
    layout: _LayoutEvidence,
    ready: dict[str, Any],
    domain_identity: DomainIdentityMatch | None = None,
) -> dict[str, Any] | None:
    fields = _preview_fields(layout, domain_identity)
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
    report_only_domain_partial_allowed = _report_only_domain_partial_rewrite_allowed(blocker)
    if report_only_domain_partial_allowed:
        identity_blockers.add("domain identity profile is report-only")
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
    if not identity and report_only_domain_partial_allowed:
        identity = _report_only_domain_partial_rewrite_identity(layout, blocker)
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
    threshold_policy = _partial_rewrite_threshold_policy(
        len(safe_offsets),
        safe_access_count,
        len(excluded_offsets),
    )
    if not threshold_policy:
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
        "threshold_policy": threshold_policy,
    }
    if source:
        comment["source"] = source
    for key in ("domain_profile_id", "domain_role", "domain_structure"):
        if identity.get(key):
            comment[key] = identity[key]
    return comment


def _report_only_domain_partial_rewrite_identity(
    layout: _LayoutEvidence,
    blocker: dict[str, Any],
) -> dict[str, str]:
    return {
        "source": layout.base,
        "source_kind": "domain",
        "source_provenance": "domain_identity_report_only",
        "source_rhs_kind": "profile_report_only",
        "domain_profile_id": str(blocker.get("domain_profile_id", "") or ""),
        "domain_role": str(blocker.get("domain_role", "") or ""),
        "domain_structure": str(blocker.get("domain_structure", "") or ""),
    }


def _report_only_domain_partial_rewrite_allowed(blocker: dict[str, Any]) -> bool:
    blockers = {
        str(item)
        for item in blocker.get("blockers", []) or []
        if str(item)
    }
    if "domain identity profile is report-only" not in blockers:
        return False
    domain_blockers = {
        str(item)
        for item in blocker.get("domain_profile_blockers", []) or []
        if str(item)
    }
    if not domain_blockers:
        return False
    allowed = {"profile_report_only", "overlay", "type_conflict"}
    return domain_blockers.issubset(allowed)


def _partial_rewrite_threshold_policy(
    safe_offset_count: int,
    safe_access_count: int,
    excluded_offset_count: int,
) -> str:
    if safe_offset_count >= 8 and safe_access_count >= 12:
        return "standard"
    if safe_offset_count >= 7 and safe_access_count >= 12 and excluded_offset_count <= 4:
        return "partial_offset_grace"
    return ""


def _offset_list_text(offsets: set[int]) -> str:
    return ", ".join("+0x%X" % offset for offset in sorted(offsets))


def _field_rewrite_blockers(
    text: str,
    layout: _LayoutEvidence,
    allow_generic_parameter_trust: bool = True,
    profile_context: dict[str, Any] | None = None,
    corrected_parameter_map: list[CorrectedParameterMapEntry] | None = None,
) -> list[str]:
    blockers: list[str] = []
    base_kind = _layout_base_kind(layout.base)
    non_identity_blockers = _non_identity_layout_rewrite_blockers(text, layout)
    domain_identity = _domain_identity_for_layout(
        text,
        layout,
        non_identity_blockers,
        profile_context=profile_context,
        corrected_parameter_map=corrected_parameter_map,
    )
    if domain_identity:
        if domain_identity.ambiguous:
            blockers.append("domain identity profile is ambiguous")
        elif domain_identity.effective_mode == MODE_REPORT_ONLY:
            blockers.append("domain identity profile is report-only")
        elif domain_identity.effective_mode == MODE_PREVIEW_REWRITE:
            blockers.append("domain identity profile is preview-only")
        elif domain_identity.effective_mode != MODE_CANONICAL_REWRITE_ELIGIBLE:
            blockers.append("domain identity profile mode is unsupported")
    elif base_kind == "temp":
        if (
            not _trusted_stable_base_source_identity(text, layout.base)
            and not _trusted_decompiler_parameter_layout_identity(text, layout)
        ):
            blockers.append("base is a decompiler temporary")
    elif base_kind == "generic":
        identity = _trusted_generic_parameter_layout_identity(text, layout)
        if not allow_generic_parameter_trust or not identity:
            blockers.append("base name is generic")
    elif base_kind == "argument":
        blockers.append("base name is unresolved argument identity")
    elif base_kind == "bugcheck":
        blockers.append("base name is unresolved bugcheck parameter identity")
    blockers.extend(non_identity_blockers)
    return list(dict.fromkeys(blockers))


def _non_identity_layout_rewrite_blockers(text: str, layout: _LayoutEvidence) -> list[str]:
    blockers: list[str] = []
    blockers.extend(_field_rewrite_threshold_blockers(layout, text=text))
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


def _trusted_decompiler_parameter_layout_identity(text: str, layout: _LayoutEvidence) -> dict[str, str] | None:
    return _trusted_decompiler_parameter_identity(
        text,
        layout,
        allow_offset_local_type_blockers=False,
    )


def _trusted_decompiler_parameter_identity(
    text: str,
    layout: _LayoutEvidence,
    allow_offset_local_type_blockers: bool = False,
) -> dict[str, str] | None:
    if not _is_decompiler_argument_base(layout.base):
        return None
    if not _base_is_function_parameter(text, layout.base):
        return None
    threshold_policy = _generic_parameter_trust_threshold_policy(layout)
    if not threshold_policy:
        return None
    blockers = _non_identity_layout_rewrite_blockers(text, layout)
    if blockers:
        if not allow_offset_local_type_blockers:
            return None
        if any(item not in _OFFSET_LOCAL_TYPE_BLOCKERS for item in blockers):
            return None
    return {
        "source": layout.base,
        "source_kind": "argument",
        "source_provenance": "decompiler_parameter_trust",
        "source_rhs_kind": "parameter",
        "source_threshold_policy": threshold_policy,
    }


def _trusted_generic_parameter_identity(
    text: str,
    layout: _LayoutEvidence,
    allow_offset_local_type_blockers: bool = False,
) -> dict[str, str] | None:
    if _layout_base_kind(layout.base) != "generic":
        return None
    threshold_policy = _generic_parameter_trust_threshold_policy(layout)
    if not threshold_policy:
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
        "source_threshold_policy": threshold_policy,
    }


def _generic_parameter_trust_threshold_policy(layout: _LayoutEvidence) -> str:
    if len(layout.offsets) >= 10 and layout.access_count >= 16:
        return "standard"
    if len(layout.offsets) >= 12 and layout.access_count >= 12:
        return "generic_parameter_offset_grace"
    if len(layout.offsets) >= 8 and layout.access_count >= 24:
        return "generic_parameter_access_grace"
    return ""


def _trusted_layout_rewrite_identity(text: str, layout: _LayoutEvidence) -> dict[str, str]:
    identity = _trusted_stable_base_source_identity(text, layout.base)
    if identity:
        return identity
    identity = _trusted_decompiler_parameter_layout_identity(text, layout)
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
    identity = _trusted_decompiler_parameter_identity(
        text,
        layout,
        allow_offset_local_type_blockers=True,
    )
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


def _preview_fields(
    layout: _LayoutEvidence,
    domain_identity: DomainIdentityMatch | None = None,
    text: str = "",
) -> list[dict[str, Any]]:
    fields = []
    observed_offsets = set(layout.offsets)
    if domain_identity and _domain_identity_direct_base_access_exists(text, domain_identity, layout.base):
        observed_offsets.add(0)
    for offset in sorted(observed_offsets):
        domain_field = domain_identity.field_for_offset(offset) if domain_identity else None
        if domain_field:
            field_name = domain_field.name
            field_type = domain_field.type_text
            field_confidence = domain_field.confidence
        else:
            field_name = "field_%X" % offset
            field_type = _preview_type_name(layout.offsets[offset])
            field_confidence = 0.0
        fields.append(
            {
                "offset": offset,
                "name": field_name,
                "type": field_type,
                "profile_confidence": field_confidence,
                "note": domain_field.note if domain_field else "",
            }
        )
    return fields


def _hot_field_cluster_fields(layout: _LayoutEvidence) -> list[dict[str, Any]]:
    fields = []
    for offset, access_count in sorted(
        layout.offset_access_counts.items(),
        key=lambda item: (-int(item[1]), int(item[0])),
    ):
        fields.append(
            {
                "offset": int(offset),
                "name": "field_%X" % int(offset),
                "type": _preview_type_name(layout.offsets.get(int(offset), set())),
                "access_count": int(access_count),
            }
        )
    return fields


def _has_hot_field_cluster_evidence(layout: _LayoutEvidence) -> bool:
    if _has_enough_layout_evidence(layout):
        return False
    offset_count = len(layout.offsets)
    if offset_count < _HOT_FIELD_CLUSTER_MIN_OFFSETS:
        return False
    if offset_count > _HOT_FIELD_CLUSTER_MAX_OFFSETS:
        return False
    if layout.access_count < _HOT_FIELD_CLUSTER_MIN_ACCESSES:
        return False
    return _hot_field_cluster_top_offset_access_count(layout) >= _HOT_FIELD_CLUSTER_MIN_TOP_OFFSET_ACCESSES


def _hot_field_cluster_top_offset_access_count(layout: _LayoutEvidence) -> int:
    if not layout.offset_access_counts:
        return 0
    return max(int(value) for value in layout.offset_access_counts.values())


def _layout_rewrite_access_count(text: str, layout: _LayoutEvidence) -> int:
    count = 0
    offsets = set(layout.offsets)
    for match in _OFFSET_DEREF_RE.finditer(text or ""):
        if match.group("base") != layout.base:
            continue
        offset = _parse_offset(match.group("offset"))
        if offset in offsets:
            count += 1
    for match in _OFFSET_INDEXED_DEREF_RE.finditer(text or ""):
        if match.group("base") != layout.base:
            continue
        offset = _indexed_deref_byte_offset(match)
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
    for match in _OFFSET_INDEXED_DEREF_RE.finditer(text or ""):
        if match.group("base") != layout.base:
            continue
        offset = _indexed_deref_byte_offset(match)
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


def _subfield_overlay_fields(
    layout: _LayoutEvidence,
    text: str = "",
    domain_identity: DomainIdentityMatch | None = None,
) -> list[dict[str, Any]]:
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
        domain_field = domain_identity.field_for_offset(offset) if domain_identity else None
        fields.append(
            {
                "offset": offset,
                "name": domain_field.name if domain_field else "field_%X" % offset,
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


def _unaligned_subfield_fields(
    layout: _LayoutEvidence,
    domain_identity: DomainIdentityMatch | None = None,
) -> list[dict[str, Any]]:
    fields = []
    for offset, type_names in sorted(layout.offsets.items()):
        for type_name in sorted(type_names):
            alignment = _natural_type_alignment(type_name)
            if not alignment or offset % alignment == 0:
                continue
            domain_field = domain_identity.field_for_offset(offset) if domain_identity else None
            fields.append(
                {
                    "offset": offset,
                    "name": domain_field.name if domain_field else "field_%X" % offset,
                    "type": type_name,
                    "alignment": alignment,
                }
            )
    return fields


def _unaligned_subfield_text(item: dict[str, Any]) -> str:
    return "+0x%X %s uses %s with %d-byte alignment" % (
        item["offset"],
        item["name"],
        item["type"],
        item["alignment"],
    )


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


def _field_rewrite_threshold_blockers(
    layout: _LayoutEvidence,
    text: str = "",
) -> list[str]:
    blockers: list[str] = []
    if _field_rewrite_threshold_policy(layout, text=text):
        return blockers
    if len(layout.offsets) < 8:
        blockers.append(_REWRITE_OFFSET_THRESHOLD_BLOCKER)
    if layout.access_count < 12:
        blockers.append(_REWRITE_ACCESS_THRESHOLD_BLOCKER)
    return blockers


def _field_rewrite_threshold_policy(
    layout: _LayoutEvidence,
    text: str = "",
) -> str:
    if len(layout.offsets) >= 8 and layout.access_count >= 12:
        return "standard"
    if _field_rewrite_named_threshold_grace(layout):
        return "named_threshold_grace"
    if _field_rewrite_named_dense_threshold_grace(layout):
        return "named_dense_threshold_grace"
    if text and _field_rewrite_allocation_alias_group_grace(text, layout):
        return "allocation_alias_group_grace"
    return ""


def _field_rewrite_named_threshold_grace(layout: _LayoutEvidence) -> bool:
    if _layout_base_kind(layout.base) != "named":
        return False
    if len(layout.offsets) >= 8 and layout.access_count >= 10:
        return True
    if len(layout.offsets) >= 6 and layout.access_count >= 12:
        return True
    return False


def _field_rewrite_named_dense_threshold_grace(layout: _LayoutEvidence) -> bool:
    if _layout_base_kind(layout.base) != "named":
        return False
    if len(layout.offsets) >= 8:
        return False
    if len(layout.offsets) >= 5 and 8 <= layout.access_count < 12:
        return True
    if len(layout.offsets) >= 4 and 10 <= layout.access_count < 12:
        return True
    return False


def _field_rewrite_allocation_alias_group_grace(text: str, layout: _LayoutEvidence) -> bool:
    stats = _allocation_alias_group_stats(text, layout)
    if not stats:
        return False
    return (
        int(stats.get("base_count", 0) or 0) >= 2
        and int(stats.get("offset_count", 0) or 0) >= 8
        and int(stats.get("access_count", 0) or 0) >= 10
    )


def _allocation_alias_group_identity(text: str, layout: _LayoutEvidence) -> dict[str, Any]:
    stats = _allocation_alias_group_stats(text, layout)
    if not stats:
        return {}
    root = str(stats.get("root", "") or "")
    if not root:
        return {}
    return {
        "source": root,
        "source_kind": "allocation",
        "source_provenance": "allocation_alias_group",
        "source_rhs_kind": "allocation_result_alias_group",
        "source_aliases": ",".join(str(item) for item in stats.get("bases", []) or [] if str(item)),
        "source_threshold_policy": "allocation_alias_group_grace",
    }


def _allocation_alias_group_stats(text: str, layout: _LayoutEvidence) -> dict[str, Any]:
    first_access = _first_layout_access_start(text or "", layout.base)
    if first_access < 0:
        return {}
    root = _allocation_source_root_before(text or "", layout.base, first_access, set())
    if not root:
        return {}
    layouts = _collect_layouts(text or "")
    group_bases = []
    group_offsets: set[int] = set()
    group_access_count = 0
    for base, candidate in sorted(layouts.items()):
        candidate_first_access = _first_layout_access_start(text or "", base)
        if candidate_first_access < 0:
            continue
        candidate_root = _allocation_source_root_before(
            text or "",
            base,
            candidate_first_access,
            set(),
        )
        if candidate_root != root:
            continue
        group_bases.append(base)
        group_offsets.update(int(offset) for offset in candidate.offsets)
        group_access_count += int(candidate.access_count)
    if len(group_bases) < 2:
        return {}
    return {
        "root": root,
        "bases": group_bases,
        "base_count": len(group_bases),
        "offset_count": len(group_offsets),
        "access_count": group_access_count,
    }


def _parse_offset(value: str) -> int | None:
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
    except ValueError:
        return None


def _indexed_deref_byte_offset(match: re.Match[str]) -> int | None:
    index = _parse_offset(match.group("index"))
    if index is None or index <= 0:
        return None
    type_name = _normalize_offset_access_type(
        match.group("type"),
        match.group("pointer_stars"),
    )
    if not type_name:
        return None
    element_size = _field_type_storage_size(type_name)
    if element_size <= 0:
        return None
    return index * element_size


def _normalize_type_name(type_name: str) -> str:
    text = " ".join(str(type_name or "").replace("const ", "").split())
    if not text:
        return ""
    if len(text) > 48:
        return ""
    return text


def _normalize_offset_access_type(type_name: str, pointer_stars: str) -> str:
    text = _normalize_type_name(type_name)
    if not text:
        return ""
    pointer_depth = len(str(pointer_stars or ""))
    if pointer_depth <= 1:
        return text
    pointer_text = "%s %s" % (text, "*" * (pointer_depth - 1))
    if len(pointer_text) > 48:
        return ""
    return pointer_text


def _is_scalar_like_base(name: str) -> bool:
    lower = str(name or "").lower()
    if lower in _SCALAR_BASE_WORDS:
        return True
    return any(lower.endswith(word) for word in _SCALAR_BASE_WORDS)


def _is_decompiler_temp_base(name: str) -> bool:
    return re.fullmatch(r"[av]\d+", str(name or "")) is not None


def _is_decompiler_argument_base(name: str) -> bool:
    return re.fullmatch(r"a\d+", str(name or "")) is not None


def _is_generic_named_base(name: str) -> bool:
    return str(name or "").lower() in _GENERIC_BASE_NAMES


def _is_generic_argument_base(name: str) -> bool:
    return re.fullmatch(r"argument\d+", str(name or "").lower()) is not None


def _is_bugcheck_parameter_base(name: str) -> bool:
    return re.fullmatch(r"bugcheckparameter\d+", str(name or "").lower()) is not None


def _layout_base_kind(name: str) -> str:
    if _is_decompiler_temp_base(name):
        return "temp"
    if _is_generic_argument_base(name):
        return "argument"
    if _is_bugcheck_parameter_base(name):
        return "bugcheck"
    if _is_generic_named_base(name):
        return "generic"
    return "named"


def _confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.74
    if base_kind == "generic":
        return 0.78
    if base_kind == "argument":
        return 0.76
    if base_kind == "bugcheck":
        return 0.74
    return 0.86


def _field_preview_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.7
    if base_kind == "generic":
        return 0.74
    if base_kind == "argument":
        return 0.72
    if base_kind == "bugcheck":
        return 0.70
    return 0.82


def _field_alias_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.66
    if base_kind == "generic":
        return 0.7
    if base_kind == "argument":
        return 0.68
    if base_kind == "bugcheck":
        return 0.66
    return 0.78


def _field_hot_cluster_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.70
    if base_kind == "generic":
        return 0.72
    if base_kind == "argument":
        return 0.70
    if base_kind == "bugcheck":
        return 0.68
    return 0.74


def _field_indexed_layout_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.66
    if base_kind == "generic":
        return 0.70
    if base_kind == "argument":
        return 0.72
    if base_kind == "bugcheck":
        return 0.66
    return 0.74


def _field_subfield_overlay_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.66
    if base_kind == "generic":
        return 0.7
    if base_kind == "argument":
        return 0.68
    if base_kind == "bugcheck":
        return 0.66
    return 0.76


def _field_narrow_subfield_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.68
    if base_kind == "generic":
        return 0.72
    if base_kind == "argument":
        return 0.70
    if base_kind == "bugcheck":
        return 0.68
    return 0.78


def _field_bitfield_alias_confidence_cap_for_base_kind(base_kind: str) -> float:
    if base_kind == "temp":
        return 0.66
    if base_kind == "generic":
        return 0.7
    if base_kind == "argument":
        return 0.68
    if base_kind == "bugcheck":
        return 0.66
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
    if base_kind == "argument":
        return 0.72
    if base_kind == "bugcheck":
        return 0.70
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
    if base_kind == "argument":
        return (
            "Review fields for %s (argument identity base): %s. Review only; no IDB type or pseudocode rewrite was applied."
            % (base, field_text)
        )
    if base_kind == "bugcheck":
        return (
            "Review fields for %s (bugcheck parameter base): %s. Review only; no IDB type or pseudocode rewrite was applied."
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
    if base_kind == "argument":
        return (
            "Review aliases for %s (argument identity base): %s. Review-only shorthand; do not treat as a recovered structure type."
            % (base, alias_text)
        )
    if base_kind == "bugcheck":
        return (
            "Review aliases for %s (bugcheck parameter base): %s. Review-only shorthand; do not treat as a recovered structure type."
            % (base, alias_text)
        )
    return (
        "Alias map for %s: %s. Use as review-only shorthand for repeated offset dereferences."
        % (base, alias_text)
    )


def _field_hot_cluster_text(
    base: str,
    base_kind: str,
    access_count: int,
    offset_count: int,
    field_text: str,
) -> str:
    return (
        "Hot field cluster for %s (%s base): %d typed dereference(s) concentrated in %d offset(s); top fields %s. "
        "Review-only access-pressure evidence; no structure type or body rewrite was inferred."
        % (base, _field_hot_cluster_base_kind_label(base_kind), access_count, offset_count, field_text)
    )


def _field_hot_cluster_base_kind_label(base_kind: str) -> str:
    if base_kind == "temp":
        return "temporary"
    if base_kind == "generic":
        return "generic"
    if base_kind == "argument":
        return "argument identity"
    if base_kind == "bugcheck":
        return "bugcheck parameter"
    return "named"


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
    if base_kind == "argument":
        return (
            "Review subfield overlays for %s (argument identity base): %s. Review-only evidence; field rewrite remains blocked for mixed-width offsets."
            % (base, overlay_text)
        )
    if base_kind == "bugcheck":
        return (
            "Review subfield overlays for %s (bugcheck parameter base): %s. Review-only evidence; field rewrite remains blocked for mixed-width offsets."
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
    if base_kind == "argument":
        return (
            "Review narrow subfields for %s (argument identity base): %s. Audit-only; body rewrite remains disabled until the parent structure is trusted."
            % (base, field_text)
        )
    if base_kind == "bugcheck":
        return (
            "Review narrow subfields for %s (bugcheck parameter base): %s. Audit-only; body rewrite remains disabled until the parent structure is trusted."
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
    if base_kind == "argument":
        return (
            "Review bitfield aliases for %s (argument identity base): %s. Review-only names; body rewrite remains disabled until the parent structure is trusted."
            % (base, alias_text)
        )
    if base_kind == "bugcheck":
        return (
            "Review bitfield aliases for %s (bugcheck parameter base): %s. Review-only names; body rewrite remains disabled until the parent structure is trusted."
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


def _field_stable_expression_source_text(
    base: str,
    source: str,
    source_expression_kind: str,
    access_count: int,
    offset_count: int,
) -> str:
    return (
        "Stable expression source for %s: %s (%s), %d typed dereference(s) across %d offset(s). "
        "Review-only; rewrite remains blocked until the parent source identity is trusted."
        % (base, source, source_expression_kind, access_count, offset_count)
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
    if base_kind == "argument":
        return "Review argument identity before inferring a structure."
    if base_kind == "bugcheck":
        return "Review bugcheck parameter identity before inferring a structure."
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
    if normalized.endswith("*"):
        return "size:8"
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
    if normalized.endswith("*"):
        return 8
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
    pre_access_rhs = _canonicalized_pre_access_assignment_rhs(
        text,
        base,
        [
            item
            for item in simple_assignments
            if item.start() < first_access
        ],
    )
    effective_pre_access_rhs = _effective_pre_access_initializer_rhs(pre_access_rhs)
    distinct_pre_access_rhs = {item for item in effective_pre_access_rhs if item}
    if (
        len(distinct_pre_access_rhs) > 1
        and not _same_call_result_family_pre_access_rhs(effective_pre_access_rhs)
    ):
        blockers.append("base has multiple initializers before layout access")
    stable_rhs = effective_pre_access_rhs[-1] if effective_pre_access_rhs else ""
    for assignment in simple_assignments:
        if assignment.start() < first_access:
            continue
        rhs = _normalize_assignment_rhs(assignment.group("rhs"))
        if _is_stable_base_reload_rhs(
            text,
            base,
            rhs,
            stable_rhs,
            first_access,
            assignment.start(),
        ):
            continue
        if _next_layout_access_start(text, base, assignment.end()) < 0:
            continue
        blockers.append("base is reassigned after layout access")
        break
    return blockers


def _is_base_stability_blocker_reason(reason: str) -> bool:
    lowered = str(reason or "").lower()
    return any(fragment in lowered for fragment in _BASE_STABILITY_BLOCKER_FRAGMENTS)


def _effective_pre_access_initializer_rhs(values: list[str]) -> list[str]:
    result: list[str] = []
    seen_non_null = False
    for value in values:
        normalized = _normalize_assignment_rhs(value)
        if normalized and _is_null_initializer(normalized) and not seen_non_null:
            continue
        if normalized and not _is_null_initializer(normalized):
            seen_non_null = True
        result.append(normalized)
    return result


def _same_call_result_family_pre_access_rhs(values: list[str]) -> str:
    effective_values = [
        _normalize_assignment_rhs(item)
        for item in values
        if _normalize_assignment_rhs(item)
    ]
    if len(effective_values) < 2:
        return ""
    call_names = []
    for value in effective_values:
        if _layout_rhs_kind(value) != "call_result":
            return ""
        call_name = _parse_direct_call_result_name(value)
        if not call_name:
            return ""
        call_names.append(call_name)
    if len(set(call_names)) != 1:
        return ""
    return effective_values[-1]


def _canonicalized_pre_access_assignment_rhs(
    text: str,
    base: str,
    assignments: list[re.Match[str]],
) -> list[str]:
    return [
        _canonical_pre_access_initializer_rhs(
            text,
            item.group("rhs"),
            item.start(),
            {base},
        )
        for item in assignments
        if item.group("op") == "="
    ]


def _canonical_pre_access_initializer_rhs(
    text: str,
    rhs: str,
    before: int,
    seen: set[str],
) -> str:
    normalized = _normalize_assignment_rhs(rhs)
    if not normalized or not _is_identifier_expression(normalized):
        return normalized
    if normalized in seen:
        return normalized
    seen.add(normalized)
    assignments = [
        item
        for item in _base_direct_assignments(text, normalized)
        if item.start() < before
    ]
    if not assignments:
        return normalized
    if any(item.group("op") != "=" for item in assignments):
        return normalized
    canonical_sources = [
        _canonical_pre_access_initializer_rhs(
            text,
            item.group("rhs"),
            item.start(),
            set(seen),
        )
        for item in assignments
    ]
    effective_sources = _effective_pre_access_initializer_rhs(canonical_sources)
    distinct_sources = list(dict.fromkeys(item for item in effective_sources if item))
    if len(distinct_sources) != 1:
        return normalized
    return distinct_sources[0]


def _base_assignment_trace(text: str, base: str) -> dict[str, Any]:
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        return {}
    assignments = _base_direct_assignments(text, base)
    pre_access = [item for item in assignments if item.start() < first_access]
    post_access = [item for item in assignments if item.start() >= first_access]
    simple_pre_rhs = _canonicalized_pre_access_assignment_rhs(
        text,
        base,
        [
            item
            for item in pre_access
            if item.group("op") == "="
        ],
    )
    effective_pre_rhs = _effective_pre_access_initializer_rhs(simple_pre_rhs)
    distinct_pre_rhs = list(dict.fromkeys(item for item in effective_pre_rhs if item))
    stable_rhs = effective_pre_rhs[-1] if effective_pre_rhs else ""
    risky_post_access_count = 0
    stable_post_access_reload_count = 0
    stable_post_access_reload_rhs: list[str] = []
    risky_post_access_rhs: list[str] = []
    for assignment in post_access:
        if assignment.group("op") != "=":
            risky_post_access_count += 1
            risky_post_access_rhs.append(str(assignment.group("op")))
            continue
        rhs = _normalize_assignment_rhs(assignment.group("rhs"))
        if _is_stable_base_reload_rhs(
            text,
            base,
            rhs,
            stable_rhs,
            first_access,
            assignment.start(),
        ):
            stable_post_access_reload_count += 1
            stable_post_access_reload_rhs.append(rhs)
            continue
        if _next_layout_access_start(text, base, assignment.end()) >= 0:
            risky_post_access_count += 1
            risky_post_access_rhs.append(rhs)
    return {
        "pre_access_assignment_count": len(pre_access),
        "distinct_pre_access_rhs_count": len(distinct_pre_rhs),
        "distinct_pre_access_rhs": distinct_pre_rhs,
        "post_access_assignment_count": len(post_access),
        "stable_post_access_reload_count": stable_post_access_reload_count,
        "risky_post_access_assignment_count": risky_post_access_count,
        "stable_post_access_reload_rhs": list(dict.fromkeys(stable_post_access_reload_rhs)),
        "risky_post_access_rhs": list(dict.fromkeys(risky_post_access_rhs)),
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


def _is_identifier_expression(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(value or "").strip()))


def _is_stable_base_reload_rhs(
    text: str,
    base: str,
    rhs: str,
    stable_rhs: str,
    first_access: int,
    assignment_start: int,
) -> bool:
    normalized_rhs = _normalize_assignment_rhs(rhs)
    if not normalized_rhs:
        return False
    if stable_rhs and normalized_rhs == stable_rhs:
        return True
    if not _is_identifier_expression(normalized_rhs):
        return False
    if normalized_rhs == base:
        return False
    return _identifier_holds_stable_base_before_access(
        text,
        normalized_rhs,
        base,
        stable_rhs,
        first_access,
        assignment_start,
        set(),
    )


def _identifier_holds_stable_base_before_access(
    text: str,
    name: str,
    base: str,
    stable_rhs: str,
    first_access: int,
    position: int,
    seen: set[str],
) -> bool:
    if first_access < 0 or position < 0:
        return False
    if name in seen:
        return False
    seen.add(name)
    assignments = [
        item
        for item in _base_direct_assignments(text, name)
        if item.start() < position
    ]
    if not assignments:
        return False
    assignment = assignments[-1]
    if assignment.start() >= first_access:
        return False
    if assignment.group("op") != "=":
        return False
    source = _normalize_assignment_rhs(assignment.group("rhs"))
    if not source:
        return False
    if stable_rhs and source == stable_rhs:
        return True
    if source == base:
        return True
    if not _is_identifier_expression(source):
        return False
    if source == name:
        return False
    return _identifier_holds_stable_base_before_access(
        text,
        source,
        base,
        stable_rhs,
        first_access,
        assignment.start(),
        seen,
    )


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
    effective_pre_access_rhs = _effective_pre_access_initializer_rhs(pre_access_rhs)
    distinct_pre_access_rhs = {item for item in effective_pre_access_rhs if item}
    canonical_pre_access_rhs = _canonicalized_pre_access_assignment_rhs(
        text,
        base,
        pre_access_assignments,
    )
    effective_canonical_pre_access_rhs = _effective_pre_access_initializer_rhs(
        canonical_pre_access_rhs
    )
    distinct_canonical_pre_access_rhs = {
        item
        for item in effective_canonical_pre_access_rhs
        if item
    }
    stable_rhs = effective_pre_access_rhs[-1] if effective_pre_access_rhs else ""
    if len(distinct_pre_access_rhs) != 1 and len(distinct_canonical_pre_access_rhs) != 1:
        stable_rhs = _same_call_result_family_pre_access_rhs(effective_pre_access_rhs)
        if not stable_rhs:
            return ""
    if _is_null_initializer(stable_rhs):
        return ""
    return stable_rhs


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
    parameter_indirect_identity = _parameter_indirect_pointer_source_identity(
        text,
        base,
        source,
        len(base_assignments),
    )
    if parameter_indirect_identity:
        return parameter_indirect_identity
    parameter_direct_identity = _parameter_direct_source_identity(
        text,
        base,
        source,
        len(base_assignments),
    )
    if parameter_direct_identity:
        return parameter_direct_identity
    parameter_derived_identity = _parameter_derived_source_identity(
        text,
        base,
        source,
        len(base_assignments),
    )
    if parameter_derived_identity:
        return parameter_derived_identity
    allocation_subobject_identity = _allocation_subobject_source_identity(
        text,
        base,
        source,
        len(base_assignments),
    )
    if allocation_subobject_identity:
        return allocation_subobject_identity
    named_parameter_identity = _named_parameter_direct_source_identity(
        text,
        base,
        source,
        len(base_assignments),
    )
    if named_parameter_identity:
        return named_parameter_identity
    temporary_call_result_identity = _temporary_call_result_source_identity(
        text,
        base,
        source,
        len(base_assignments),
    )
    if temporary_call_result_identity:
        return temporary_call_result_identity
    out_parameter_identity = _local_out_parameter_source_identity(
        text,
        base,
        source,
        len(base_assignments),
    )
    if out_parameter_identity:
        return out_parameter_identity
    direct_call_result_identity = _direct_call_result_source_identity(
        base,
        source,
        len(base_assignments),
    )
    if direct_call_result_identity:
        return direct_call_result_identity
    named_branch_call_result_identity = _named_branch_call_result_source_identity(
        text,
        base,
        source,
        len(base_assignments),
    )
    if named_branch_call_result_identity:
        return named_branch_call_result_identity
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


def _parameter_indirect_pointer_source_identity(
    text: str,
    base: str,
    source: str,
    base_alias_assignment_count: int,
) -> dict[str, Any]:
    if base_alias_assignment_count != 1:
        return {}
    if _layout_base_kind(base) != "temp":
        return {}
    match = _parse_parameter_indirect_pointer_source(source)
    if not match:
        return {}
    parent = str(match["parent"])
    if not _base_is_function_parameter(text, parent):
        return {}
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        return {}
    parent_assignments = [
        item
        for item in _base_direct_assignments(text, parent)
        if item.start() < first_access
    ]
    if parent_assignments:
        return {}
    source_kind = "argument" if _is_decompiler_argument_base(parent) else "parameter"
    identity: dict[str, Any] = {
        "source": parent,
        "source_kind": source_kind,
        "source_provenance": "parameter_indirect_pointer_alias",
        "source_rhs_kind": "parameter_pointer_deref",
        "base_alias_assignments": base_alias_assignment_count,
        "source_assignments": 0,
    }
    if match.get("type"):
        identity["source_type"] = match["type"]
    return identity


def _parse_parameter_indirect_pointer_source(source: str) -> dict[str, Any]:
    value = str(source or "").strip()
    direct = re.fullmatch(r"\*\s*(?P<parent>[A-Za-z_][A-Za-z0-9_]*)", value)
    if direct:
        return {
            "parent": direct.group("parent"),
            "type": "",
        }
    casted = re.fullmatch(
        r"\*\s*\(\s*(?P<type>[^()]+?)\s*\*\s*\)\s*(?P<parent>[A-Za-z_][A-Za-z0-9_]*)",
        value,
    )
    if not casted:
        return {}
    type_name = _normalize_type_name(casted.group("type"))
    if _field_type_storage_size(type_name) != 8:
        return {}
    return {
        "parent": casted.group("parent"),
        "type": type_name,
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


def _parameter_direct_source_identity(
    text: str,
    base: str,
    source: str,
    base_alias_assignment_count: int,
) -> dict[str, Any]:
    if base_alias_assignment_count <= 0:
        return {}
    if _layout_base_kind(base) != "temp":
        return {}
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(source or "")):
        return {}
    if _is_generic_argument_base(source):
        return {}
    if not _base_is_function_parameter(text, source):
        return {}
    if _is_bugcheck_parameter_base(source):
        return {}
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        return {}
    source_assignments = [
        item
        for item in _base_direct_assignments(text, source)
        if item.start() < first_access
    ]
    if source_assignments:
        return {}
    return {
        "source": source,
        "source_kind": "parameter",
        "source_provenance": "parameter_direct_alias",
        "source_rhs_kind": "direct_parameter",
        "base_alias_assignments": base_alias_assignment_count,
        "source_assignments": 0,
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
    back_container = _parse_parameter_back_container_source(source)
    if back_container and _base_is_function_parameter(text, str(back_container["parent"])):
        return _parameter_source_identity(
            back_container,
            "parameter_back_container_alias",
            "parameter_back_container",
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
    elif source_kind == "named":
        source_kind = "parameter"
    identity: dict[str, Any] = {
        "source": parent,
        "source_kind": source_kind,
        "source_provenance": provenance,
        "source_rhs_kind": rhs_kind,
        "base_alias_assignments": base_alias_assignment_count,
        "source_assignments": 0,
    }
    if "offset" in match:
        if match.get("offset_direction") == "negative":
            identity["source_offset"] = "-0x%X" % int(match["offset"])
            identity["source_container_offset"] = "0x%X" % int(match["offset"])
        else:
            identity["source_offset"] = "0x%X" % int(match["offset"])
    if "index" in match:
        identity["source_index"] = int(match["index"])
    return identity


def _allocation_subobject_source_identity(
    text: str,
    base: str,
    source: str,
    base_alias_assignment_count: int,
) -> dict[str, Any]:
    if base_alias_assignment_count <= 0:
        return {}
    if _layout_base_kind(base) != "temp":
        return {}
    subobject = _parse_parameter_subobject_source(source)
    if not subobject:
        return {}
    parent = str(subobject["parent"])
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        return {}
    base_alias_assignments = [
        item
        for item in _base_direct_assignments(text, base)
        if item.start() < first_access
        and item.group("op") == "="
        and _normalize_assignment_rhs(item.group("rhs")) == source
    ]
    if not base_alias_assignments:
        return {}
    allocation_root = _allocation_source_root_before(
        text,
        parent,
        base_alias_assignments[0].start(),
        set(),
    )
    if not allocation_root:
        return {}
    source_offset = _scaled_pointer_arithmetic_offset(text, parent, int(subobject["offset"]))
    identity: dict[str, Any] = {
        "source": allocation_root,
        "source_kind": "allocation",
        "source_provenance": "allocation_subobject_pointer_alias",
        "source_rhs_kind": "allocation_pointer_arithmetic",
        "source_offset": "0x%X" % source_offset,
        "base_alias_assignments": base_alias_assignment_count,
        "source_assignments": 0,
    }
    if parent != allocation_root:
        identity["source_alias"] = parent
    return identity


def _allocation_source_root_before(
    text: str,
    name: str,
    before: int,
    seen: set[str],
) -> str:
    if not name or name in seen:
        return ""
    seen.add(name)
    assignments = [
        item
        for item in _base_direct_assignments(text, name)
        if item.start() < before and item.group("op") == "="
    ]
    if not assignments:
        return ""
    roots: list[str] = []
    for assignment in assignments:
        rhs = _normalize_assignment_rhs(assignment.group("rhs"))
        if not rhs or _is_null_initializer(rhs):
            continue
        if _is_allocation_result_rhs(rhs):
            roots.append(name)
            continue
        if _is_identifier_expression(rhs):
            root = _allocation_source_root_before(text, rhs, assignment.start(), seen)
            if root:
                roots.append(root)
                continue
        return ""
    unique_roots = list(dict.fromkeys(roots))
    if len(unique_roots) != 1:
        return ""
    return unique_roots[0]


def _is_allocation_result_rhs(rhs: str) -> bool:
    value = _normalize_assignment_rhs(rhs)
    call_name = _parse_any_direct_call_result_name(value)
    return _is_allocation_like_call_result_name(call_name)


def _scaled_pointer_arithmetic_offset(text: str, parent: str, offset: int) -> int:
    element_size = _local_pointer_element_size(text, parent)
    if element_size <= 0:
        return offset
    return offset * element_size


def _local_pointer_element_size(text: str, name: str) -> int:
    match = re.search(
        r"(?m)^\s*(?P<type>[A-Za-z_][A-Za-z0-9_:\s]*?)\s*"
        r"(?P<stars>\*+)\s*%s\b\s*(?:[;=,])" % re.escape(name),
        text or "",
    )
    if not match:
        return 0
    if len(match.group("stars") or "") != 1:
        return 8
    type_name = _normalize_type_name(match.group("type"))
    if type_name.lower() == "void":
        return 1
    return _field_type_storage_size(type_name)


def _stable_expression_source_profile(source: str) -> dict[str, Any]:
    indexed = _parse_parameter_indexed_source(source)
    if indexed:
        return {
            "source_expression_kind": "indexed_pointer",
            "source_parent": str(indexed["parent"]),
            "source_index": int(indexed["index"]),
        }
    field_pointer = _parse_field_pointer_source(source)
    if field_pointer:
        return {
            "source_expression_kind": "field_pointer_deref",
            "source_parent": str(field_pointer["parent"]),
            "source_offset": "0x%X" % int(field_pointer["offset"]),
            "source_type": str(field_pointer["type"]),
        }
    indirect = _parse_parameter_indirect_pointer_source(source)
    if indirect:
        profile: dict[str, Any] = {
            "source_expression_kind": "pointer_deref",
            "source_parent": str(indirect["parent"]),
        }
        if indirect.get("type"):
            profile["source_type"] = str(indirect["type"])
        return profile
    subobject = _parse_parameter_subobject_source(source)
    if subobject:
        return {
            "source_expression_kind": "pointer_arithmetic",
            "source_parent": str(subobject["parent"]),
            "source_offset": "0x%X" % int(subobject["offset"]),
        }
    back_container = _parse_parameter_back_container_source(source)
    if back_container:
        return {
            "source_expression_kind": "back_container_pointer_arithmetic",
            "source_parent": str(back_container["parent"]),
            "source_offset": "-0x%X" % int(back_container["offset"]),
            "source_container_offset": "0x%X" % int(back_container["offset"]),
        }
    return {}


def _named_parameter_direct_source_identity(
    text: str,
    base: str,
    source: str,
    base_alias_assignment_count: int,
) -> dict[str, Any]:
    if base_alias_assignment_count <= 0:
        return {}
    if _layout_base_kind(base) != "temp":
        return {}
    source_kind = _layout_source_kind(source)
    if source_kind not in {"named", "temporary"}:
        return {}
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        return {}
    base_alias_assignments = [
        item
        for item in _base_direct_assignments(text, base)
        if item.start() < first_access
        and item.group("op") == "="
        and _normalize_assignment_rhs(item.group("rhs")) == source
    ]
    if not base_alias_assignments:
        return {}
    base_alias_start = base_alias_assignments[0].start()
    source_assignments = [
        item
        for item in _base_direct_assignments(text, source)
        if item.start() < first_access
    ]
    if len(source_assignments) != 1:
        return {}
    source_assignment = source_assignments[0]
    if source_assignment.group("op") != "=":
        return {}
    if source_assignment.start() >= base_alias_start:
        return {}
    root = _normalize_assignment_rhs(source_assignment.group("rhs"))
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", root):
        return {}
    if _is_generic_argument_base(root) or _is_bugcheck_parameter_base(root):
        return {}
    if not _base_is_function_parameter(text, root):
        return {}
    root_assignments = [
        item
        for item in _base_direct_assignments(text, root)
        if item.start() < first_access
    ]
    if root_assignments:
        return {}
    if _base_address_taken(text, source) or _base_has_array_index_use(text, source) or _base_is_incremented(text, source):
        return {}
    source_provenance = "named_parameter_direct_alias"
    if source_kind == "temporary":
        source_provenance = "temporary_parameter_direct_alias"
    return {
        "source": root,
        "source_kind": "parameter",
        "source_provenance": source_provenance,
        "source_rhs_kind": "direct_parameter_alias",
        "source_alias": source,
        "base_alias_assignments": base_alias_assignment_count,
        "source_assignments": len(source_assignments),
    }


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


def _parse_parameter_back_container_source(source: str) -> dict[str, Any]:
    match = re.fullmatch(
        r"(?P<parent>[A-Za-z_][A-Za-z0-9_]*)\s*-\s*"
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
        "offset_direction": "negative",
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


def _local_out_parameter_source_identity(
    text: str,
    base: str,
    source: str,
    base_alias_assignment_count: int,
) -> dict[str, Any]:
    if base_alias_assignment_count != 1:
        return {}
    if _layout_base_kind(base) != "temp":
        return {}
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(source or "")):
        return {}
    if _base_is_function_parameter(text, source):
        return {}
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        return {}
    base_alias_assignments = [
        item
        for item in _base_direct_assignments(text, base)
        if item.start() < first_access
        and item.group("op") == "="
        and _normalize_assignment_rhs(item.group("rhs")) == source
    ]
    if len(base_alias_assignments) != 1:
        return {}
    base_alias_start = base_alias_assignments[0].start()
    source_assignments = [
        item
        for item in _base_direct_assignments(text, source)
        if item.start() < first_access
    ]
    if len(source_assignments) != 1:
        return {}
    source_initializer = source_assignments[0]
    if source_initializer.group("op") != "=":
        return {}
    if not _is_null_initializer(_normalize_assignment_rhs(source_initializer.group("rhs"))):
        return {}
    out_calls = _direct_out_parameter_calls_before(text, source, base_alias_start)
    if len(out_calls) != 1:
        return {}
    out_call = out_calls[0]
    if source_initializer.start() >= int(out_call["start"]):
        return {}
    source_reassignments_after_call = [
        item
        for item in source_assignments
        if item.start() > int(out_call["end"])
    ]
    if source_reassignments_after_call:
        return {}
    address_uses = _address_taken_occurrences_before(text, source, first_access)
    if len(address_uses) != 1:
        return {}
    return {
        "source": source,
        "source_kind": "out_parameter",
        "source_provenance": "local_out_parameter_alias",
        "source_rhs_kind": "out_parameter_call",
        "source_call": out_call["name"],
        "base_alias_assignments": base_alias_assignment_count,
        "source_assignments": len(source_assignments),
    }


def _is_null_initializer(value: str) -> bool:
    normalized = _normalize_assignment_rhs(value).lower()
    if normalized in {"0", "0ll", "0i64", "0ull", "null", "nullptr"}:
        return True
    return re.fullmatch(r"0+[ul]*", normalized) is not None


def _direct_out_parameter_calls_before(text: str, source: str, before: int) -> list[dict[str, Any]]:
    if before < 0:
        return []
    pattern = re.compile(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_:~]*)\s*"
        r"\((?P<args>[^();{}\n]*&\s*%s\b[^();{}\n]*)\)"
        % re.escape(source)
    )
    calls = []
    for match in pattern.finditer(text or ""):
        if match.start() >= before:
            continue
        name = match.group("name")
        if not _is_trusted_direct_out_parameter_call_name(name):
            continue
        calls.append({"name": name, "start": match.start(), "end": match.end()})
    return calls


def _is_trusted_direct_out_parameter_call_name(name: str) -> bool:
    normalized = str(name or "").strip()
    if not normalized:
        return False
    if normalized in {"if", "while", "for", "switch", "return", "sizeof"}:
        return False
    if normalized.startswith("sub_") or normalized.startswith("guard_dispatch_"):
        return False
    return True


def _address_taken_occurrences_before(text: str, source: str, before: int) -> list[int]:
    if before < 0:
        return []
    pattern = re.compile(r"&\s*%s\b" % re.escape(source))
    return [
        match.start()
        for match in pattern.finditer(text or "")
        if match.start() < before
    ]


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


def _named_branch_call_result_source_identity(
    text: str,
    base: str,
    source: str,
    base_alias_assignment_count: int,
) -> dict[str, Any]:
    if base_alias_assignment_count != 1:
        return {}
    if _layout_base_kind(base) != "temp":
        return {}
    if _layout_source_kind(source) != "named":
        return {}
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        return {}
    base_alias_assignments = [
        item
        for item in _base_direct_assignments(text, base)
        if item.start() < first_access
        and item.group("op") == "="
        and _normalize_assignment_rhs(item.group("rhs")) == source
    ]
    if len(base_alias_assignments) != 1:
        return {}
    base_alias_start = base_alias_assignments[0].start()
    source_assignments = [
        item
        for item in _base_direct_assignments(text, source)
        if item.start() < first_access
    ]
    if len(source_assignments) < 2 or len(source_assignments) > 4:
        return {}
    source_calls = []
    source_call_names = []
    for source_assignment in source_assignments:
        if source_assignment.group("op") != "=":
            return {}
        if source_assignment.start() >= base_alias_start:
            return {}
        rhs = _normalize_assignment_rhs(source_assignment.group("rhs"))
        if _layout_rhs_kind(rhs) != "call_result":
            return {}
        call_name = _parse_direct_call_result_name(rhs)
        if not call_name:
            return {}
        source_calls.append(rhs)
        source_call_names.append(call_name)
    return {
        "source": source,
        "source_kind": "named",
        "source_provenance": "named_branch_call_result_alias",
        "source_rhs_kind": "call_result",
        "source_call": "; ".join(source_calls[:4]),
        "source_calls": source_calls,
        "source_call_names": source_call_names,
        "base_alias_assignments": base_alias_assignment_count,
        "source_assignments": len(source_assignments),
    }


def _temporary_call_result_source_identity(
    text: str,
    base: str,
    source: str,
    base_alias_assignment_count: int,
) -> dict[str, Any]:
    if base_alias_assignment_count <= 0:
        return {}
    if _layout_base_kind(base) != "temp":
        return {}
    if not _is_decompiler_temp_base(source):
        return {}
    first_access = _first_layout_access_start(text, base)
    if first_access < 0:
        return {}
    base_alias_assignments = [
        item
        for item in _base_direct_assignments(text, base)
        if item.start() < first_access
        and item.group("op") == "="
        and _normalize_assignment_rhs(item.group("rhs")) == source
    ]
    if len(base_alias_assignments) != base_alias_assignment_count:
        return {}
    base_alias_assignments.sort(key=lambda item: item.start())
    first_base_alias = base_alias_assignments[0]
    source_assignments = [
        item
        for item in _base_direct_assignments(text, source)
        if item.start() < first_access
    ]
    source_assignments.sort(key=lambda item: item.start())
    source_assignments_before_alias = [
        item for item in source_assignments if item.start() < first_base_alias.start()
    ]
    source_assignments_after_alias = [
        item for item in source_assignments if item.start() >= first_base_alias.start()
    ]
    if not source_assignments_before_alias or source_assignments_after_alias:
        return {}
    source_assignment = source_assignments_before_alias[-1]
    if source_assignment.group("op") != "=":
        return {}
    if _brace_depth_at(text, source_assignment.start()) != 1:
        return {}
    if _brace_depth_at(text, first_base_alias.start()) != 1:
        return {}
    if not _only_trivia_between(text, source_assignment.end(), first_base_alias.start()):
        return {}
    rhs = _normalize_assignment_rhs(source_assignment.group("rhs"))
    if _layout_rhs_kind(rhs) != "call_result":
        return {}
    call_name = _parse_direct_call_result_name(rhs)
    if not call_name:
        return {}
    return {
        "source": source,
        "source_kind": "temporary",
        "source_provenance": "temporary_call_result_alias",
        "source_rhs_kind": "call_result",
        "source_call": rhs,
        "base_alias_assignments": base_alias_assignment_count,
        "source_assignments": len(source_assignments),
    }


def _only_trivia_between(text: str, start: int, end: int) -> bool:
    if start > end:
        return False
    segment = str(text or "")[max(0, start) : max(0, end)]
    segment = re.sub(r"//[^\n]*", "", segment)
    segment = re.sub(r"/\*.*?\*/", "", segment, flags=re.S)
    return not segment.strip()


def _truthiness_guard_dominating_offset(text: str, base: str, offset: int) -> dict[str, Any]:
    if offset < 0 or not base:
        return {}
    value = str(text or "")
    escaped = re.escape(base)
    base_pattern = r"\b%s\b" % escaped
    guard_pattern = re.compile(
        r"\bif\s*\(\s*(?P<condition>"
        r"%s"
        r"|%s\s*!=\s*(?:0|0LL|0i64|nullptr|NULL)"
        r"|(?:0|0LL|0i64|nullptr|NULL)\s*!=\s*%s"
        r")\s*\)"
        % (base_pattern, base_pattern, base_pattern)
    )
    for match in guard_pattern.finditer(value):
        if match.start() >= offset:
            break
        block_start = value.find("{", match.end(), offset)
        if block_start < 0:
            continue
        block_end = _matching_brace_end(value, block_start)
        if block_end >= offset:
            return {
                "condition": match.group("condition").strip(),
                "start": match.start(),
                "end": block_end,
            }
    return {}


def _matching_brace_end(text: str, open_offset: int) -> int:
    value = str(text or "")
    if open_offset < 0 or open_offset >= len(value) or value[open_offset] != "{":
        return -1
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = open_offset
    while index < len(value):
        char = value[index]
        next_char = value[index + 1] if index + 1 < len(value) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 2
                continue
            index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char == "/" and next_char == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            index += 2
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                return -1
        index += 1
    return -1


def _brace_depth_at(text: str, offset: int) -> int:
    value = str(text or "")
    limit = max(0, min(int(offset), len(value)))
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = 0
    while index < limit:
        char = value[index]
        next_char = value[index + 1] if index + 1 < limit else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 2
                continue
            index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char == "/" and next_char == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            index += 2
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        index += 1
    return depth


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


def _parse_any_direct_call_result_name(source: str) -> str:
    match = re.fullmatch(
        r"(?P<name>[A-Za-z_][A-Za-z0-9_:~]*)\s*\([^;\n]*\)",
        str(source or "").strip(),
    )
    if not match:
        return ""
    return match.group("name")


def _is_allocation_like_call_result_name(name: str) -> bool:
    return str(name or "") in {
        "ExAllocateFromLookasideListEx",
        "ExAllocateFromNPagedLookasideList",
        "ExAllocatePool2",
        "MiAllocatePool",
    }


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
    if _is_bugcheck_parameter_base(value):
        return "bugcheck"
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
        "_oword",
        "_qword",
        "_word",
        "char",
        "const",
        "dword",
        "int",
        "long",
        "oword",
        "short",
        "signed",
        "size_t",
        "uint64",
        "ulong",
        "unsigned",
        "void",
        "word",
        "xmmword",
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
    first = -1
    for match in _OFFSET_DEREF_RE.finditer(text or ""):
        if match.group("base") == base:
            first = match.start() if first < 0 else min(first, match.start())
    for match in _OFFSET_INDEXED_DEREF_RE.finditer(text or ""):
        if match.group("base") == base:
            first = match.start() if first < 0 else min(first, match.start())
    return first


def _next_layout_access_start(text: str, base: str, start: int) -> int:
    next_access = -1
    for match in _OFFSET_DEREF_RE.finditer(text or "", max(0, int(start))):
        if match.group("base") == base:
            next_access = match.start() if next_access < 0 else min(next_access, match.start())
    for match in _OFFSET_INDEXED_DEREF_RE.finditer(text or "", max(0, int(start))):
        if match.group("base") == base:
            next_access = match.start() if next_access < 0 else min(next_access, match.start())
    return next_access


def _base_address_taken(text: str, base: str) -> bool:
    return re.search(r"&\s*%s\b" % re.escape(base), text or "") is not None


def _base_has_array_index_use(text: str, base: str) -> bool:
    return re.search(r"\b%s\s*\[" % re.escape(base), text or "") is not None

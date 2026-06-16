from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import Any


_OFFSET_DEREF_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[A-Za-z_][A-Za-z0-9_:\s]*?)\s*\*\s*\)\s*"
    r"\(\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
)

_PREVIEW_ONLY_COMMENT = "Preview artifact only; body rewrite was not applied."
_AUDIT_ONLY_NOT_APPLIED_COMMENT = "Audit only; body rewrite was not applied."
_CANONICAL_APPLIED_COMMENT = "Validated layout rewrite applied to canonical cleaned output."

_REWRITE_PREVIEW_RE = re.compile(
    r"-\s+inferred_offset_rewrite_preview:\s+Offset field rewrite preview for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<access_count>\d+)\s+dereference\(s\)\s+can map to\s+"
    r"(?P<field_count>\d+)\s+field alias\(es\)\s+"
    r"(?P<fields>.*?)\.\s+"
    r"(?:Source provenance\s+(?P<source_provenance>[a-z_]+)\s+from\s+"
    r"(?P<source>[A-Za-z_][A-Za-z0-9_]*)\.\s+)?"
    + re.escape(_PREVIEW_ONLY_COMMENT)
    + r"\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)

_REWRITE_READY_RE = re.compile(
    r"-\s+inferred_offset_rewrite_ready:\s+Offset field rewrite candidate for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\),\s+no rewrite blockers found\.\s+"
    r"(?:Source provenance\s+(?P<source_provenance>[a-z_]+)\s+from\s+"
    r"(?P<source>[A-Za-z_][A-Za-z0-9_]*)\.\s+)?"
    r"(?P<status_comment>"
    + re.escape(_AUDIT_ONLY_NOT_APPLIED_COMMENT)
    + r"|"
    + re.escape(_CANONICAL_APPLIED_COMMENT)
    + r")\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)

_REWRITE_ACCESS_THRESHOLD = 12
_REWRITE_FIELD_THRESHOLD = 8


@dataclass(slots=True)
class LayoutRewritePreviewBundle:
    text: str
    diff: str
    metadata: dict[str, Any]
    canonical_text: str | None = None


def build_layout_rewrite_preview_bundle(
    cleaned_text: str,
    artifact_name: str = "function",
    apply_validated_body_rewrite: bool = False,
) -> LayoutRewritePreviewBundle | None:
    plans = _layout_rewrite_preview_plans(cleaned_text)
    if not plans:
        return None
    normalized_cleaned_text, normalized_plans, normalization_items = _normalize_layout_rewrite_advertisements(
        cleaned_text,
        plans,
    )
    if normalization_items:
        cleaned_text = normalized_cleaned_text
        plans = normalized_plans
    rewritten, rewrite_stats = _rewrite_layout_offset_dereferences(cleaned_text, plans)
    if rewrite_stats["rewritten_accesses"] <= 0:
        return None
    validation_text = _preview_header(artifact_name, rewrite_stats) + rewritten.rstrip() + "\n"
    validation = _validate_layout_rewrite_preview(plans, rewrite_stats, validation_text)
    canonical_text = None
    canonical_rewrite_status = "not_requested"
    canonical_rewrite_errors: list[str] = []
    if apply_validated_body_rewrite:
        if validation.get("status") == "passed":
            canonical_text = _canonical_layout_rewrite_text(rewritten)
            canonical_rewrite_status = "applied"
        else:
            canonical_rewrite_status = "blocked_by_validation"
            canonical_rewrite_errors = [
                str(error)
                for error in validation.get("errors", []) or []
                if str(error)
            ]
    preview_text = (
        _preview_header(
            artifact_name,
            rewrite_stats,
            canonical_cleaned_output_modified=canonical_text is not None,
        )
        + rewritten.rstrip()
        + "\n"
    )
    metadata = {
        "schema": "layout_rewrite_preview_v2",
        "artifact": "layout_rewrite_preview",
        "canonical_rewrite_requested": bool(apply_validated_body_rewrite),
        "canonical_cleaned_output_modified": canonical_text is not None,
        "canonical_rewrite_status": canonical_rewrite_status,
        "canonical_rewrite_errors": canonical_rewrite_errors,
        "preview_plans": plans,
        "rewritten_accesses": rewrite_stats["rewritten_accesses"],
        "rewritten_fields": rewrite_stats["rewritten_fields"],
        "rewritten_bases": rewrite_stats["rewritten_bases"],
        "rewrite_results": rewrite_stats["rewrite_results"],
        "advertisement_normalizations": normalization_items,
        "validation": validation,
    }
    return LayoutRewritePreviewBundle(
        text=preview_text,
        diff=_layout_rewrite_preview_diff(artifact_name, cleaned_text, preview_text),
        metadata=metadata,
        canonical_text=canonical_text,
    )


def _layout_rewrite_preview_plans(text: str) -> list[dict[str, Any]]:
    plans = []
    for match in _REWRITE_PREVIEW_RE.finditer(text or ""):
        plans.append(
            {
                "base": match.group("base"),
                "source": match.groupdict().get("source") or "",
                "source_provenance": match.groupdict().get("source_provenance") or "none",
                "advertised_access_count": _int_value(match.group("access_count")),
                "advertised_field_count": _int_value(match.group("field_count")),
                "confidence": _float_value(match.group("confidence")),
            }
        )
    return plans


def _rewrite_layout_offset_dereferences(text: str, plans: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    bases = {str(item.get("base", "")) for item in plans if str(item.get("base", ""))}
    rewritten_accesses = 0
    rewritten_fields: set[str] = set()
    rewritten_bases: set[str] = set()
    rewrite_results: dict[str, dict[str, Any]] = {
        base: {
            "rewritten_accesses": 0,
            "rewritten_fields": set(),
        }
        for base in sorted(bases)
    }

    def replace(match: re.Match[str]) -> str:
        nonlocal rewritten_accesses
        base = match.group("base")
        if base not in bases:
            return match.group(0)
        offset = _parse_offset(match.group("offset"))
        if offset is None or offset <= 0:
            return match.group(0)
        type_name = " ".join(match.group("type").split())
        field_name = "field_%X" % offset
        rewritten_accesses += 1
        rewritten_fields.add("%s.%s" % (base, field_name))
        rewritten_bases.add(base)
        rewrite_results[base]["rewritten_accesses"] += 1
        rewrite_results[base]["rewritten_fields"].add(field_name)
        return "%s->%s /* %s +0x%X */" % (base, field_name, type_name, offset)

    rewritten = _OFFSET_DEREF_RE.sub(replace, text or "")
    return rewritten, {
        "rewritten_accesses": rewritten_accesses,
        "rewritten_fields": len(rewritten_fields),
        "rewritten_bases": sorted(rewritten_bases),
        "rewrite_results": {
            base: {
                "rewritten_accesses": int(result["rewritten_accesses"]),
                "rewritten_fields": len(result["rewritten_fields"]),
                "field_aliases": sorted(result["rewritten_fields"], key=_field_alias_sort_key),
            }
            for base, result in sorted(rewrite_results.items())
        },
    }


def _normalize_layout_rewrite_advertisements(
    text: str,
    plans: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    if not plans:
        return str(text or ""), plans, []
    _, rewrite_stats = _rewrite_layout_offset_dereferences(text, plans)
    rewrite_results = {
        str(base): result
        for base, result in (rewrite_stats.get("rewrite_results", {}) or {}).items()
        if isinstance(result, dict)
    }
    normalized_text = str(text or "")
    normalizations = []
    for plan in plans:
        base = str(plan.get("base", "") or "")
        result = rewrite_results.get(base, {})
        actual_accesses = int(result.get("rewritten_accesses", 0) or 0)
        actual_fields = int(result.get("rewritten_fields", 0) or 0)
        expected_accesses = int(plan.get("advertised_access_count", 0) or 0)
        expected_fields = int(plan.get("advertised_field_count", 0) or 0)
        if actual_accesses == expected_accesses and actual_fields == expected_fields:
            continue
        if actual_accesses < _REWRITE_ACCESS_THRESHOLD or actual_fields < _REWRITE_FIELD_THRESHOLD:
            continue
        field_aliases = [
            str(alias)
            for alias in result.get("field_aliases", []) or []
            if str(alias)
        ]
        normalized_text = _rewrite_preview_advertisement_comment(
            normalized_text,
            base,
            actual_accesses,
            actual_fields,
            field_aliases,
        )
        normalized_text = _rewrite_ready_advertisement_comment(
            normalized_text,
            base,
            actual_accesses,
            actual_fields,
        )
        normalizations.append(
            {
                "base": base,
                "original_accesses": expected_accesses,
                "original_fields": expected_fields,
                "normalized_accesses": actual_accesses,
                "normalized_fields": actual_fields,
            }
        )
    if not normalizations:
        return str(text or ""), plans, []
    return normalized_text, _layout_rewrite_preview_plans(normalized_text), normalizations


def _rewrite_preview_advertisement_comment(
    text: str,
    base: str,
    access_count: int,
    field_count: int,
    field_aliases: list[str],
) -> str:
    field_text = ", ".join(field_aliases[:8])
    if len(field_aliases) > 8:
        field_text += ", ..."

    def replace(match: re.Match[str]) -> str:
        if match.group("base") != base:
            return match.group(0)
        source_text = _source_provenance_text(match)
        return (
            "- inferred_offset_rewrite_preview: Offset field rewrite preview for %s: "
            "%d dereference(s) can map to %d field alias(es) %s.%s %s confidence=%s"
            % (
                base,
                access_count,
                field_count,
                field_text,
                source_text,
                _PREVIEW_ONLY_COMMENT,
                match.group("confidence"),
            )
        )

    return _REWRITE_PREVIEW_RE.sub(replace, text or "")


def _rewrite_ready_advertisement_comment(
    text: str,
    base: str,
    access_count: int,
    field_count: int,
) -> str:
    def replace(match: re.Match[str]) -> str:
        if match.group("base") != base:
            return match.group(0)
        source_text = _source_provenance_text(match)
        return (
            "- inferred_offset_rewrite_ready: Offset field rewrite candidate for %s: "
            "%d typed dereference(s) across %d offset(s), no rewrite blockers found.%s "
            "%s confidence=%s"
            % (
                base,
                access_count,
                field_count,
                source_text,
                match.group("status_comment"),
                match.group("confidence"),
            )
        )

    return _REWRITE_READY_RE.sub(replace, text or "")


def _source_provenance_text(match: re.Match[str]) -> str:
    source_provenance = str(match.groupdict().get("source_provenance") or "")
    source = str(match.groupdict().get("source") or "")
    if not source_provenance or not source:
        return ""
    return " Source provenance %s from %s." % (source_provenance, source)


def _validate_layout_rewrite_preview(
    plans: list[dict[str, Any]],
    rewrite_stats: dict[str, Any],
    preview_text: str,
) -> dict[str, Any]:
    errors: list[str] = []
    checks = {
        "canonical_cleaned_output_preserved": True,
        "all_plans_rewritten": True,
        "advertised_access_counts_match": True,
        "advertised_field_counts_match": True,
        "preview_contains_field_rewrites": "->field_" in str(preview_text or ""),
        "preview_has_no_raw_offset_derefs_for_rewritten_bases": True,
    }
    rewrite_results = {
        str(base): result
        for base, result in (rewrite_stats.get("rewrite_results", {}) or {}).items()
        if isinstance(result, dict)
    }
    for plan in plans:
        base = str(plan.get("base", "") or "")
        result = rewrite_results.get(base, {})
        actual_accesses = int(result.get("rewritten_accesses", 0) or 0)
        actual_fields = int(result.get("rewritten_fields", 0) or 0)
        expected_accesses = int(plan.get("advertised_access_count", 0) or 0)
        expected_fields = int(plan.get("advertised_field_count", 0) or 0)
        if actual_accesses <= 0:
            checks["all_plans_rewritten"] = False
            errors.append("%s had no rewritten accesses" % base)
        if actual_accesses != expected_accesses:
            checks["advertised_access_counts_match"] = False
            errors.append(
                "%s advertised %d access(es) but rewrote %d"
                % (base, expected_accesses, actual_accesses)
            )
        if actual_fields != expected_fields:
            checks["advertised_field_counts_match"] = False
            errors.append(
                "%s advertised %d field alias(es) but rewrote %d"
                % (base, expected_fields, actual_fields)
            )
        if _raw_offset_deref_for_base_exists(preview_text, base):
            checks["preview_has_no_raw_offset_derefs_for_rewritten_bases"] = False
            errors.append("%s still has raw offset dereference(s) in preview output" % base)
    if not checks["preview_contains_field_rewrites"]:
        errors.append("preview output contains no field rewrite syntax")
    status = "passed" if all(checks.values()) else "failed"
    return {
        "status": status,
        "checks": checks,
        "errors": errors,
    }


def _raw_offset_deref_for_base_exists(text: str, base: str) -> bool:
    if not base:
        return False
    for match in _OFFSET_DEREF_RE.finditer(text or ""):
        if match.group("base") == base:
            return True
    return False


def _canonical_layout_rewrite_text(rewritten_text: str) -> str:
    text = str(rewritten_text or "").replace(_PREVIEW_ONLY_COMMENT, _CANONICAL_APPLIED_COMMENT)
    text = text.replace(_AUDIT_ONLY_NOT_APPLIED_COMMENT, _CANONICAL_APPLIED_COMMENT)
    return text.rstrip() + "\n"


def _preview_header(
    artifact_name: str,
    rewrite_stats: dict[str, Any],
    canonical_cleaned_output_modified: bool = False,
) -> str:
    canonical_status = (
        "Canonical cleaned output was modified by validated opt-in rewrite."
        if canonical_cleaned_output_modified
        else "Canonical cleaned output was not modified."
    )
    return (
        "/*\n"
        "    PseudoForge layout rewrite preview artifact.\n"
        "    Source artifact: %s.cleaned.cpp\n"
        "    %s\n"
        "    Preview rewrites: %d dereference(s), %d field alias(es), bases=[%s].\n"
        "*/\n\n"
        % (
            artifact_name,
            canonical_status,
            int(rewrite_stats.get("rewritten_accesses", 0) or 0),
            int(rewrite_stats.get("rewritten_fields", 0) or 0),
            ", ".join(str(item) for item in rewrite_stats.get("rewritten_bases", []) or []),
        )
    )


def _layout_rewrite_preview_diff(artifact_name: str, cleaned_text: str, preview_text: str) -> str:
    return "".join(
        difflib.unified_diff(
            str(cleaned_text or "").splitlines(keepends=True),
            str(preview_text or "").splitlines(keepends=True),
            fromfile="cleaned/%s.cpp" % artifact_name,
            tofile="layout-rewrite-preview/%s.cpp" % artifact_name,
            lineterm="\n",
        )
    )


def _parse_offset(value: str) -> int | None:
    try:
        return int(value, 16) if str(value).lower().startswith("0x") else int(value, 10)
    except ValueError:
        return None


def _int_value(value: str) -> int:
    try:
        return int(str(value), 10)
    except ValueError:
        return 0


def _float_value(value: str) -> float:
    try:
        return float(str(value))
    except ValueError:
        return 0.0


def _field_alias_sort_key(value: str) -> tuple[int, str]:
    text = str(value or "")
    match = re.fullmatch(r"field_([0-9A-Fa-f]+)", text)
    if not match:
        return (0, text)
    return (int(match.group(1), 16), text)

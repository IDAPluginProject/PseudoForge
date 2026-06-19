from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ida_pseudoforge.core.normalize import (
    extract_function_name,
    extract_function_signature,
    extract_parameters_from_signature,
)
from ida_pseudoforge.profiles.loader import load_json_profile


PROFILE_NAME = "domain_identity.json"

MODE_REPORT_ONLY = "report-only"
MODE_PREVIEW_REWRITE = "preview-rewrite"
MODE_CANONICAL_REWRITE_ELIGIBLE = "canonical-rewrite-eligible"
VALID_MODES = {
    MODE_REPORT_ONLY,
    MODE_PREVIEW_REWRITE,
    MODE_CANONICAL_REWRITE_ELIGIBLE,
}


@dataclass(frozen=True, slots=True)
class DomainIdentityField:
    offset: int
    name: str
    type_text: str
    size: int
    confidence: float
    note: str = ""


@dataclass(frozen=True, slots=True)
class DomainIdentityMatch:
    profile_id: str
    base: str
    role: str
    structure: str
    mode: str
    effective_mode: str
    confidence: float
    parameter_index: int
    parameter_name: str
    fields: tuple[DomainIdentityField, ...]
    match_reason: str
    forced_report_only_reasons: tuple[str, ...] = ()
    ambiguous_profile_ids: tuple[str, ...] = ()

    @property
    def ambiguous(self) -> bool:
        return bool(self.ambiguous_profile_ids)

    def field_for_offset(self, offset: int) -> DomainIdentityField | None:
        for field in self.fields:
            if field.offset == offset:
                return field
        return None


@dataclass(frozen=True, slots=True)
class DomainIdentityParameterRename:
    profile_id: str
    old: str
    new: str
    parameter_index: int
    role: str
    structure: str
    confidence: float
    evidence: str


def domain_identity_match_for_base(
    text: str,
    base: str,
    non_identity_blockers: list[str] | None = None,
) -> DomainIdentityMatch | None:
    if not domain_identity_profiles_available():
        return None
    base_name = str(base or "").strip()
    if not base_name:
        return None
    matches = [
        match
        for match in _candidate_matches(text, base_name, non_identity_blockers or [])
        if match.base == base_name
    ]
    if not matches:
        return None
    matches.sort(key=lambda item: item.profile_id)
    if len(matches) == 1:
        return matches[0]
    profile_ids = tuple(item.profile_id for item in matches)
    first = matches[0]
    return DomainIdentityMatch(
        profile_id="ambiguous",
        base=base_name,
        role=first.role,
        structure=first.structure,
        mode=MODE_REPORT_ONLY,
        effective_mode=MODE_REPORT_ONLY,
        confidence=min(0.54, first.confidence),
        parameter_index=first.parameter_index,
        parameter_name=first.parameter_name,
        fields=(),
        match_reason="ambiguous profile match",
        forced_report_only_reasons=("ambiguous_profile_match",),
        ambiguous_profile_ids=profile_ids,
    )


def domain_identity_matches(
    text: str,
    bases: list[str] | set[str] | tuple[str, ...],
    non_identity_blockers_by_base: dict[str, list[str]] | None = None,
) -> dict[str, DomainIdentityMatch]:
    if not domain_identity_profiles_available():
        return {}
    result: dict[str, DomainIdentityMatch] = {}
    blockers_by_base = non_identity_blockers_by_base or {}
    for base in sorted({str(item or "").strip() for item in bases if str(item or "").strip()}):
        match = domain_identity_match_for_base(
            text,
            base,
            non_identity_blockers=blockers_by_base.get(base, []),
        )
        if match:
            result[base] = match
    return result


def domain_identity_profiles_available() -> bool:
    return bool(_domain_identity_profiles())


def domain_identity_parameter_renames(text: str) -> list[DomainIdentityParameterRename]:
    if not domain_identity_profiles_available():
        return []
    signature = extract_function_signature(text or "")
    function_name = extract_function_name(signature)
    full_name = _extract_full_function_name(signature)
    parameters = extract_parameters_from_signature(signature)
    candidates: list[DomainIdentityParameterRename] = []
    for profile in _domain_identity_profiles():
        if not _function_matches(profile, function_name, full_name, signature):
            continue
        if not _profile_parameter_shape_matches(profile, parameters):
            continue
        profile_id = _profile_id(profile)
        for parameter in _profile_parameters(profile):
            rename = _parameter_rename(profile_id, parameter, parameters)
            if rename:
                candidates.append(rename)
    return _dedupe_parameter_renames(candidates)


def _candidate_matches(
    text: str,
    base: str,
    non_identity_blockers: list[str],
) -> list[DomainIdentityMatch]:
    signature = extract_function_signature(text or "")
    function_name = extract_function_name(signature)
    full_name = _extract_full_function_name(signature)
    parameters = extract_parameters_from_signature(signature)
    result: list[DomainIdentityMatch] = []
    for profile in _domain_identity_profiles():
        if not _function_matches(profile, function_name, full_name, signature):
            continue
        for parameter in _profile_parameters(profile):
            match = _parameter_match(profile, parameter, base, parameters, non_identity_blockers)
            if match:
                result.append(match)
    return result


def _domain_identity_profiles() -> tuple[dict[str, Any], ...]:
    payload = load_json_profile(PROFILE_NAME)
    if not isinstance(payload, dict):
        return ()
    profiles = payload.get("profiles", [])
    if not isinstance(profiles, list):
        return ()
    return tuple(item for item in profiles if isinstance(item, dict))


def _profile_parameter_shape_matches(profile: dict[str, Any], parameters: list[tuple[str, str]]) -> bool:
    expected_count = _int_value(profile.get("parameter_count", profile.get("expected_parameter_count")), -1)
    if expected_count >= 0 and expected_count != len(parameters):
        return False
    return True


def _function_matches(profile: dict[str, Any], function_name: str, full_name: str, signature: str) -> bool:
    names = _string_list(profile.get("function_names"))
    if names and function_name in names:
        return True
    demangled_names = _string_list(profile.get("demangled_names"))
    if demangled_names and (full_name in demangled_names or signature in demangled_names):
        return True
    for pattern in _string_list(profile.get("function_regex")):
        if _safe_regex_search(pattern, function_name) or _safe_regex_search(pattern, full_name):
            return True
    for pattern in _string_list(profile.get("demangled_regex")):
        if _safe_regex_search(pattern, full_name) or _safe_regex_search(pattern, signature):
            return True
    return False


def _profile_parameters(profile: dict[str, Any]) -> list[dict[str, Any]]:
    parameters = profile.get("parameters", [])
    if isinstance(parameters, list):
        return [item for item in parameters if isinstance(item, dict)]
    if isinstance(parameters, dict):
        return [parameters]
    return []


def _parameter_rename(
    profile_id: str,
    parameter: dict[str, Any],
    parameters: list[tuple[str, str]],
) -> DomainIdentityParameterRename | None:
    parameter_index = _int_value(parameter.get("parameter_index", parameter.get("index")), -1)
    if parameter_index < 0 or parameter_index >= len(parameters):
        return None
    old_name, type_text = parameters[parameter_index]
    if not _parameter_type_matches(parameter, type_text):
        return None
    new_name = _safe_identifier_text(parameter.get("rename_to"), "")
    if not new_name or new_name == old_name:
        return None
    role = _safe_identifier_text(parameter.get("role"), new_name)
    structure = _safe_identifier_text(parameter.get("structure"), "DOMAIN_STRUCTURE")
    confidence = _float_value(parameter.get("rename_confidence", parameter.get("confidence")), 0.88)
    confidence = round(max(0.0, min(0.98, confidence)), 2)
    return DomainIdentityParameterRename(
        profile_id=profile_id,
        old=old_name,
        new=new_name,
        parameter_index=parameter_index,
        role=role,
        structure=structure,
        confidence=confidence,
        evidence=(
            "Domain identity profile %s parameter %d identifies %s %s"
            % (profile_id, parameter_index, role, structure)
        ),
    )


def _parameter_type_matches(parameter: dict[str, Any], type_text: str) -> bool:
    accepted_types = _string_list(parameter.get("accepted_types"))
    if not accepted_types:
        return True
    actual = _normalize_type_shape(type_text)
    if not actual:
        return False
    return any(_normalize_type_shape(item) == actual for item in accepted_types)


def _normalize_type_shape(type_text: str) -> str:
    return re.sub(r"\s+", " ", str(type_text or "").strip()).lower()


def _dedupe_parameter_renames(
    candidates: list[DomainIdentityParameterRename],
) -> list[DomainIdentityParameterRename]:
    selected: dict[str, DomainIdentityParameterRename] = {}
    conflicts: set[str] = set()
    for item in sorted(candidates, key=lambda rename: (rename.old, rename.profile_id, rename.new)):
        current = selected.get(item.old)
        if current is None:
            selected[item.old] = item
            continue
        if current.new != item.new:
            conflicts.add(item.old)
            continue
        if item.confidence > current.confidence:
            selected[item.old] = item
    return [
        item
        for old, item in sorted(selected.items(), key=lambda pair: pair[1].parameter_index)
        if old not in conflicts
    ]


def _parameter_match(
    profile: dict[str, Any],
    parameter: dict[str, Any],
    base: str,
    parameters: list[tuple[str, str]],
    non_identity_blockers: list[str],
) -> DomainIdentityMatch | None:
    parameter_index = _int_value(parameter.get("parameter_index", parameter.get("index")), -1)
    parameter_name = str(parameter.get("parameter_name", parameter.get("name", "")) or "").strip()
    base_names = set(_string_list(parameter.get("base_names")))
    if parameter_name:
        base_names.add(parameter_name)
    if 0 <= parameter_index < len(parameters):
        base_names.add(parameters[parameter_index][0])
    if not base_names or base not in base_names:
        return None

    role = _safe_identifier_text(parameter.get("role"), "domainRole")
    structure = _safe_identifier_text(parameter.get("structure"), "DOMAIN_STRUCTURE")
    mode = _mode_value(parameter.get("mode"))
    effective_mode, forced_reasons = _effective_mode(
        mode,
        _string_list(parameter.get("force_report_only_on")),
        non_identity_blockers,
    )
    profile_id = _profile_id(profile)
    fields = tuple(_profile_fields(parameter.get("fields", [])))
    confidence = min(
        _float_value(parameter.get("confidence"), 0.72),
        _mode_confidence_cap(effective_mode),
    )
    if parameter_index < 0:
        parameter_index = _parameter_index_for_name(parameters, base)
    if not parameter_name and 0 <= parameter_index < len(parameters):
        parameter_name = parameters[parameter_index][0]
    return DomainIdentityMatch(
        profile_id=profile_id,
        base=base,
        role=role,
        structure=structure,
        mode=mode,
        effective_mode=effective_mode,
        confidence=round(confidence, 2),
        parameter_index=parameter_index,
        parameter_name=parameter_name or base,
        fields=fields,
        match_reason=_match_reason(profile_id, parameter_index, parameter_name or base),
        forced_report_only_reasons=tuple(forced_reasons),
    )


def _profile_fields(value: Any) -> list[DomainIdentityField]:
    if not isinstance(value, list):
        return []
    result: list[DomainIdentityField] = []
    seen_offsets: set[int] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        offset = _offset_value(item.get("offset"))
        if offset is None or offset < 0 or offset in seen_offsets:
            continue
        name = _safe_identifier_text(item.get("name"), "field_%X" % offset)
        type_text = _safe_type_text(item.get("type", item.get("type_text", "unknown")))
        size = _int_value(item.get("size"), 0)
        confidence = _float_value(item.get("confidence"), 0.72)
        seen_offsets.add(offset)
        result.append(
            DomainIdentityField(
                offset=offset,
                name=name,
                type_text=type_text,
                size=max(0, size),
                confidence=round(max(0.0, min(1.0, confidence)), 2),
                note=_safe_note_text(item.get("note", "")),
            )
        )
    result.sort(key=lambda field: field.offset)
    return result


def _effective_mode(
    mode: str,
    force_report_only_on: list[str],
    non_identity_blockers: list[str],
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    categories = _blocker_categories(non_identity_blockers)
    for item in force_report_only_on:
        category = str(item or "").strip().lower().replace("-", "_")
        if category and category in categories:
            reasons.append(category)
    if reasons:
        return MODE_REPORT_ONLY, list(dict.fromkeys(reasons))
    return mode, []


def _blocker_categories(blockers: list[str]) -> set[str]:
    categories: set[str] = set()
    for blocker in blockers:
        lowered = str(blocker or "").lower()
        if "overlay" in lowered or "subfield" in lowered or "field access widths" in lowered:
            categories.add("overlay")
        if "incompatible access type" in lowered:
            categories.add("type_conflict")
        if "threshold" in lowered:
            categories.add("threshold")
        if "unaligned" in lowered or "not naturally aligned" in lowered:
            categories.add("unaligned")
        if "volatile" in lowered:
            categories.add("volatile")
        if "assignment" in lowered or "initializer" in lowered or "reassigned" in lowered:
            categories.add("base_stability")
        if "address is taken" in lowered or "indexed like an array" in lowered:
            categories.add("base_escape")
    return categories


def _mode_value(value: Any) -> str:
    mode = str(value or MODE_REPORT_ONLY).strip().lower().replace("_", "-")
    if mode in VALID_MODES:
        return mode
    return MODE_REPORT_ONLY


def _mode_confidence_cap(mode: str) -> float:
    if mode == MODE_CANONICAL_REWRITE_ELIGIBLE:
        return 0.86
    if mode == MODE_PREVIEW_REWRITE:
        return 0.80
    return 0.74


def _profile_id(profile: dict[str, Any]) -> str:
    value = str(profile.get("id", profile.get("name", "")) or "").strip()
    return value or "domain_identity_profile"


def _match_reason(profile_id: str, parameter_index: int, parameter_name: str) -> str:
    if parameter_index >= 0:
        return "profile %s parameter %d (%s)" % (profile_id, parameter_index, parameter_name)
    return "profile %s parameter %s" % (profile_id, parameter_name)


def _parameter_index_for_name(parameters: list[tuple[str, str]], name: str) -> int:
    for index, (parameter_name, _type_text) in enumerate(parameters):
        if parameter_name == name:
            return index
    return -1


def _extract_full_function_name(signature: str) -> str:
    match = re.search(r"([A-Za-z_?@$][A-Za-z0-9_:~<>?@$]*)\s*\(", signature or "")
    if not match:
        return ""
    return match.group(1)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = [str(item) for item in value if str(item)]
    else:
        values = []
    return [item.strip() for item in values if item.strip()]


def _safe_regex_search(pattern: str, text: str) -> bool:
    if not pattern or not text:
        return False
    try:
        return re.search(pattern, text) is not None
    except re.error:
        return False


def _offset_value(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _int_value(value: Any, default: int) -> int:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def _float_value(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_identifier_text(value: Any, default: str) -> str:
    text = str(value or "").strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
        return text
    return default


def _safe_type_text(value: Any) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return "unknown"
    if len(text) > 64:
        return "unknown"
    if re.search(r"[^A-Za-z0-9_\s\*\:]", text):
        return "unknown"
    return text


def _safe_note_text(value: Any) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    if len(text) > 180:
        text = text[:180].rstrip()
    return text.encode("ascii", "ignore").decode("ascii")

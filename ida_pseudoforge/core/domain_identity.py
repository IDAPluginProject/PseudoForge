from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ida_pseudoforge.core.normalize import (
    extract_calls,
    extract_function_name,
    extract_function_signature,
    extract_parameters_from_signature,
)
from ida_pseudoforge.core.plan_schema import FunctionIdentityCandidate, ParameterTypeCorrection
from ida_pseudoforge.profiles import loader as profile_loader


PROFILE_NAME = "domain_identity.json"
PROFILE_PACK_DIR = "domain_identity"

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
    source: str = ""
    provenance: str = ""
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
    profile_source: str = ""
    profile_version: str = ""
    profile_metadata: tuple[tuple[str, str], ...] = ()
    suppress_layout_inference: bool = False

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


@dataclass(frozen=True, slots=True)
class DomainIdentityPrototypeParameter:
    parameter_index: int
    canonical_name: str
    canonical_type: str
    display_type: str
    accepted_types: tuple[str, ...]
    semantic_role: str
    apply_to_preview: bool
    apply_to_idb: bool


@dataclass(frozen=True, slots=True)
class DomainIdentityPrototype:
    profile_id: str
    function_name: str
    return_type: str
    calling_convention: str
    parameters: tuple[DomainIdentityPrototypeParameter, ...]
    signature_preview: bool
    body_canonical_rewrite: bool
    apply_to_idb_default: bool
    blockers: tuple[str, ...] = ()


def domain_identity_match_for_base(
    text: str,
    base: str,
    non_identity_blockers: list[str] | None = None,
    profile_context: dict[str, Any] | None = None,
) -> DomainIdentityMatch | None:
    if not domain_identity_profiles_available():
        return None
    base_name = str(base or "").strip()
    if not base_name:
        return None
    matches = [
        match
        for match in _candidate_matches(text, base_name, non_identity_blockers or [], profile_context)
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
        profile_source=first.profile_source,
        profile_version=first.profile_version,
        profile_metadata=first.profile_metadata,
        suppress_layout_inference=all(item.suppress_layout_inference for item in matches),
    )


def domain_identity_matches(
    text: str,
    bases: list[str] | set[str] | tuple[str, ...],
    non_identity_blockers_by_base: dict[str, list[str]] | None = None,
    profile_context: dict[str, Any] | None = None,
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
            profile_context=profile_context,
        )
        if match:
            result[base] = match
    return result


def domain_identity_role_matches(
    text: str,
    profile_context: dict[str, Any] | None = None,
) -> list[DomainIdentityMatch]:
    if not domain_identity_profiles_available():
        return []
    signature = extract_function_signature(text or "")
    function_name = extract_function_name(signature)
    full_name = _extract_full_function_name(signature)
    parameters = extract_parameters_from_signature(signature)
    matches: list[DomainIdentityMatch] = []
    for profile in _domain_identity_profiles():
        if not _function_matches(profile, function_name, full_name, signature, text or ""):
            continue
        profile_blockers = _profile_context_blockers(profile, profile_context)
        for parameter in _profile_parameters(profile):
            for base in _parameter_role_bases(parameter, parameters, text or ""):
                match = _parameter_match(
                    profile,
                    parameter,
                    base,
                    parameters,
                    [],
                    profile_blockers,
                )
                if match:
                    matches.append(match)
    return _dedupe_role_matches(matches)


def domain_identity_profiles_available() -> bool:
    return bool(_domain_identity_profiles())


def domain_identity_function_prototypes(
    text: str,
    profile_context: dict[str, Any] | None = None,
) -> list[DomainIdentityPrototype]:
    if not domain_identity_profiles_available():
        return []
    signature = extract_function_signature(text or "")
    function_name = extract_function_name(signature)
    full_name = _extract_full_function_name(signature)
    parameters = extract_parameters_from_signature(signature)
    result: list[DomainIdentityPrototype] = []
    for profile in _domain_identity_profiles():
        if not _function_matches(profile, function_name, full_name, signature, text or ""):
            continue
        if not _profile_parameter_shape_matches(profile, parameters):
            continue
        prototype = _domain_identity_prototype(
            profile,
            function_name or full_name,
            _profile_context_blockers(profile, profile_context),
        )
        if prototype:
            result.append(prototype)
    result.sort(key=lambda item: item.profile_id)
    return result


def domain_identity_function_identity_candidates(
    text: str,
    profile_context: dict[str, Any] | None = None,
) -> list[FunctionIdentityCandidate]:
    if not domain_identity_profiles_available():
        return []
    signature = extract_function_signature(text or "")
    function_name = extract_function_name(signature)
    full_name = _extract_full_function_name(signature)
    parameters = extract_parameters_from_signature(signature)
    candidates: list[FunctionIdentityCandidate] = []
    for profile in _domain_identity_profiles():
        if not _profile_parameter_shape_matches(profile, parameters):
            continue
        candidate = _function_identity_candidate(
            profile,
            function_name,
            full_name,
            signature,
            text or "",
            profile_context,
        )
        if candidate:
            candidates.append(candidate)
    return _dedupe_function_identity_candidates(candidates)


def domain_identity_parameter_renames(
    text: str,
    profile_context: dict[str, Any] | None = None,
) -> list[DomainIdentityParameterRename]:
    if not domain_identity_profiles_available():
        return []
    signature = extract_function_signature(text or "")
    function_name = extract_function_name(signature)
    full_name = _extract_full_function_name(signature)
    parameters = extract_parameters_from_signature(signature)
    candidates: list[DomainIdentityParameterRename] = []
    for profile in _domain_identity_profiles():
        if not _function_matches(profile, function_name, full_name, signature, text or ""):
            continue
        if _profile_context_blockers(profile, profile_context):
            continue
        if not _profile_parameter_shape_matches(profile, parameters):
            continue
        profile_id = _profile_id(profile)
        for parameter in _profile_parameters(profile):
            rename = _parameter_rename(profile_id, parameter, parameters)
            if rename:
                candidates.append(rename)
    return _dedupe_parameter_renames(candidates)


def domain_identity_parameter_type_corrections(
    text: str,
    profile_context: dict[str, Any] | None = None,
) -> list[ParameterTypeCorrection]:
    if not domain_identity_profiles_available():
        return []
    signature = extract_function_signature(text or "")
    function_name = extract_function_name(signature)
    full_name = _extract_full_function_name(signature)
    parameters = extract_parameters_from_signature(signature)
    candidates: list[ParameterTypeCorrection] = []
    identity_blockers_by_profile = _function_identity_blockers_by_profile(
        text or "",
        profile_context,
    )
    for profile in _domain_identity_profiles():
        if not _function_matches(profile, function_name, full_name, signature, text or ""):
            continue
        if not _profile_parameter_shape_matches(profile, parameters):
            continue
        profile_blockers = _profile_context_blockers(profile, profile_context)
        profile_blockers.extend(identity_blockers_by_profile.get(_profile_id(profile), []))
        for parameter in _profile_type_parameters(profile):
            correction = _parameter_type_correction(
                profile,
                parameter,
                parameters,
                profile_blockers,
            )
            if correction:
                candidates.append(correction)
    return _dedupe_parameter_type_corrections(candidates)


def _function_identity_blockers_by_profile(
    text: str,
    profile_context: dict[str, Any] | None,
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for candidate in domain_identity_function_identity_candidates(text, profile_context=profile_context):
        if candidate.profile_id == "ambiguous":
            continue
        blockers = [
            blocker
            for blocker in candidate.blockers
            if blocker != "report_only_profile"
        ]
        if blockers:
            result.setdefault(candidate.profile_id, [])
            result[candidate.profile_id].extend(blockers)
    return {
        profile_id: list(dict.fromkeys(blockers))
        for profile_id, blockers in result.items()
    }


def _candidate_matches(
    text: str,
    base: str,
    non_identity_blockers: list[str],
    profile_context: dict[str, Any] | None,
) -> list[DomainIdentityMatch]:
    signature = extract_function_signature(text or "")
    function_name = extract_function_name(signature)
    full_name = _extract_full_function_name(signature)
    parameters = extract_parameters_from_signature(signature)
    result: list[DomainIdentityMatch] = []
    for profile in _domain_identity_profiles():
        if not _function_matches(profile, function_name, full_name, signature, text or ""):
            continue
        profile_blockers = _profile_context_blockers(profile, profile_context)
        for parameter in _profile_parameters(profile):
            match = _parameter_match(
                profile,
                parameter,
                base,
                parameters,
                non_identity_blockers,
                profile_blockers,
            )
            if match:
                result.append(match)
    return result


def _domain_identity_profiles() -> tuple[dict[str, Any], ...]:
    result: list[dict[str, Any]] = []
    for name in _domain_identity_profile_names():
        payload = profile_loader.load_json_profile(name)
        result.extend(_profiles_from_payload(payload, name))
    return tuple(result)


def _domain_identity_profile_names() -> list[str]:
    root = Path(profile_loader.active_profile_root())
    names: list[str] = []
    if (root / PROFILE_NAME).exists():
        names.append(PROFILE_NAME)
    pack_root = root / PROFILE_PACK_DIR
    if pack_root.exists():
        for path in sorted(pack_root.glob("*.json")):
            names.append("%s/%s" % (PROFILE_PACK_DIR, path.name))
    if not names:
        names.append(PROFILE_NAME)
    return names


def _profiles_from_payload(payload: Any, profile_name: str) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    pack_metadata = _pack_metadata(payload, profile_name)
    profiles = payload.get("profiles", [])
    if not isinstance(profiles, list) and _looks_like_profile(payload):
        profiles = [payload]
    if not isinstance(profiles, list):
        return []
    result = []
    for item in profiles:
        if not isinstance(item, dict):
            continue
        profile = dict(item)
        profile["_pack_metadata"] = dict(pack_metadata)
        profile["_pack_name"] = profile_name
        result.append(profile)
    return result


def _looks_like_profile(payload: dict[str, Any]) -> bool:
    return bool(payload.get("id") or payload.get("name")) and bool(payload.get("parameters"))


def _pack_metadata(payload: dict[str, Any], profile_name: str) -> dict[str, str]:
    metadata: dict[str, str] = {"profile_name": profile_name}
    for section_name in ("metadata", "target"):
        section = payload.get(section_name)
        if isinstance(section, dict):
            metadata.update(_metadata_items(section))
    for key in ("schema", "profile_version", "version", "image", "image_name", "arch", "architecture", "build", "build_number"):
        if key in payload and not isinstance(payload.get(key), (dict, list)):
            metadata[key] = str(payload.get(key) or "").strip()
    return {key: value for key, value in metadata.items() if value}


def _profile_parameter_shape_matches(profile: dict[str, Any], parameters: list[tuple[str, str]]) -> bool:
    expected_count = _int_value(profile.get("parameter_count", profile.get("expected_parameter_count")), -1)
    if expected_count >= 0 and expected_count != len(parameters):
        return False
    return True


def _function_matches(
    profile: dict[str, Any],
    function_name: str,
    full_name: str,
    signature: str,
    text: str = "",
) -> bool:
    matched = False
    names = _string_list(profile.get("function_names"))
    if names and function_name in names:
        matched = True
    demangled_names = _string_list(profile.get("demangled_names"))
    if demangled_names and (full_name in demangled_names or signature in demangled_names):
        matched = True
    if not matched:
        for pattern in _string_list(profile.get("function_regex")):
            if _safe_regex_search(pattern, function_name) or _safe_regex_search(pattern, full_name):
                matched = True
                break
    if not matched:
        for pattern in _string_list(profile.get("demangled_regex")):
            if _safe_regex_search(pattern, full_name) or _safe_regex_search(pattern, signature):
                matched = True
                break
    if not matched:
        if not _body_identity_match_allowed(profile):
            return False
        if not _has_body_hints(profile):
            return False
    if not matched and not _body_hints_match(profile, text):
        return False
    if matched and not _body_hints_match(profile, text):
        return False
    return _callee_hints_match(profile, text)


def _function_identity_candidate(
    profile: dict[str, Any],
    function_name: str,
    full_name: str,
    signature: str,
    text: str,
    profile_context: dict[str, Any] | None,
) -> FunctionIdentityCandidate | None:
    match_kind, evidence, match_blockers = _function_identity_match_evidence(
        profile,
        function_name,
        full_name,
        signature,
        text,
    )
    if not match_kind:
        return None
    blockers = list(match_blockers)
    blockers.extend(_profile_context_blockers(profile, profile_context))
    profile_report_only = _profile_is_report_only(profile)
    if profile_report_only and "report_only_profile" not in blockers:
        blockers.append("report_only_profile")
    effective_mode = MODE_REPORT_ONLY if blockers else _profile_active_identity_mode(profile)
    confidence = _function_identity_confidence(match_kind, effective_mode)
    return FunctionIdentityCandidate(
        profile_id=_profile_id(profile),
        subsystem=_profile_subsystem(profile),
        function_name=function_name or full_name,
        match_kind=match_kind,
        confidence=confidence,
        evidence=evidence,
        blockers=list(dict.fromkeys(blockers)),
        effective_mode=effective_mode,
        profile_source=_profile_source(profile),
        profile_version=_profile_version(profile),
    )


def _function_identity_match_evidence(
    profile: dict[str, Any],
    function_name: str,
    full_name: str,
    signature: str,
    text: str,
) -> tuple[str, list[str], list[str]]:
    evidence: list[str] = []
    match_kind = ""
    names = _string_list(profile.get("function_names"))
    if names and function_name in names:
        match_kind = "function_name"
        evidence.append("function_name")
    demangled_names = _string_list(profile.get("demangled_names"))
    if not match_kind and demangled_names and (full_name in demangled_names or signature in demangled_names):
        match_kind = "demangled_name"
        evidence.append("demangled_name")
    if not match_kind:
        for pattern in _string_list(profile.get("function_regex")):
            if _safe_regex_search(pattern, function_name) or _safe_regex_search(pattern, full_name):
                match_kind = "function_regex"
                evidence.append("function_regex")
                break
    if not match_kind:
        for pattern in _string_list(profile.get("demangled_regex")):
            if _safe_regex_search(pattern, full_name) or _safe_regex_search(pattern, signature):
                match_kind = "demangled_regex"
                evidence.append("demangled_regex")
                break

    body_hints = _has_body_hints(profile)
    body_matched = _body_hints_match(profile, text)
    if body_hints and body_matched:
        evidence.append("body_hints")
    if body_hints and not body_matched:
        return "", [], []

    callee_hints = _has_callee_hints(profile)
    if callee_hints and _callee_hints_match(profile, text):
        evidence.append("callee_hints")
    elif callee_hints:
        return "", [], []

    if match_kind:
        return match_kind, list(dict.fromkeys(evidence)), []

    if not body_hints or not body_matched:
        return "", [], []
    evidence.append("body_identity")
    if not _body_identity_match_allowed(profile):
        return "body_identity", list(dict.fromkeys(evidence)), ["body_identity_not_allowed"]
    return "body_identity", list(dict.fromkeys(evidence)), []


def _has_callee_hints(profile: dict[str, Any]) -> bool:
    return bool(
        _string_list(profile.get("callee_names"))
        or _string_list(profile.get("required_calls"))
        or _string_list(profile.get("required_callees"))
        or _string_list(profile.get("callee_regex"))
        or _string_list(profile.get("required_call_regex"))
        or _string_list(profile.get("required_callee_regex"))
    )


def _profile_is_report_only(profile: dict[str, Any]) -> bool:
    modes = [_mode_value(parameter.get("mode")) for parameter in _profile_parameters(profile)]
    if modes and all(mode == MODE_REPORT_ONLY for mode in modes):
        return True
    policy = _profile_rewrite_policy(profile)
    prototype_parameters = _prototype_parameter_dicts(profile)
    if prototype_parameters and not policy["signature_preview"] and not policy["body_canonical_rewrite"]:
        return True
    return False


def _profile_active_identity_mode(profile: dict[str, Any]) -> str:
    modes = [_mode_value(parameter.get("mode")) for parameter in _profile_parameters(profile)]
    if MODE_CANONICAL_REWRITE_ELIGIBLE in modes:
        return MODE_CANONICAL_REWRITE_ELIGIBLE
    if MODE_PREVIEW_REWRITE in modes:
        return MODE_PREVIEW_REWRITE
    policy = _profile_rewrite_policy(profile)
    if policy["signature_preview"]:
        return MODE_PREVIEW_REWRITE
    return MODE_REPORT_ONLY


def _function_identity_confidence(match_kind: str, effective_mode: str) -> float:
    base = {
        "function_name": 0.92,
        "demangled_name": 0.90,
        "function_regex": 0.82,
        "demangled_regex": 0.80,
        "body_identity": 0.66,
    }.get(match_kind, 0.60)
    return round(min(base, _mode_confidence_cap(effective_mode)), 2)


def _dedupe_function_identity_candidates(
    candidates: list[FunctionIdentityCandidate],
) -> list[FunctionIdentityCandidate]:
    candidates = sorted(candidates, key=lambda item: (item.profile_id, item.match_kind))
    active = [
        item
        for item in candidates
        if item.profile_id != "ambiguous"
        and not [blocker for blocker in item.blockers if blocker != "report_only_profile"]
    ]
    if len(active) <= 1:
        return candidates
    active_profile_ids = {item.profile_id for item in active}
    profile_ids = sorted({item.profile_id for item in active})
    first = active[0]
    ambiguous = FunctionIdentityCandidate(
        profile_id="ambiguous",
        subsystem=first.subsystem,
        function_name=first.function_name,
        match_kind="ambiguous",
        confidence=min(0.54, first.confidence),
        evidence=sorted({evidence for item in active for evidence in item.evidence}),
        blockers=["ambiguous_profile_match"],
        effective_mode=MODE_REPORT_ONLY,
        profile_source=first.profile_source,
        profile_version=first.profile_version,
        ambiguous_profile_ids=profile_ids,
    )
    blocked = [
        item
        for item in candidates
        if item.blockers and item.profile_id not in active_profile_ids
    ]
    return [ambiguous] + blocked


def _body_identity_match_allowed(profile: dict[str, Any]) -> bool:
    return _bool_value(
        profile.get(
            "allow_body_identity_match",
            profile.get("match_body_only", False),
        ),
        False,
    )


def _has_body_hints(profile: dict[str, Any]) -> bool:
    return bool(
        _string_list(profile.get("body_contains"))
        or _string_list(profile.get("required_body_contains"))
        or _string_list(profile.get("body_regex"))
        or _string_list(profile.get("required_body_regex"))
    )


def _body_hints_match(profile: dict[str, Any], text: str) -> bool:
    body_text = text or ""
    for literal in (
        _string_list(profile.get("body_contains"))
        + _string_list(profile.get("required_body_contains"))
    ):
        if literal not in body_text:
            return False
    for pattern in (
        _string_list(profile.get("body_regex"))
        + _string_list(profile.get("required_body_regex"))
    ):
        if not _safe_regex_search(pattern, body_text):
            return False
    return True


def _callee_hints_match(profile: dict[str, Any], text: str) -> bool:
    names = set(
        _string_list(profile.get("callee_names"))
        + _string_list(profile.get("required_calls"))
        + _string_list(profile.get("required_callees"))
    )
    regexes = (
        _string_list(profile.get("callee_regex"))
        + _string_list(profile.get("required_call_regex"))
        + _string_list(profile.get("required_callee_regex"))
    )
    if not names and not regexes:
        return True
    calls = set(extract_calls(text or ""))
    for name in names:
        if name not in calls and re.search(r"\b%s\s*\(" % re.escape(name), text or "") is None:
            return False
    for pattern in regexes:
        if not any(_safe_regex_search(pattern, call) for call in calls):
            if not _safe_regex_search(pattern, text or ""):
                return False
    return True


def _profile_parameters(profile: dict[str, Any]) -> list[dict[str, Any]]:
    parameters = profile.get("parameters", [])
    if isinstance(parameters, list):
        return [item for item in parameters if isinstance(item, dict)]
    if isinstance(parameters, dict):
        return [parameters]
    return []


def _profile_type_parameters(profile: dict[str, Any]) -> list[dict[str, Any]]:
    return _profile_parameters(profile) + _prototype_parameter_dicts(profile)


def _prototype_parameter_dicts(profile: dict[str, Any]) -> list[dict[str, Any]]:
    prototype = profile.get("prototype")
    if not isinstance(prototype, dict):
        return []
    parameters = prototype.get("parameters", [])
    if isinstance(parameters, dict):
        raw_parameters = [parameters]
    elif isinstance(parameters, list):
        raw_parameters = [item for item in parameters if isinstance(item, dict)]
    else:
        return []

    policy = _profile_rewrite_policy(profile)
    result: list[dict[str, Any]] = []
    for item in raw_parameters:
        parameter = dict(item)
        if "parameter_index" not in parameter and "index" in parameter:
            parameter["parameter_index"] = parameter["index"]
        if "role" not in parameter and "semantic_role" in parameter:
            parameter["role"] = parameter["semantic_role"]
        if "apply_to_preview" not in parameter:
            parameter["apply_to_preview"] = policy["signature_preview"]
        if "apply_to_idb" not in parameter:
            parameter["apply_to_idb"] = policy["apply_to_idb_default"]
        result.append(parameter)
    return result


def _domain_identity_prototype(
    profile: dict[str, Any],
    function_name: str,
    blockers: list[str],
) -> DomainIdentityPrototype | None:
    prototype = profile.get("prototype")
    if not isinstance(prototype, dict):
        return None
    parameters = tuple(
        item
        for item in (
            _domain_identity_prototype_parameter(parameter)
            for parameter in _prototype_parameter_dicts(profile)
        )
        if item is not None
    )
    return_type = _safe_type_correction_text(prototype.get("return_type", ""))
    calling_convention = _safe_calling_convention_text(prototype.get("calling_convention", ""))
    if not return_type and not calling_convention and not parameters:
        return None
    policy = _profile_rewrite_policy(profile)
    return DomainIdentityPrototype(
        profile_id=_profile_id(profile),
        function_name=function_name,
        return_type=return_type,
        calling_convention=calling_convention,
        parameters=parameters,
        signature_preview=policy["signature_preview"],
        body_canonical_rewrite=policy["body_canonical_rewrite"],
        apply_to_idb_default=policy["apply_to_idb_default"],
        blockers=tuple(dict.fromkeys(blockers)),
    )


def _domain_identity_prototype_parameter(
    parameter: dict[str, Any],
) -> DomainIdentityPrototypeParameter | None:
    parameter_index = _int_value(parameter.get("parameter_index", parameter.get("index")), -1)
    if parameter_index < 0:
        return None
    canonical_type = _safe_type_correction_text(parameter.get("canonical_type", ""))
    display_type = _safe_type_correction_text(parameter.get("display_type", ""))
    if not canonical_type and display_type:
        canonical_type = display_type
    return DomainIdentityPrototypeParameter(
        parameter_index=parameter_index,
        canonical_name=_safe_identifier_text(
            parameter.get("canonical_name", parameter.get("display_name", "")),
            "",
        ),
        canonical_type=canonical_type,
        display_type=display_type,
        accepted_types=tuple(_string_list(parameter.get("accepted_types"))),
        semantic_role=_safe_identifier_text(parameter.get("semantic_role", parameter.get("role", "")), ""),
        apply_to_preview=_bool_value(parameter.get("apply_to_preview"), True),
        apply_to_idb=_bool_value(parameter.get("apply_to_idb"), False),
    )


def _profile_rewrite_policy(profile: dict[str, Any]) -> dict[str, bool]:
    value = profile.get("rewrite_policy")
    policy = value if isinstance(value, dict) else {}
    return {
        "signature_preview": _bool_value(policy.get("signature_preview"), True),
        "body_canonical_rewrite": _bool_value(policy.get("body_canonical_rewrite"), False),
        "apply_to_idb_default": _bool_value(policy.get("apply_to_idb_default"), False),
    }


def _profile_apply_to_idb_default(profile: dict[str, Any]) -> bool:
    return _profile_rewrite_policy(profile)["apply_to_idb_default"]


def _parameter_role_bases(
    parameter: dict[str, Any],
    parameters: list[tuple[str, str]],
    text: str,
) -> list[str]:
    result: list[str] = []
    parameter_index = _int_value(parameter.get("parameter_index", parameter.get("index")), -1)
    if 0 <= parameter_index < len(parameters):
        result.append(parameters[parameter_index][0])
    for name in (
        _string_list(parameter.get("parameter_name"))
        + _string_list(parameter.get("name"))
        + _string_list(parameter.get("base_names"))
        + _string_list(parameter.get("parameter_names"))
        + _string_list(parameter.get("local_names"))
        + _string_list(parameter.get("name_hints"))
    ):
        if _identifier_exists(text, name):
            result.append(name)
    return list(dict.fromkeys(item for item in result if item))


def _dedupe_role_matches(matches: list[DomainIdentityMatch]) -> list[DomainIdentityMatch]:
    selected: dict[tuple[str, str, str], DomainIdentityMatch] = {}
    conflicts: dict[tuple[str, str], list[DomainIdentityMatch]] = {}
    for match in sorted(matches, key=lambda item: (item.base, item.structure, item.profile_id, item.role)):
        key = (match.base, match.structure, match.role)
        selected.setdefault(key, match)
        conflicts.setdefault((match.base, match.structure), [])
        if all(item.profile_id != match.profile_id for item in conflicts[(match.base, match.structure)]):
            conflicts[(match.base, match.structure)].append(match)

    result: list[DomainIdentityMatch] = []
    ambiguous_keys = {
        key: values
        for key, values in conflicts.items()
        if len({item.profile_id for item in values}) > 1
    }
    emitted_ambiguous: set[tuple[str, str]] = set()
    for key, match in selected.items():
        conflict_key = (match.base, match.structure)
        ambiguous = ambiguous_keys.get(conflict_key)
        if not ambiguous:
            result.append(match)
            continue
        if conflict_key in emitted_ambiguous:
            continue
        emitted_ambiguous.add(conflict_key)
        profile_ids = tuple(item.profile_id for item in ambiguous)
        first = ambiguous[0]
        result.append(
            DomainIdentityMatch(
                profile_id="ambiguous",
                base=first.base,
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
                profile_source=first.profile_source,
                profile_version=first.profile_version,
                profile_metadata=first.profile_metadata,
                suppress_layout_inference=all(item.suppress_layout_inference for item in ambiguous),
            )
        )
    result.sort(key=lambda item: (item.base.lower(), item.structure, item.role, item.profile_id))
    return result


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


def _parameter_type_correction_blockers(
    parameter: dict[str, Any],
    old_type: str,
    canonical_type: str,
    display_type: str,
) -> list[str]:
    accepted_types = _string_list(parameter.get("accepted_types"))
    if not accepted_types:
        return []
    actual = _normalize_type_shape(old_type)
    if not actual:
        return ["type_conflict"]
    if canonical_type and actual == _normalize_type_shape(canonical_type):
        return []
    if display_type and actual == _normalize_type_shape(display_type):
        return []
    if any(_normalize_type_shape(item) == actual for item in accepted_types):
        return []
    return ["type_conflict"]


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


def _parameter_type_correction(
    profile: dict[str, Any],
    parameter: dict[str, Any],
    parameters: list[tuple[str, str]],
    profile_blockers: list[str],
) -> ParameterTypeCorrection | None:
    raw_display_type = parameter.get("display_type", "")
    raw_type = parameter.get("canonical_type", raw_display_type)
    if raw_type in (None, ""):
        return None
    parameter_index = _int_value(parameter.get("parameter_index", parameter.get("index")), -1)
    if parameter_index < 0 or parameter_index >= len(parameters):
        return None
    old_name, old_type = parameters[parameter_index]
    canonical_type = _safe_type_correction_text(raw_type)
    display_type = _safe_type_correction_text(raw_display_type)
    blockers = list(profile_blockers)
    if not canonical_type:
        blockers.append("invalid_canonical_type")
    blockers.extend(_parameter_type_correction_blockers(parameter, old_type, canonical_type, display_type))
    new_name = _safe_identifier_text(
        parameter.get(
            "canonical_name",
            parameter.get("display_name", parameter.get("rename_to", parameter.get("role", old_name))),
        ),
        old_name,
    )
    confidence = _float_value(parameter.get("type_confidence", parameter.get("confidence")), 0.72)
    confidence = round(max(0.0, min(0.98, confidence)), 2)
    mode = _mode_value(parameter.get("mode"))
    if mode != MODE_REPORT_ONLY and confidence < 0.75:
        blockers.append("low_confidence")
    effective_mode = MODE_REPORT_ONLY if blockers else mode
    apply_to_preview = _bool_value(parameter.get("apply_to_preview"), True) and not blockers
    return ParameterTypeCorrection(
        parameter_index=parameter_index,
        old_name=old_name,
        new_name=new_name,
        old_type=old_type,
        canonical_type=canonical_type,
        profile_id=_profile_id(profile),
        display_type=display_type,
        source=_safe_note_text(parameter.get("type_source", parameter.get("source", ""))) or _profile_source(profile, parameter),
        provenance=_safe_note_text(parameter.get("type_provenance", parameter.get("provenance", "")))
        or _profile_source(profile, parameter),
        confidence=confidence,
        effective_mode=effective_mode,
        blockers=list(dict.fromkeys(blockers)),
        apply_to_preview=apply_to_preview,
        apply_to_idb=_bool_value(parameter.get("apply_to_idb"), _profile_apply_to_idb_default(profile)),
    )


def _dedupe_parameter_type_corrections(
    candidates: list[ParameterTypeCorrection],
) -> list[ParameterTypeCorrection]:
    by_index: dict[int, list[ParameterTypeCorrection]] = {}
    for item in candidates:
        by_index.setdefault(item.parameter_index, []).append(item)

    result: list[ParameterTypeCorrection] = []
    for parameter_index, items in sorted(by_index.items()):
        active = [item for item in items if item.apply_to_preview]
        active_shapes = {
            (item.canonical_type, item.new_name)
            for item in active
            if item.canonical_type
        }
        active_profile_ids = {item.profile_id for item in active if item.profile_id}
        ambiguous_blocked = [item for item in items if "ambiguous_profile_match" in item.blockers]
        if len(active_profile_ids) > 1 or len(active_shapes) > 1:
            first = sorted(items, key=lambda item: item.profile_id)[0]
            result.append(
                ParameterTypeCorrection(
                    parameter_index=parameter_index,
                    old_name=first.old_name,
                    new_name=first.old_name,
                    old_type=first.old_type,
                    canonical_type="",
                    profile_id="ambiguous",
                    display_type="",
                    source=first.source,
                    provenance=", ".join(sorted({item.profile_id for item in items if item.profile_id})),
                    confidence=min(0.54, first.confidence),
                    effective_mode=MODE_REPORT_ONLY,
                    blockers=["ambiguous_profile_match"],
                    apply_to_preview=False,
                    apply_to_idb=False,
                )
            )
            continue
        if ambiguous_blocked and not active:
            first = sorted(items, key=lambda item: item.profile_id)[0]
            result.append(
                ParameterTypeCorrection(
                    parameter_index=parameter_index,
                    old_name=first.old_name,
                    new_name=first.old_name,
                    old_type=first.old_type,
                    canonical_type="",
                    profile_id="ambiguous",
                    display_type="",
                    source=first.source,
                    provenance=", ".join(sorted({item.profile_id for item in items if item.profile_id})),
                    confidence=min(0.54, first.confidence),
                    effective_mode=MODE_REPORT_ONLY,
                    blockers=["ambiguous_profile_match"],
                    apply_to_preview=False,
                    apply_to_idb=False,
                )
            )
            continue

        selected = sorted(
            items,
            key=lambda item: (not item.apply_to_preview, -item.confidence, item.profile_id),
        )[0]
        result.append(selected)
    return result


def _parameter_match(
    profile: dict[str, Any],
    parameter: dict[str, Any],
    base: str,
    parameters: list[tuple[str, str]],
    non_identity_blockers: list[str],
    profile_blockers: list[str],
) -> DomainIdentityMatch | None:
    parameter_index = _int_value(parameter.get("parameter_index", parameter.get("index")), -1)
    parameter_name = str(parameter.get("parameter_name", parameter.get("name", "")) or "").strip()
    base_names = set(_string_list(parameter.get("base_names")))
    base_names.update(_string_list(parameter.get("parameter_names")))
    base_names.update(_string_list(parameter.get("local_names")))
    base_names.update(_string_list(parameter.get("name_hints")))
    if parameter_name:
        base_names.add(parameter_name)
    if 0 <= parameter_index < len(parameters):
        base_names.add(parameters[parameter_index][0])
    if not base_names or base not in base_names:
        return None
    type_index = parameter_index if 0 <= parameter_index < len(parameters) else _parameter_index_for_name(parameters, base)
    if type_index >= 0 and not _parameter_type_matches(parameter, parameters[type_index][1]):
        return None

    role = _safe_identifier_text(parameter.get("role"), "domainRole")
    structure = _safe_identifier_text(parameter.get("structure"), "DOMAIN_STRUCTURE")
    mode = _mode_value(parameter.get("mode"))
    confidence_value = _float_value(parameter.get("confidence"), 0.72)
    effective_profile_blockers = list(profile_blockers)
    if mode != MODE_REPORT_ONLY and confidence_value < 0.75:
        effective_profile_blockers.append("low_confidence")
    effective_mode, forced_reasons = _effective_mode(
        mode,
        _string_list(parameter.get("force_report_only_on")),
        non_identity_blockers,
        effective_profile_blockers,
    )
    profile_id = _profile_id(profile)
    fields = tuple() if effective_profile_blockers else tuple(_profile_fields(parameter.get("fields", []), profile, parameter))
    confidence = min(
        confidence_value,
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
        profile_source=_profile_source(profile, parameter),
        profile_version=_profile_version(profile),
        profile_metadata=_profile_metadata_tuple(profile),
        suppress_layout_inference=_bool_value(
            parameter.get(
                "suppress_layout_inference",
                profile.get("suppress_layout_inference"),
            ),
            False,
        ),
    )


def _profile_fields(value: Any, profile: dict[str, Any], parameter: dict[str, Any]) -> list[DomainIdentityField]:
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
        source = _safe_note_text(item.get("source", item.get("provenance", "")))
        if not source:
            source = _profile_source(profile, parameter)
        provenance = _safe_note_text(item.get("provenance", source))
        seen_offsets.add(offset)
        result.append(
            DomainIdentityField(
                offset=offset,
                name=name,
                type_text=type_text,
                size=max(0, size),
                confidence=round(max(0.0, min(1.0, confidence)), 2),
                source=source,
                provenance=provenance,
                note=_safe_note_text(item.get("note", "")),
            )
        )
    result.sort(key=lambda field: field.offset)
    return result


def _effective_mode(
    mode: str,
    force_report_only_on: list[str],
    non_identity_blockers: list[str],
    profile_blockers: list[str],
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    reasons.extend(profile_blockers)
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
        if "build_mismatch" in lowered or "build mismatch" in lowered:
            categories.add("build_mismatch")
        if "missing_source_identity" in lowered or "missing source identity" in lowered:
            categories.add("missing_source_identity")
        if "low_confidence" in lowered or "low confidence" in lowered:
            categories.add("low_confidence")
    return categories


def _profile_context_blockers(
    profile: dict[str, Any],
    profile_context: dict[str, Any] | None,
) -> list[str]:
    constraints = _profile_context_constraints(profile)
    if not constraints:
        return []
    context = _normalize_profile_context(profile_context)
    if not context:
        return ["missing_source_identity"]
    blockers: list[str] = []
    missing = False
    for key, expected_values in constraints.items():
        actual = context.get(key, "")
        if not actual:
            missing = True
            continue
        if not any(_context_value_matches(key, actual, expected) for expected in expected_values):
            blockers.append(_context_mismatch_blocker(key))
    if missing:
        blockers.insert(0, "missing_source_identity")
    return list(dict.fromkeys(blockers))


def _profile_context_constraints(profile: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    constraints: dict[str, list[str]] = {}
    for section in _profile_metadata_sections(profile):
        for key, values in _metadata_constraints(section).items():
            constraints.setdefault(key, [])
            constraints[key].extend(values)
    return {
        key: tuple(dict.fromkeys(value for value in values if value))
        for key, values in constraints.items()
        if values
    }


def _profile_metadata_sections(profile: dict[str, Any]) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for key in ("_pack_metadata", "target", "metadata", "build"):
        value = profile.get(key)
        if isinstance(value, dict):
            sections.append(value)
        elif key == "build" and value not in (None, ""):
            sections.append({"build": value})
    sections.append(profile)
    return sections


def _metadata_constraints(section: dict[str, Any]) -> dict[str, list[str]]:
    aliases = {
        "image": ("image", "image_name", "module", "binary"),
        "arch": ("arch", "architecture", "machine"),
        "build": ("build", "build_number", "os_build", "nt_build"),
        "pdb_guid_age": ("pdb_guid_age", "pdb_guidage"),
        "pdb_guid": ("pdb_guid",),
        "pdb_age": ("pdb_age",),
        "image_sha256": ("image_sha256", "image_hash"),
    }
    result: dict[str, list[str]] = {}
    for canonical, names in aliases.items():
        for name in names:
            if name not in section:
                continue
            values = _metadata_value_list(section.get(name))
            if values:
                result.setdefault(canonical, [])
                result[canonical].extend(values)
    return result


def _metadata_value_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _normalize_profile_context(profile_context: dict[str, Any] | None) -> dict[str, str]:
    if not isinstance(profile_context, dict):
        return {}
    result: dict[str, str] = {}
    for section in [profile_context]:
        for key, values in _metadata_constraints(section).items():
            if values:
                result[key] = _normalize_context_value(key, values[0])
    return result


def _context_value_matches(key: str, actual: str, expected: str) -> bool:
    expected_normalized = _normalize_context_value(key, expected)
    return bool(expected_normalized and actual == expected_normalized)


def _normalize_context_value(key: str, value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if key == "image":
        text = re.split(r"[\\/]", text)[-1]
    if key == "arch":
        lowered = text.lower()
        if lowered in {"amd64", "x86_64"}:
            return "x64"
        if lowered in {"i386", "i686"}:
            return "x86"
        return lowered
    if key in {"pdb_guid_age", "pdb_guid", "image_sha256"}:
        return text.strip("{}").lower()
    return text.lower()


def _context_mismatch_blocker(key: str) -> str:
    if key == "build":
        return "build_mismatch"
    if key == "image":
        return "image_mismatch"
    if key == "arch":
        return "arch_mismatch"
    if key.startswith("pdb"):
        return "pdb_mismatch"
    if key == "image_sha256":
        return "image_hash_mismatch"
    return "profile_context_mismatch"


def _metadata_items(section: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in section.items():
        if isinstance(value, (dict, list)):
            continue
        text = str(value or "").strip()
        if text:
            result[str(key)] = text
    return result


def _profile_source(profile: dict[str, Any], parameter: dict[str, Any] | None = None) -> str:
    if parameter:
        source = _safe_note_text(parameter.get("source", parameter.get("provenance", "")))
        if source:
            return source
    source = _safe_note_text(profile.get("source", profile.get("provenance", "")))
    if source:
        return source
    metadata = profile.get("_pack_metadata")
    if isinstance(metadata, dict):
        source = _safe_note_text(metadata.get("source", ""))
        if source:
            return source
    return ""


def _profile_version(profile: dict[str, Any]) -> str:
    for section in _profile_metadata_sections(profile):
        for key in ("profile_version", "version"):
            value = str(section.get(key, "") if isinstance(section, dict) else "").strip()
            if value:
                return value
    return ""


def _profile_metadata_tuple(profile: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    metadata: dict[str, str] = {}
    for section in _profile_metadata_sections(profile):
        metadata.update(_metadata_items(section))
    return tuple(sorted((key, value) for key, value in metadata.items() if not key.startswith("_")))


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


def _profile_subsystem(profile: dict[str, Any]) -> str:
    for section in (profile, profile.get("metadata"), profile.get("_pack_metadata")):
        if not isinstance(section, dict):
            continue
        value = str(section.get("subsystem", section.get("domain", "")) or "").strip()
        if value:
            return value
    metadata = profile_loader.subsystem_identity_metadata(_profile_id(profile))
    return str(metadata.get("subsystem", "") or "").strip()


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


def _identifier_exists(text: str, name: str) -> bool:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(name or "")):
        return False
    return re.search(r"\b%s\b" % re.escape(str(name)), text or "") is not None


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


def _bool_value(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
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


def _safe_type_correction_text(value: Any) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text or len(text) > 96:
        return ""
    if not text.isascii():
        return ""
    if re.search(r"[^A-Za-z0-9_\s\*\:]", text):
        return ""
    if not re.search(r"[A-Za-z_]", text):
        return ""
    return text


def _safe_calling_convention_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 32:
        return ""
    if re.fullmatch(r"__?[A-Za-z][A-Za-z0-9_]*", text):
        return text
    return ""


def _safe_note_text(value: Any) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    if len(text) > 180:
        text = text[:180].rstrip()
    return text.encode("ascii", "ignore").decode("ascii")

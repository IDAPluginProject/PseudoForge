from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ida_pseudoforge.core.normalize import (
    extract_function_name,
    extract_function_signature,
    extract_parameters_from_signature,
    safe_identifier_replace,
)
from ida_pseudoforge.core.plan_schema import FunctionCapture, RenameSuggestion
from ida_pseudoforge.profiles.loader import load_json_profile


PROFILE_NAME = "registry_domain.json"
MODE_REPORT_ONLY = "report-only"


@dataclass(frozen=True, slots=True)
class RegistryDomainRoleMatch:
    profile_id: str
    role: str
    structure: str
    mode: str
    target_kind: str
    target: str
    display: str
    rename_to: str
    confidence: float
    rename_confidence: float
    evidence: tuple[str, ...]
    blockers: tuple[str, ...]


def registry_domain_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    suggestions: list[RenameSuggestion] = []
    for match in registry_domain_role_matches(capture):
        if not match.rename_to or not match.target:
            continue
        if match.target_kind not in {"local", "parameter"}:
            continue
        kind = "arg" if match.target_kind == "parameter" else "lvar"
        suggestions.append(
            RenameSuggestion(
                kind=kind,
                old=match.target,
                new=match.rename_to,
                confidence=match.rename_confidence,
                source="registry-domain",
                evidence=(
                    "Registry domain profile %s identifies %s as %s; evidence: %s"
                    % (match.profile_id, match.target, match.role, "; ".join(match.evidence[:4]))
                ),
            )
        )
    return suggestions


def registry_domain_comments(
    capture: FunctionCapture,
    rename_map: dict[str, str],
) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    for match in registry_domain_role_matches(capture):
        display = _renamed_display(match.display or match.target or match.role, rename_map)
        target = _renamed_display(match.target, rename_map) if match.target else display
        evidence_text = "; ".join(match.evidence[:5]) if match.evidence else "matched profile evidence"
        blockers = _unique_strings(
            list(match.blockers)
            + [
                "report-only registry-domain triage",
                "no registry structure field rewrite is enabled by this profile",
            ]
        )
        comments.append(
            {
                "kind": "registry_domain_role_evidence",
                "text": (
                    "Registry domain role for %s: %s is %s/%s, mode report-only. "
                    "Evidence: %s. Blockers: %s."
                    % (
                        capture.name or "function",
                        display,
                        match.role,
                        match.structure,
                        evidence_text,
                        "; ".join(blockers),
                    )
                ),
                "confidence": match.confidence,
                "profile_id": match.profile_id,
                "role": match.role,
                "structure": match.structure,
                "mode": MODE_REPORT_ONLY,
                "target": target,
                "raw_target": match.target,
                "target_kind": match.target_kind,
                "evidence": list(match.evidence),
                "blockers": blockers,
            }
        )
    return comments


def registry_domain_role_matches(capture: FunctionCapture) -> list[RegistryDomainRoleMatch]:
    if not registry_domain_profiles_available():
        return []
    text = capture.pseudocode or ""
    signature = capture.prototype or extract_function_signature(text)
    function_name = capture.name or extract_function_name(signature)
    parameters = extract_parameters_from_signature(signature)
    local_names = {var.name for var in capture.lvars if var.name}
    matches: list[RegistryDomainRoleMatch] = []
    for profile in _registry_domain_profiles():
        if not _function_matches(profile, function_name, signature):
            continue
        profile_id = _profile_id(profile)
        mode = _mode_value(profile.get("mode"))
        for role in _profile_roles(profile):
            match = _role_match(profile_id, mode, role, text, parameters, local_names)
            if match:
                matches.append(match)
    matches.sort(key=lambda item: (item.profile_id, item.role, item.target))
    return matches


def registry_domain_profiles_available() -> bool:
    return bool(_registry_domain_profiles())


def _role_match(
    profile_id: str,
    mode: str,
    role: dict[str, Any],
    text: str,
    parameters: list[tuple[str, str]],
    local_names: set[str],
) -> RegistryDomainRoleMatch | None:
    target_kind, target = _resolve_target(role, parameters, local_names)
    if target_kind in {"local", "parameter"} and not target:
        return None
    aliases = _target_aliases(target, role)
    evidence = _matched_evidence(role, text, aliases)
    min_evidence = _int_value(role.get("min_evidence"), 1)
    if len(evidence) < max(1, min_evidence):
        return None
    role_name = _safe_identifier_text(role.get("role"), "registryRole")
    structure = _safe_identifier_text(role.get("structure"), "REGISTRY_DOMAIN")
    confidence = min(_float_value(role.get("confidence"), 0.72), 0.88)
    rename_confidence = min(_float_value(role.get("rename_confidence"), confidence), confidence + 0.04, 0.95)
    display = _display_text(role, target, aliases)
    return RegistryDomainRoleMatch(
        profile_id=profile_id,
        role=role_name,
        structure=structure,
        mode=mode,
        target_kind=target_kind,
        target=target,
        display=display,
        rename_to=_safe_identifier_text(role.get("rename_to"), ""),
        confidence=round(confidence, 2),
        rename_confidence=round(rename_confidence, 2),
        evidence=tuple(evidence),
        blockers=tuple(_string_list(role.get("blockers"))),
    )


def _matched_evidence(role: dict[str, Any], text: str, aliases: list[str]) -> list[str]:
    result: list[str] = []
    for item in role.get("evidence", []) or []:
        if not isinstance(item, dict):
            continue
        pattern = _evidence_pattern(item, aliases)
        if not pattern:
            continue
        try:
            matched = re.search(pattern, text or "", flags=re.IGNORECASE | re.MULTILINE) is not None
        except re.error:
            matched = False
        if matched:
            result.append(_safe_note_text(item.get("text")) or _safe_identifier_text(item.get("id"), "matched"))
    return _unique_strings(result)


def _evidence_pattern(item: dict[str, Any], aliases: list[str]) -> str:
    pattern = str(item.get("pattern", "") or "").strip()
    if not pattern:
        return ""
    target = re.escape(aliases[0]) if aliases else r"[A-Za-z_][A-Za-z0-9_]*"
    targets = "(?:%s)" % "|".join(re.escape(alias) for alias in aliases) if aliases else target
    return pattern.replace("{target}", target).replace("{targets}", targets)


def _resolve_target(
    role: dict[str, Any],
    parameters: list[tuple[str, str]],
    local_names: set[str],
) -> tuple[str, str]:
    if "parameter_index" in role:
        index = _int_value(role.get("parameter_index"), -1)
        if 0 <= index < len(parameters):
            return "parameter", parameters[index][0]
        return "parameter", ""
    target = _safe_identifier_text(role.get("target"), "")
    target_kind = str(role.get("target_kind", "") or "").strip().lower()
    if not target_kind:
        target_kind = "local" if target in local_names else "expression"
    if target_kind == "local" and target not in local_names:
        return "local", ""
    return target_kind, target


def _target_aliases(target: str, role: dict[str, Any]) -> list[str]:
    aliases = []
    if target:
        aliases.append(target)
    aliases.extend(_string_list(role.get("aliases")))
    return _unique_strings([alias for alias in aliases if _safe_identifier_text(alias, "")])


def _display_text(role: dict[str, Any], target: str, aliases: list[str]) -> str:
    display = _safe_note_text(role.get("display"))
    if not display:
        return target
    primary = aliases[0] if aliases else target
    targets = "/".join(aliases) if aliases else primary
    return display.replace("{target}", primary).replace("{targets}", targets)


def _renamed_display(value: str, rename_map: dict[str, str]) -> str:
    if not value:
        return ""
    return safe_identifier_replace(value, rename_map or {})


def _registry_domain_profiles() -> tuple[dict[str, Any], ...]:
    payload = load_json_profile(PROFILE_NAME)
    if not isinstance(payload, dict):
        return ()
    profiles = payload.get("profiles", [])
    if not isinstance(profiles, list):
        return ()
    return tuple(item for item in profiles if isinstance(item, dict))


def _profile_roles(profile: dict[str, Any]) -> list[dict[str, Any]]:
    roles = profile.get("roles", [])
    if isinstance(roles, list):
        return [item for item in roles if isinstance(item, dict)]
    return []


def _function_matches(profile: dict[str, Any], function_name: str, signature: str) -> bool:
    names = _string_list(profile.get("function_names"))
    if names and function_name in names:
        return True
    for pattern in _string_list(profile.get("function_regex")):
        if _safe_regex_search(pattern, function_name) or _safe_regex_search(pattern, signature):
            return True
    return False


def _mode_value(value: Any) -> str:
    mode = str(value or MODE_REPORT_ONLY).strip().lower().replace("_", "-")
    if mode == MODE_REPORT_ONLY:
        return mode
    return MODE_REPORT_ONLY


def _profile_id(profile: dict[str, Any]) -> str:
    value = str(profile.get("id", profile.get("name", "")) or "").strip()
    return value or "registry_domain_profile"


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


def _safe_note_text(value: Any) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    if len(text) > 220:
        text = text[:220].rstrip()
    return text.encode("ascii", "ignore").decode("ascii")


def _unique_strings(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result

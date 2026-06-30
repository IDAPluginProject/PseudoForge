from __future__ import annotations

import json
import re
from typing import Any

from ida_pseudoforge.core.plan_schema import FunctionCapture, LlmCandidate, RenameSuggestion
from ida_pseudoforge.core.rename_normalization import normalize_rename_suggestions
from ida_pseudoforge.core.validation import validate_renames
from ida_pseudoforge.models.base import RenameAssistProvider


def suggest_renames_with_provider(
    capture: FunctionCapture,
    provider: RenameAssistProvider,
    min_confidence: float = 0.70,
) -> tuple[list[RenameSuggestion], list[str]]:
    effective_min_confidence = _effective_min_confidence(capture, min_confidence)
    raw_response = provider.suggest_renames(capture)
    suggestions, warnings = parse_llm_rename_response(raw_response, min_confidence=effective_min_confidence)
    suggestions = normalize_rename_suggestions(capture, suggestions)
    validated, validation_warnings = validate_renames(capture, suggestions)
    warnings = _filter_llm_warnings(capture, warnings, effective_min_confidence)
    return validated, warnings + validation_warnings


def suggest_candidates_with_provider(
    capture: FunctionCapture,
    provider: Any,
    min_confidence: float = 0.70,
) -> tuple[list[LlmCandidate], list[str]]:
    candidate_func = getattr(provider, "suggest_candidates", None)
    if candidate_func is None:
        return [], []
    try:
        raw_response = candidate_func(capture)
    except Exception as exc:
        return [], ["LLM candidate assist failed; deterministic fallback used: %s" % exc]
    return parse_llm_candidate_response(capture, raw_response, min_confidence=min_confidence)


def parse_llm_rename_response(
    raw_response: str,
    min_confidence: float = 0.70,
) -> tuple[list[RenameSuggestion], list[str]]:
    normalized_response = _extract_json_object_text(raw_response or "{}")
    try:
        data = json.loads(normalized_response)
    except json.JSONDecodeError as exc:
        return [], [f"LLM rename response was not valid JSON: {exc}"]

    raw_items = data.get("renames", [])
    if isinstance(raw_items, dict):
        raw_items = [
            {
                "old": old,
                "new": new,
                "confidence": 0.75,
                "reason": "legacy object mapping",
            }
            for old, new in raw_items.items()
        ]

    if not isinstance(raw_items, list):
        return [], ["LLM rename response did not contain a renames list"]

    suggestions = []
    warnings = []
    for index, item in enumerate(raw_items):
        suggestion = _parse_one_item(index, item, min_confidence)
        if isinstance(suggestion, str):
            warnings.append(suggestion)
        else:
            suggestions.append(suggestion)

    for warning in data.get("warnings", []) if isinstance(data.get("warnings", []), list) else []:
        warnings.append(_format_warning(warning))

    return suggestions, warnings


def parse_llm_candidate_response(
    capture: FunctionCapture,
    raw_response: str,
    min_confidence: float = 0.70,
) -> tuple[list[LlmCandidate], list[str]]:
    text = str(raw_response or "{}").strip()
    if not text.startswith("{") or not text.endswith("}"):
        return [], ["LLM candidate response was not strict JSON"]
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], [f"LLM candidate response was not valid JSON: {exc}"]
    if not isinstance(data, dict):
        return [], ["LLM candidate response root was not an object"]

    candidates: list[LlmCandidate] = []
    warnings: list[str] = []
    _extend_field_candidates(candidates, warnings, capture, data.get("field_candidates", []), min_confidence)
    _extend_type_role_candidates(candidates, warnings, capture, data.get("type_role_candidates", []), min_confidence)
    _extend_intent_comment_candidates(candidates, warnings, data.get("intent_comments", []), min_confidence)
    for warning in data.get("warnings", []) if isinstance(data.get("warnings", []), list) else []:
        warnings.append(_format_warning(warning))
    return candidates, warnings


def _extend_field_candidates(
    candidates: list[LlmCandidate],
    warnings: list[str],
    capture: FunctionCapture,
    raw_items: object,
    min_confidence: float,
) -> None:
    if raw_items in (None, []):
        return
    if not isinstance(raw_items, list):
        warnings.append("LLM candidate response field_candidates was not a list")
        return
    for index, item in enumerate(raw_items):
        if not isinstance(item, dict):
            warnings.append("Skipped LLM field candidate %d: not an object" % index)
            continue
        base = str(item.get("base", "")).strip()
        offset = str(item.get("offset", "")).strip()
        name = str(item.get("name", "")).strip()
        candidate, warning = _base_candidate(
            task="field_candidates",
            kind="field_name",
            confidence=_candidate_confidence(item),
            min_confidence=min_confidence,
            index=index,
            target=base,
            name=name,
            evidence=str(item.get("evidence", "") or item.get("reason", "")).strip(),
            attributes={"base": base, "offset": offset},
        )
        if warning:
            warnings.append(warning)
            continue
        if candidate is None:
            continue
        candidate.blockers.extend(_field_candidate_blockers(capture, base, offset))
        candidates.append(candidate)


def _extend_type_role_candidates(
    candidates: list[LlmCandidate],
    warnings: list[str],
    capture: FunctionCapture,
    raw_items: object,
    min_confidence: float,
) -> None:
    if raw_items in (None, []):
        return
    if not isinstance(raw_items, list):
        warnings.append("LLM candidate response type_role_candidates was not a list")
        return
    local_names = {var.name for var in capture.lvars if var.name}
    for index, item in enumerate(raw_items):
        if not isinstance(item, dict):
            warnings.append("Skipped LLM type-role candidate %d: not an object" % index)
            continue
        target = str(item.get("target", "")).strip()
        role = str(item.get("role", "")).strip()
        type_name = str(item.get("type", "") or item.get("type_name", "")).strip()
        candidate, warning = _base_candidate(
            task="type_role_candidates",
            kind="type_role",
            confidence=_candidate_confidence(item),
            min_confidence=min_confidence,
            index=index,
            target=target,
            name=role,
            evidence=str(item.get("evidence", "") or item.get("reason", "")).strip(),
            role=role,
            type_name=type_name,
            attributes={"target": target},
        )
        if warning:
            warnings.append(warning)
            continue
        if candidate is None:
            continue
        if target not in local_names:
            candidate.blockers.append("target local is not present in capture")
        candidate.blockers.append("deterministic type evidence required before rewrite")
        candidates.append(candidate)


def _extend_intent_comment_candidates(
    candidates: list[LlmCandidate],
    warnings: list[str],
    raw_items: object,
    min_confidence: float,
) -> None:
    if raw_items in (None, []):
        return
    if not isinstance(raw_items, list):
        warnings.append("LLM candidate response intent_comments was not a list")
        return
    for index, item in enumerate(raw_items):
        if not isinstance(item, dict):
            warnings.append("Skipped LLM intent-comment candidate %d: not an object" % index)
            continue
        anchor = str(item.get("anchor", "") or "function").strip()
        text = str(item.get("text", "")).strip()
        candidate, warning = _base_candidate(
            task="intent_comments",
            kind="intent_comment",
            confidence=_candidate_confidence(item),
            min_confidence=min_confidence,
            index=index,
            target=anchor,
            text=text,
            evidence=str(item.get("evidence", "") or item.get("reason", "")).strip(),
            attributes={"anchor": anchor},
        )
        if warning:
            warnings.append(warning)
            continue
        if candidate is None:
            continue
        candidate.blockers.append("manual review required before comment projection")
        candidates.append(candidate)


def _base_candidate(
    task: str,
    kind: str,
    confidence: float,
    min_confidence: float,
    index: int,
    target: str = "",
    name: str = "",
    text: str = "",
    role: str = "",
    type_name: str = "",
    evidence: str = "",
    attributes: dict[str, Any] | None = None,
) -> tuple[LlmCandidate | None, str]:
    if confidence < min_confidence:
        return None, "Skipped LLM %s candidate %d: low confidence %.2f" % (task, index, confidence)
    if kind == "field_name" and (not target or not name or not str((attributes or {}).get("offset", "")).strip()):
        return None, "Skipped LLM field candidate %d: missing base, offset, or name" % index
    if kind == "type_role" and (not target or not role):
        return None, "Skipped LLM type-role candidate %d: missing target or role" % index
    if kind == "intent_comment" and not text:
        return None, "Skipped LLM intent-comment candidate %d: missing text" % index
    candidate = LlmCandidate(
        task=task,
        kind=kind,
        confidence=confidence,
        target=target,
        name=name,
        text=text,
        role=role,
        type_name=type_name,
        evidence=evidence or "LLM candidate suggestion",
        blockers=["llm_candidate is report-only until deterministic evidence validates it"],
        attributes=dict(attributes or {}),
    )
    return candidate, ""


def _candidate_confidence(item: dict[str, Any]) -> float:
    try:
        return float(item.get("confidence", 0))
    except (TypeError, ValueError):
        return 0.0


def _field_candidate_blockers(capture: FunctionCapture, base: str, offset: str) -> list[str]:
    blockers = ["deterministic field access evidence required before rewrite"]
    if not base or base not in (capture.pseudocode or ""):
        blockers.append("base variable is not present in pseudocode")
    if not _offset_is_present(capture.pseudocode or "", offset):
        blockers.append("offset is not present in pseudocode")
    return blockers


def _offset_is_present(text: str, offset: str) -> bool:
    normalized = str(offset or "").strip()
    if not normalized:
        return False
    variants = {normalized}
    try:
        value = int(normalized, 0)
        variants.add(str(value))
        variants.add("0x%X" % value)
        variants.add("0x%x" % value)
    except ValueError:
        pass
    return any(re.search(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(item), text) for item in variants)


def _format_warning(warning: Any) -> str:
    if isinstance(warning, dict):
        message = str(warning.get("message", "")).strip()
        if message:
            return message
        old = str(warning.get("old", "")).strip()
        reason = str(warning.get("reason", "")).strip()
        if old and reason:
            return "Potential bad call target %s: %s" % (old, reason)
        try:
            return json.dumps(warning, ensure_ascii=False, sort_keys=True)
        except TypeError:
            return str(warning)
    return str(warning)


def _parse_one_item(
    index: int,
    item: Any,
    min_confidence: float,
) -> RenameSuggestion | str:
    if not isinstance(item, dict):
        return f"Skipped LLM rename item {index}: not an object"

    old = str(item.get("old", "")).strip()
    new = str(item.get("new", "")).strip()
    reason = str(item.get("reason", "") or item.get("evidence", "")).strip()
    try:
        confidence = float(item.get("confidence", 0))
    except (TypeError, ValueError):
        confidence = 0.0

    if not old or not new:
        return f"Skipped LLM rename item {index}: missing old or new"
    if confidence < min_confidence:
        return f"Skipped LLM rename {old}->{new}: low confidence {confidence:.2f}"

    return RenameSuggestion(
        kind=str(item.get("kind", "lvar")),
        old=old,
        new=new,
        confidence=confidence,
        source="llm",
        evidence=reason or "LLM-assisted rename suggestion",
        apply=True,
    )


def _extract_json_object_text(raw_response: str) -> str:
    text = raw_response.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip().startswith("```"):
            text = "\n".join(lines[1:-1]).strip()

    if text.startswith("{") and text.endswith("}"):
        return text

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1]
    return text


def _effective_min_confidence(capture: FunctionCapture, default_min_confidence: float) -> float:
    if _looks_like_large_dispatcher(capture.pseudocode or ""):
        return max(default_min_confidence, 0.85)
    return default_min_confidence


def _filter_llm_warnings(
    capture: FunctionCapture,
    warnings: list[str],
    min_confidence: float,
) -> list[str]:
    if not warnings:
        return warnings
    if min_confidence < 0.85 or not _looks_like_large_dispatcher(capture.pseudocode or ""):
        return warnings
    return [warning for warning in warnings if "low confidence" not in warning.lower()]


def _looks_like_large_dispatcher(text: str) -> bool:
    lines = text.splitlines()
    if len(lines) >= 180:
        return True
    return_count = text.count("return")
    label_count = len([line for line in lines if "LABEL_" in line])
    branch_count = text.count("if (") + len([line for line in lines if line.lstrip().startswith("case ")])
    if label_count >= 8 and return_count >= 8:
        return True
    return return_count >= 16 and branch_count >= 16

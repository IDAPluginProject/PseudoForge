from __future__ import annotations

import json
from typing import Any

from ida_pseudoforge.core.plan_schema import FunctionCapture, RenameSuggestion
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

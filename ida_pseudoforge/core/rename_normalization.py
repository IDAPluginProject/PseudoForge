from __future__ import annotations

import re
from dataclasses import replace

from ida_pseudoforge.core.normalize import extract_parameters_from_signature
from ida_pseudoforge.core.plan_schema import FunctionCapture, RenameSuggestion
from ida_pseudoforge.core.validation import is_valid_c_identifier


LLM_LOCAL_RENAME_KINDS = {
    "arg",
    "argument",
    "local",
    "lvar",
    "param",
    "parameter",
}
MIN_STYLE_NORMALIZATION_CONFIDENCE = 0.85
TYPE_LIKE_SUFFIXES = (
    "Class",
    "Record",
    "RecordType",
    "Struct",
    "Structure",
    "Type",
)


def normalize_rename_suggestions(
    capture: FunctionCapture,
    suggestions: list[RenameSuggestion],
) -> list[RenameSuggestion]:
    local_names = {var.name for var in capture.lvars if var.name}
    parameter_names = {name for name, _type_text in extract_parameters_from_signature(capture.prototype)}
    return [_normalize_one_suggestion(item, local_names, parameter_names) for item in suggestions]


def _normalize_one_suggestion(
    item: RenameSuggestion,
    local_names: set[str],
    parameter_names: set[str],
) -> RenameSuggestion:
    if not _should_normalize_pascal_case_llm_rename(item, local_names, parameter_names):
        return item
    normalized = pascal_to_lower_camel(item.new)
    if not normalized or normalized == item.new or not is_valid_c_identifier(normalized):
        return item
    evidence = _normalized_evidence(item.new, item.evidence)
    return replace(item, new=normalized, evidence=evidence)


def _should_normalize_pascal_case_llm_rename(
    item: RenameSuggestion,
    local_names: set[str],
    parameter_names: set[str],
) -> bool:
    if item.source != "llm":
        return False
    if (item.kind or "").lower() not in LLM_LOCAL_RENAME_KINDS:
        return False
    if not _is_known_local_or_argument(item.old, local_names, parameter_names):
        return False
    if item.confidence < MIN_STYLE_NORMALIZATION_CONFIDENCE:
        return False
    name = item.new or ""
    if not _looks_like_pascal_or_underscore_local_name(name):
        return False
    if _looks_type_like(name):
        return False
    return True


def _is_known_local_or_argument(old_name: str, local_names: set[str], parameter_names: set[str]) -> bool:
    if old_name in local_names or old_name in parameter_names:
        return True
    return bool(re.fullmatch(r"(?:a|v)\d+", old_name or ""))


def _looks_like_pascal_or_underscore_local_name(name: str) -> bool:
    if "_" in name:
        return _looks_like_pascal_underscore_local_name(name)
    return _looks_like_pascal_case_local_name(name)


def _looks_like_pascal_case_local_name(name: str) -> bool:
    if not name or not name[0].isupper():
        return False
    if name.isupper():
        return False
    if "_" in name:
        return False
    return any(char.islower() for char in name)


def _looks_like_pascal_underscore_local_name(name: str) -> bool:
    if not name or name.startswith("_") or name.endswith("_") or "__" in name:
        return False
    parts = name.split("_")
    if len(parts) < 2:
        return False
    if all(part.upper() == part for part in parts):
        return False
    return all(_looks_like_pascal_case_local_name(part) for part in parts)


def _looks_type_like(name: str) -> bool:
    if name.startswith("_"):
        return True
    if "::" in name:
        return True
    if "_" in name and name.upper() == name:
        return True
    if any(name.endswith(suffix) for suffix in TYPE_LIKE_SUFFIXES):
        return True
    if re.fullmatch(r"[A-Z][A-Za-z0-9]*(?:_T|Type|Class|Struct)", name or ""):
        return True
    return False


def pascal_to_lower_camel(name: str) -> str:
    if not name:
        return name
    if "_" in name:
        return _pascal_underscore_to_lower_camel(name)
    if len(name) == 1:
        return name.lower()
    if not name[0].isupper():
        return name
    word_end = _leading_acronym_end(name)
    return name[:word_end].lower() + name[word_end:]


def _pascal_underscore_to_lower_camel(name: str) -> str:
    parts = name.split("_")
    if not parts:
        return name
    normalized = [pascal_to_lower_camel(part) for part in parts]
    if any(not part for part in normalized):
        return name
    tail = [part[:1].upper() + part[1:] for part in normalized[1:]]
    return normalized[0] + "".join(tail)


def _leading_acronym_end(name: str) -> int:
    if len(name) < 2 or not name[1].isupper():
        return 1
    index = 1
    while index < len(name):
        if not name[index].isupper():
            break
        next_index = index + 1
        if next_index < len(name) and name[next_index].islower():
            break
        index += 1
    return max(1, index)


def _normalized_evidence(original_name: str, evidence: str) -> str:
    prefix = "style-normalized from LLM PascalCase candidate %s" % original_name
    if not evidence:
        return prefix
    return "%s; %s" % (prefix, evidence)

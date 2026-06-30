from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ida_pseudoforge.core.deterministic.schema import (
    FORBIDDEN_RULE_KEYS,
    SUPPORTED_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    SUPPORTED_TYPED_FACT_OPERATORS,
    SUPPORTED_V1_EMISSION_KINDS,
    SUPPORTED_V1_MATCH_OPERATORS,
    SUPPORTED_V1_PHASES,
    SUPPORTED_V1_SCOPE_OPERATORS,
    SUPPORTED_V2_EMISSION_KINDS,
    SUPPORTED_V2_MATCH_OPERATORS,
    SUPPORTED_V2_PHASES,
    SUPPORTED_V2_SCOPE_OPERATORS,
)


class RulePackValidationError(ValueError):
    pass


def parse_rule_pack_file(path: str | Path) -> tuple[dict[str, Any] | None, list[str]]:
    file_path = Path(path)
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, ["file not found"]
    except (OSError, UnicodeDecodeError) as exc:
        return None, ["could not read file: %s" % exc]
    except json.JSONDecodeError as exc:
        return None, ["invalid JSON: line %d column %d: %s" % (exc.lineno, exc.colno, exc.msg)]
    if not isinstance(data, dict):
        return None, ["rule pack root must be an object"]
    return data, []


def validate_rule_pack_data(data: dict[str, Any], source_path: str = "") -> list[str]:
    errors: list[str] = []
    if _contains_forbidden_key(data):
        errors.append("rule pack contains forbidden execution or network field")

    schema_version = data.get("schema_version")
    if not _is_supported_schema_version(schema_version):
        errors.append("unsupported schema_version %r" % (schema_version,))
        schema_version = SUPPORTED_SCHEMA_VERSION

    pack_id = data.get("id")
    if not isinstance(pack_id, str) or not pack_id.strip():
        errors.append("pack id is required")

    description = data.get("description", "")
    if description is not None and not isinstance(description, str):
        errors.append("description must be a string")

    rules = data.get("rules")
    if not isinstance(rules, list):
        errors.append("rules must be a list")
        return errors

    seen_rule_ids = set()
    for index, item in enumerate(rules):
        prefix = "rules[%d]" % index
        if not isinstance(item, dict):
            errors.append("%s must be an object" % prefix)
            continue
        rule_id = item.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append("%s.id is required" % prefix)
        elif rule_id in seen_rule_ids:
            errors.append("duplicate rule id %s" % rule_id)
        else:
            seen_rule_ids.add(rule_id)
        errors.extend(_validate_rule(item, prefix, int(schema_version)))

    return errors


def validate_rule_pack_file(path: str | Path) -> list[str]:
    data, errors = parse_rule_pack_file(path)
    if errors:
        return errors
    assert data is not None
    return validate_rule_pack_data(data, str(path))


def _validate_rule(rule: dict[str, Any], prefix: str, schema_version: int) -> list[str]:
    errors: list[str] = []
    if _contains_forbidden_key(rule):
        errors.append("%s contains forbidden execution or network field" % prefix)

    phase = rule.get("phase")
    supported_phases = _supported_phases(schema_version)
    if phase not in supported_phases:
        errors.append("%s.phase must be one of %s" % (prefix, ", ".join(sorted(supported_phases))))

    confidence = rule.get("confidence")
    if not _is_real_number(confidence) or not 0.0 <= float(confidence) <= 1.0:
        errors.append("%s.confidence must be between 0.0 and 1.0" % prefix)

    priority = rule.get("priority", 0)
    if not isinstance(priority, int) or isinstance(priority, bool):
        errors.append("%s.priority must be an integer" % prefix)

    enabled = rule.get("enabled", True)
    if not isinstance(enabled, bool):
        errors.append("%s.enabled must be a boolean" % prefix)

    override_of = rule.get("override_of", "")
    if override_of is not None and not isinstance(override_of, str):
        errors.append("%s.override_of must be a string" % prefix)

    scope = rule.get("scope", {})
    if not isinstance(scope, dict):
        errors.append("%s.scope must be an object" % prefix)
        scope = {}
    errors.extend(_validate_operator_map(scope, _supported_scope_operators(schema_version), "%s.scope" % prefix))
    errors.extend(_validate_scope_values(scope, "%s.scope" % prefix))
    errors.extend(_validate_scope_regexes(scope, "%s.scope" % prefix))

    match = rule.get("match")
    if not isinstance(match, dict):
        errors.append("%s.match must be an object" % prefix)
        match = {}
    supported_match_operators = _supported_match_operators(schema_version)
    errors.extend(_validate_operator_map(match, supported_match_operators, "%s.match" % prefix))
    errors.extend(_validate_regexes(match, "%s.match" % prefix))
    errors.extend(_validate_match_values(match, "%s.match" % prefix))
    errors.extend(_validate_match_shape(match, "%s.match" % prefix))
    if phase == "text_rewrite":
        errors.extend(_validate_text_rewrite_match(match, "%s.match" % prefix))
    elif phase == "flow":
        errors.extend(_validate_flow_match(match, "%s.match" % prefix))
    if not any(key in match for key in supported_match_operators):
        errors.append("%s.match must define at least one supported operator" % prefix)

    emit = rule.get("emit")
    if not isinstance(emit, dict):
        errors.append("%s.emit must be an object" % prefix)
        return errors
    errors.extend(_validate_emit(emit, phase, "%s.emit" % prefix, schema_version))
    if phase == "call_arg_rewrite":
        errors.extend(_validate_call_arg_rewrite_scope(scope, emit, "%s.scope" % prefix))
    elif phase == "text_rewrite":
        errors.extend(_validate_text_rewrite_scope(scope, "%s.scope" % prefix))
    return errors


def _validate_operator_map(data: dict[str, Any], supported: set[str], prefix: str) -> list[str]:
    errors = []
    for key in data:
        if key not in supported:
            errors.append("%s.%s is not supported" % (prefix, key))
    return errors


def _validate_regexes(match: dict[str, Any], prefix: str) -> list[str]:
    errors = []
    for key in ("regex", "assignment_regex", "before_regex", "flow_dispatcher_regex"):
        if key not in match:
            continue
        pattern = match.get(key)
        if not isinstance(pattern, str) or not pattern:
            errors.append("%s.%s must be a non-empty regex string" % (prefix, key))
            continue
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append("%s.%s invalid regex: %s" % (prefix, key, exc))
    return errors


def _validate_scope_values(scope: dict[str, Any], prefix: str) -> list[str]:
    errors = []
    for key in ("calls_any", "calls_all", "lvars_any", "requires_comment_kind", "text_contains_all"):
        if key in scope:
            errors.extend(_validate_string_or_string_list(scope.get(key), "%s.%s" % (prefix, key)))
    for key in ("prototype_contains", "text_contains"):
        if key in scope:
            errors.extend(_validate_non_empty_string(scope.get(key), "%s.%s" % (prefix, key)))
    if "target" in scope:
        errors.extend(_validate_target_selector(scope.get("target"), "%s.target" % prefix))
    errors.extend(_validate_typed_fact_values(scope, prefix))
    return errors


def _validate_match_values(match: dict[str, Any], prefix: str) -> list[str]:
    errors = []
    if "text_contains" in match:
        errors.extend(_validate_non_empty_string(match.get("text_contains"), "%s.text_contains" % prefix))
    if "text_contains_all" in match:
        errors.extend(_validate_string_or_string_list(match.get("text_contains_all"), "%s.text_contains_all" % prefix))
    if "call_arg_count" in match:
        errors.extend(_validate_call_arg_count_match(match.get("call_arg_count"), "%s.call_arg_count" % prefix))
    if "call_arg_literal" in match:
        errors.extend(_validate_call_arg_literal_match(match.get("call_arg_literal"), "%s.call_arg_literal" % prefix))
    if "flow_case_count_min" in match:
        errors.extend(_validate_flow_case_count_min(match.get("flow_case_count_min"), "%s.flow_case_count_min" % prefix))
    if "flow_body_state_any" in match:
        errors.extend(_validate_string_or_string_list(match.get("flow_body_state_any"), "%s.flow_body_state_any" % prefix))
    errors.extend(_validate_typed_fact_values(match, prefix))
    return errors


def _validate_match_shape(match: dict[str, Any], prefix: str) -> list[str]:
    primary_regexes = [key for key in ("regex", "assignment_regex", "before_regex") if key in match]
    if len(primary_regexes) > 1:
        return ["%s must not combine regex, assignment_regex, and before_regex" % prefix]
    primary_typed = [key for key in SUPPORTED_TYPED_FACT_OPERATORS if key in match]
    if len(primary_typed) > 1:
        return ["%s must not combine typed fact match operators" % prefix]
    if primary_regexes and primary_typed:
        return ["%s must not combine regex matchers with typed fact match operators" % prefix]
    fact_gate_operators = {
        "call_arg_count",
        "call_arg_literal",
        "flow_body_state_any",
        "flow_case_count_min",
        "flow_dispatcher_regex",
    }
    if primary_typed and any(key in match for key in fact_gate_operators):
        return ["%s must not combine typed fact match operators with call_arg or flow match gates" % prefix]
    return []


def _validate_text_rewrite_match(match: dict[str, Any], prefix: str) -> list[str]:
    if "before_regex" in match:
        return []
    return ["%s.before_regex is required for text_rewrite" % prefix]


def _validate_flow_match(match: dict[str, Any], prefix: str) -> list[str]:
    errors: list[str] = []
    if "flow_case_count_min" not in match:
        errors.append("%s.flow_case_count_min is required for flow" % prefix)
    for key in ("regex", "assignment_regex", "before_regex", "call_arg_count", "call_arg_literal"):
        if key in match:
            errors.append("%s.%s is not supported for flow" % (prefix, key))
    for key in SUPPORTED_TYPED_FACT_OPERATORS:
        if key in match:
            errors.append("%s.%s is not supported for flow" % (prefix, key))
    return errors


def _validate_typed_fact_values(data: dict[str, Any], prefix: str) -> list[str]:
    errors: list[str] = []
    if "lvar" in data:
        errors.extend(_validate_lvar_selector(data.get("lvar"), "%s.lvar" % prefix))
    if "assignment" in data:
        errors.extend(_validate_assignment_selector(data.get("assignment"), "%s.assignment" % prefix))
    if "call_site" in data:
        errors.extend(_validate_call_site_selector(data.get("call_site"), "%s.call_site" % prefix))
    if "profile_function" in data:
        errors.extend(_validate_profile_function_selector(data.get("profile_function"), "%s.profile_function" % prefix))
    return errors


def _validate_lvar_selector(value: object, prefix: str) -> list[str]:
    data, errors = _selector_object(value, prefix)
    if data is None:
        return errors
    allowed = {"index", "is_arg", "name", "name_regex", "type_contains", "type_regex"}
    errors.extend(_validate_selector_keys(data, allowed, prefix))
    errors.extend(_validate_selector_non_empty(data, prefix))
    for key in ("name", "type_contains"):
        if key in data:
            errors.extend(_validate_non_empty_string(data.get(key), "%s.%s" % (prefix, key)))
    for key in ("name_regex", "type_regex"):
        if key in data:
            errors.extend(_validate_regex_string(data.get(key), "%s.%s" % (prefix, key)))
    if "is_arg" in data and not isinstance(data.get("is_arg"), bool):
        errors.append("%s.is_arg must be a boolean" % prefix)
    if "index" in data:
        errors.extend(_validate_non_negative_integer(data.get("index"), "%s.index" % prefix))
    return errors


def _validate_assignment_selector(value: object, prefix: str) -> list[str]:
    data, errors = _selector_object(value, prefix)
    if data is None:
        return errors
    allowed = {
        "rhs_call_arg_contains",
        "rhs_call_arg_count",
        "rhs_call_arg_literal",
        "rhs_call_arg_regex",
        "rhs_call_name",
        "rhs_identifier_all",
        "rhs_identifier_any",
        "rhs_literal_all",
        "rhs_literal_any",
        "target",
        "target_regex",
    }
    errors.extend(_validate_selector_keys(data, allowed, prefix))
    errors.extend(_validate_selector_non_empty(data, prefix))
    for key in ("target", "rhs_call_name"):
        if key in data:
            errors.extend(_validate_non_empty_string(data.get(key), "%s.%s" % (prefix, key)))
    for key in ("target_regex",):
        if key in data:
            errors.extend(_validate_regex_string(data.get(key), "%s.%s" % (prefix, key)))
    for key in ("rhs_identifier_any", "rhs_identifier_all", "rhs_literal_any", "rhs_literal_all"):
        if key in data:
            errors.extend(_validate_string_or_string_list(data.get(key), "%s.%s" % (prefix, key)))
    if "rhs_call_arg_count" in data:
        errors.extend(_validate_non_negative_integer(data.get("rhs_call_arg_count"), "%s.rhs_call_arg_count" % prefix))
    for key in ("rhs_call_arg_literal", "rhs_call_arg_contains"):
        if key in data:
            errors.extend(_validate_argument_value_selector(data.get(key), "%s.%s" % (prefix, key), regex=False))
    if "rhs_call_arg_regex" in data:
        errors.extend(_validate_argument_value_selector(data.get("rhs_call_arg_regex"), "%s.rhs_call_arg_regex" % prefix, regex=True))
    return errors


def _validate_call_site_selector(value: object, prefix: str) -> list[str]:
    data, errors = _selector_object(value, prefix)
    if data is None:
        return errors
    allowed = {
        "arg_contains",
        "arg_count",
        "arg_literal",
        "arg_regex",
        "function_name",
        "function_name_regex",
    }
    errors.extend(_validate_selector_keys(data, allowed, prefix))
    errors.extend(_validate_selector_non_empty(data, prefix))
    if "function_name" in data:
        errors.extend(_validate_non_empty_string(data.get("function_name"), "%s.function_name" % prefix))
    if "function_name_regex" in data:
        errors.extend(_validate_regex_string(data.get("function_name_regex"), "%s.function_name_regex" % prefix))
    if "arg_count" in data:
        errors.extend(_validate_non_negative_integer(data.get("arg_count"), "%s.arg_count" % prefix))
    for key in ("arg_literal", "arg_contains"):
        if key in data:
            errors.extend(_validate_argument_value_selector(data.get(key), "%s.%s" % (prefix, key), regex=False))
    if "arg_regex" in data:
        errors.extend(_validate_argument_value_selector(data.get("arg_regex"), "%s.arg_regex" % prefix, regex=True))
    return errors


def _validate_profile_function_selector(value: object, prefix: str) -> list[str]:
    data, errors = _selector_object(value, prefix)
    if data is None:
        return errors
    allowed = {
        "alias_kind",
        "alias_of",
        "function_name",
        "function_name_regex",
        "header_contains",
        "param",
        "param_count",
        "return_type_contains",
        "return_type_regex",
    }
    errors.extend(_validate_selector_keys(data, allowed, prefix))
    errors.extend(_validate_selector_non_empty(data, prefix))
    for key in ("alias_kind", "alias_of", "function_name", "header_contains", "return_type_contains"):
        if key in data:
            errors.extend(_validate_non_empty_string(data.get(key), "%s.%s" % (prefix, key)))
    for key in ("function_name_regex", "return_type_regex"):
        if key in data:
            errors.extend(_validate_regex_string(data.get(key), "%s.%s" % (prefix, key)))
    if "param_count" in data:
        errors.extend(_validate_non_negative_integer(data.get("param_count"), "%s.param_count" % prefix))
    if "param" in data:
        errors.extend(_validate_profile_param_selector(data.get("param"), "%s.param" % prefix))
    return errors


def _validate_profile_param_selector(value: object, prefix: str) -> list[str]:
    data, errors = _selector_object(value, prefix)
    if data is None:
        return errors
    allowed = {"enum", "index", "kind", "name", "type_contains", "type_regex"}
    errors.extend(_validate_selector_keys(data, allowed, prefix))
    errors.extend(_validate_selector_non_empty(data, prefix))
    if "index" not in data:
        errors.append("%s.index is required" % prefix)
    else:
        errors.extend(_validate_non_negative_integer(data.get("index"), "%s.index" % prefix))
    for key in ("enum", "kind", "name", "type_contains"):
        if key in data:
            errors.extend(_validate_non_empty_string(data.get(key), "%s.%s" % (prefix, key)))
    if "type_regex" in data:
        errors.extend(_validate_regex_string(data.get("type_regex"), "%s.type_regex" % prefix))
    return errors


def _validate_target_selector(value: object, prefix: str) -> list[str]:
    data, errors = _selector_object(value, prefix)
    if data is None:
        return errors
    allowed = {
        "abi",
        "architecture",
        "compiler_family",
        "endianness",
        "format",
        "image_name",
        "image_name_regex",
        "language_runtime",
        "platform",
        "privilege_domain",
        "source_path",
        "source_path_regex",
        "symbol_state",
    }
    errors.extend(_validate_selector_keys(data, allowed, prefix))
    errors.extend(_validate_selector_non_empty(data, prefix))
    for key in (
        "abi",
        "architecture",
        "compiler_family",
        "endianness",
        "format",
        "image_name",
        "language_runtime",
        "platform",
        "privilege_domain",
        "source_path",
        "symbol_state",
    ):
        if key in data:
            errors.extend(_validate_string_or_string_list(data.get(key), "%s.%s" % (prefix, key)))
    for key in ("image_name_regex", "source_path_regex"):
        if key in data:
            errors.extend(_validate_regex_string(data.get(key), "%s.%s" % (prefix, key)))
    return errors


def _validate_argument_value_selector(value: object, prefix: str, regex: bool) -> list[str]:
    data, errors = _selector_object(value, prefix)
    if data is None:
        return errors
    value_key = "regex" if regex else "value"
    allowed = {"argument_index", value_key}
    errors.extend(_validate_selector_keys(data, allowed, prefix))
    if "argument_index" not in data:
        errors.append("%s.argument_index is required" % prefix)
    else:
        errors.extend(_validate_non_negative_integer(data.get("argument_index"), "%s.argument_index" % prefix))
    if value_key not in data:
        errors.append("%s.%s is required" % (prefix, value_key))
    elif regex:
        errors.extend(_validate_regex_string(data.get(value_key), "%s.%s" % (prefix, value_key)))
    else:
        errors.extend(_validate_non_empty_string(data.get(value_key), "%s.%s" % (prefix, value_key)))
    return errors


def _selector_object(value: object, prefix: str) -> tuple[dict[str, Any] | None, list[str]]:
    if isinstance(value, dict):
        return value, []
    return None, ["%s must be an object" % prefix]


def _validate_selector_keys(data: dict[str, Any], allowed: set[str], prefix: str) -> list[str]:
    return ["%s.%s is not supported" % (prefix, key) for key in data if key not in allowed]


def _validate_selector_non_empty(data: dict[str, Any], prefix: str) -> list[str]:
    if data:
        return []
    return ["%s must define at least one selector field" % prefix]


def _validate_regex_string(value: object, prefix: str) -> list[str]:
    errors = _validate_non_empty_string(value, prefix)
    if errors:
        return errors
    try:
        re.compile(str(value))
    except re.error as exc:
        return ["%s invalid regex: %s" % (prefix, exc)]
    return []


def _validate_non_negative_integer(value: object, prefix: str) -> list[str]:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return []
    return ["%s must be a non-negative integer" % prefix]


def _validate_scope_regexes(scope: dict[str, Any], prefix: str) -> list[str]:
    errors = []
    pattern = scope.get("function_name_regex")
    if pattern is None:
        return errors
    if not isinstance(pattern, str) or not pattern:
        errors.append("%s.function_name_regex must be a non-empty regex string" % prefix)
        return errors
    try:
        re.compile(pattern)
    except re.error as exc:
        errors.append("%s.function_name_regex invalid regex: %s" % (prefix, exc))
    return errors


def _validate_non_empty_string(value: object, prefix: str) -> list[str]:
    if isinstance(value, str) and value:
        return []
    return ["%s must be a non-empty string" % prefix]


def _validate_string_or_string_list(value: object, prefix: str) -> list[str]:
    if isinstance(value, str):
        if value:
            return []
        return ["%s must be a non-empty string or non-empty string list" % prefix]
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return []
    return ["%s must be a non-empty string or non-empty string list" % prefix]


def _validate_call_arg_count_match(value: object, prefix: str) -> list[str]:
    if not isinstance(value, dict):
        return ["%s must be an object" % prefix]
    errors: list[str] = []
    errors.extend(_validate_non_empty_string(value.get("function_name"), "%s.function_name" % prefix))
    count = value.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        errors.append("%s.count must be a non-negative integer" % prefix)
    return errors


def _validate_call_arg_literal_match(value: object, prefix: str) -> list[str]:
    if not isinstance(value, dict):
        return ["%s must be an object" % prefix]
    errors: list[str] = []
    errors.extend(_validate_non_empty_string(value.get("function_name"), "%s.function_name" % prefix))
    argument_index = value.get("argument_index")
    if not isinstance(argument_index, int) or isinstance(argument_index, bool) or argument_index < 0:
        errors.append("%s.argument_index must be a non-negative integer" % prefix)
    errors.extend(_validate_non_empty_string(value.get("value"), "%s.value" % prefix))
    return errors


def _validate_flow_case_count_min(value: object, prefix: str) -> list[str]:
    if not isinstance(value, int) or isinstance(value, bool) or value < 3:
        return ["%s must be an integer >= 3" % prefix]
    return []


def _is_real_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_emit(emit: dict[str, Any], phase: object, prefix: str, schema_version: int) -> list[str]:
    errors: list[str] = []
    kind = emit.get("kind")
    supported_kinds = _supported_emission_kinds(schema_version)
    if kind not in supported_kinds:
        errors.append("%s.kind must be one of %s" % (prefix, ", ".join(sorted(supported_kinds))))
        return errors
    if phase != kind:
        errors.append("%s.kind must match rule phase" % prefix)

    if kind == "rename":
        for field_name in ("target", "new_name"):
            if not isinstance(emit.get(field_name), str) or not emit.get(field_name):
                errors.append("%s.%s is required" % (prefix, field_name))
        rename_kind = emit.get("rename_kind", "lvar")
        if not isinstance(rename_kind, str) or not rename_kind:
            errors.append("%s.rename_kind must be a string" % prefix)
    elif kind == "semantic_comment":
        for field_name in ("comment_kind", "text"):
            if not isinstance(emit.get(field_name), str) or not emit.get(field_name):
                errors.append("%s.%s is required" % (prefix, field_name))
    elif kind == "call_arg_rewrite":
        errors.extend(_validate_call_arg_rewrite_emit(emit, prefix))
    elif kind == "flow":
        errors.extend(_validate_flow_emit(emit, prefix))
    elif kind == "text_rewrite":
        errors.extend(_validate_text_rewrite_emit(emit, prefix))
    return errors


def _validate_call_arg_rewrite_emit(emit: dict[str, Any], prefix: str) -> list[str]:
    errors: list[str] = []
    for field_name in ("function_name", "replacement"):
        if not isinstance(emit.get(field_name), str) or not emit.get(field_name):
            errors.append("%s.%s is required" % (prefix, field_name))
    argument_index = emit.get("argument_index")
    if not isinstance(argument_index, int) or isinstance(argument_index, bool) or argument_index < 0:
        errors.append("%s.argument_index must be a non-negative integer" % prefix)
    if emit.get("preview_only") is not True:
        errors.append("%s.preview_only must be true" % prefix)
    return errors


def _validate_text_rewrite_emit(emit: dict[str, Any], prefix: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(emit.get("replacement"), str) or not emit.get("replacement"):
        errors.append("%s.replacement is required" % prefix)
    if emit.get("preview_only") is not True:
        errors.append("%s.preview_only must be true" % prefix)
    return errors


def _validate_flow_emit(emit: dict[str, Any], prefix: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(emit.get("flow_kind"), str) or not emit.get("flow_kind"):
        errors.append("%s.flow_kind is required" % prefix)
    if "summary" in emit and not isinstance(emit.get("summary"), str):
        errors.append("%s.summary must be a string" % prefix)
    if emit.get("preview_only") is not True:
        errors.append("%s.preview_only must be true" % prefix)
    return errors


def _validate_call_arg_rewrite_scope(scope: dict[str, Any], emit: dict[str, Any], prefix: str) -> list[str]:
    function_name = emit.get("function_name")
    if not isinstance(function_name, str) or not function_name:
        return []
    if "$" in function_name:
        if _has_call_scope_gate(scope):
            return []
        return ["%s must gate call_arg_rewrite with calls_any/calls_all or call_site" % prefix]
    if _scope_calls_include(scope.get("calls_any"), function_name):
        return []
    if _scope_calls_include(scope.get("calls_all"), function_name):
        return []
    if _scope_call_site_includes(scope.get("call_site"), function_name):
        return []
    return ["%s must gate call_arg_rewrite with calls_any/calls_all or call_site for %s" % (prefix, function_name)]


def _validate_text_rewrite_scope(scope: dict[str, Any], prefix: str) -> list[str]:
    if "requires_comment_kind" in scope:
        return []
    return ["%s.requires_comment_kind is required for text_rewrite" % prefix]


def _has_call_scope_gate(scope: dict[str, Any]) -> bool:
    return "calls_any" in scope or "calls_all" in scope or _scope_has_call_site_function_gate(scope.get("call_site"))


def _scope_calls_include(value: object, function_name: str) -> bool:
    if isinstance(value, str):
        return value == function_name
    if isinstance(value, list):
        return function_name in value
    return False


def _scope_has_call_site_function_gate(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    function_name = value.get("function_name")
    function_name_regex = value.get("function_name_regex")
    return bool(function_name) or bool(function_name_regex)


def _scope_call_site_includes(value: object, function_name: str) -> bool:
    if not isinstance(value, dict):
        return False
    exact = value.get("function_name")
    if isinstance(exact, str) and exact == function_name:
        return True
    pattern = value.get("function_name_regex")
    if isinstance(pattern, str) and pattern:
        try:
            return re.search(pattern, function_name) is not None
        except re.error:
            return False
    return False


def _is_supported_schema_version(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value in SUPPORTED_SCHEMA_VERSIONS


def _supported_phases(schema_version: int) -> set[str]:
    if schema_version <= 1:
        return SUPPORTED_V1_PHASES
    return SUPPORTED_V2_PHASES


def _supported_emission_kinds(schema_version: int) -> set[str]:
    if schema_version <= 1:
        return SUPPORTED_V1_EMISSION_KINDS
    return SUPPORTED_V2_EMISSION_KINDS


def _supported_match_operators(schema_version: int) -> set[str]:
    if schema_version <= 1:
        return SUPPORTED_V1_MATCH_OPERATORS
    return SUPPORTED_V2_MATCH_OPERATORS


def _supported_scope_operators(schema_version: int) -> set[str]:
    if schema_version <= 1:
        return SUPPORTED_V1_SCOPE_OPERATORS
    return SUPPORTED_V2_SCOPE_OPERATORS


def _contains_forbidden_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if normalized in FORBIDDEN_RULE_KEYS:
                return True
            if _contains_forbidden_key(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False

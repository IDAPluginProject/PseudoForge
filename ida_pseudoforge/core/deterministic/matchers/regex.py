from __future__ import annotations

import re
from typing import Any

from ida_pseudoforge.core.deterministic.context import (
    AssignmentFact,
    CallSiteFact,
    FlowFact,
    LvarFact,
    ProfileFunctionFact,
    RuleContext,
)
from ida_pseudoforge.core.deterministic.schema import Rule, RuleMatch

_TYPED_FACT_OPERATORS = {"assignment", "call_site", "lvar", "profile_function"}


def match_regex_rule(rule: Rule, context: RuleContext) -> list[RuleMatch]:
    if not _scope_matches(rule, context):
        return []
    match_data = rule.match or {}
    if not _match_text_gates(match_data, context.text):
        return []
    call_arg_matches = _call_arg_gate_matches(match_data, context)
    if call_arg_matches == []:
        return []
    flow_matches = _flow_gate_matches(match_data, context)
    if flow_matches == []:
        return []
    typed_matches = _typed_fact_matches(rule, match_data, context)
    if typed_matches == []:
        return []
    if "assignment_regex" in match_data:
        return _regex_matches(rule, context, str(match_data.get("assignment_regex", "")), assignment=True)
    if "before_regex" in match_data:
        return _regex_matches(rule, context, str(match_data.get("before_regex", "")), assignment=False)
    if "regex" in match_data:
        return _regex_matches(rule, context, str(match_data.get("regex", "")), assignment=False)
    if call_arg_matches is not None:
        return [
            RuleMatch(
                rule_id=rule.id,
                phase=rule.phase,
                confidence=rule.confidence,
                bindings={},
                span=call_site.span,
                evidence=str(rule.emit.get("evidence", "") or rule.id),
                emission_kind=str(rule.emit.get("kind", "")),
            )
            for call_site in call_arg_matches
        ]
    if flow_matches is not None:
        return [
            RuleMatch(
                rule_id=rule.id,
                phase=rule.phase,
                confidence=rule.confidence,
                bindings={
                    "dispatcher": flow.dispatcher,
                    "case_count": str(len(flow.recovered_cases)),
                    "flow_kind": flow.kind,
                },
                span=None,
                evidence=str(rule.emit.get("evidence", "") or flow.evidence or rule.id),
                emission_kind=str(rule.emit.get("kind", "")),
                metadata={"flow": _flow_fact_payload(flow)},
            )
            for flow in flow_matches
        ]
    if typed_matches is not None:
        return typed_matches
    if _has_text_match_operator(match_data):
        return [
            RuleMatch(
                rule_id=rule.id,
                phase=rule.phase,
                confidence=rule.confidence,
                bindings={},
                span=None,
                evidence=str(rule.emit.get("evidence", "") or rule.id),
                emission_kind=str(rule.emit.get("kind", "")),
            )
        ]
    return []


def _regex_matches(rule: Rule, context: RuleContext, pattern: str, assignment: bool) -> list[RuleMatch]:
    if not pattern:
        return []
    flags = re.MULTILINE
    if assignment:
        flags |= re.DOTALL
    result = []
    for match in re.finditer(pattern, context.text, flags=flags):
        result.append(
            RuleMatch(
                rule_id=rule.id,
                phase=rule.phase,
                confidence=rule.confidence,
                bindings={key: str(value) for key, value in match.groupdict().items() if value is not None},
                span=match.span(),
                evidence=str(rule.emit.get("evidence", "") or rule.id),
                emission_kind=str(rule.emit.get("kind", "")),
            )
        )
    return result


def _regex_matches_for_pattern(context: RuleContext, pattern: str, assignment: bool) -> bool:
    flags = re.MULTILINE
    if assignment:
        flags |= re.DOTALL
    return re.search(pattern, context.text, flags=flags) is not None


def _scope_matches(rule: Rule, context: RuleContext) -> bool:
    scope = rule.scope or {}
    for key, value in scope.items():
        if key == "calls_any":
            if not _any_string_in_set(value, context.calls):
                return False
        elif key == "calls_all":
            if not _all_strings_in_set(value, context.calls):
                return False
        elif key == "lvars_any":
            if not _any_string_in_set(value, context.lvar_names):
                return False
        elif key == "function_name_regex":
            if re.search(str(value), context.capture.name or "") is None:
                return False
        elif key == "prototype_contains":
            if str(value) not in (context.capture.prototype or ""):
                return False
        elif key == "requires_comment_kind":
            if not _any_string_in_set(value, context.semantic_comment_kinds):
                return False
        elif key == "text_contains":
            if str(value) not in context.text:
                return False
        elif key == "text_contains_all":
            if not _all_strings_in_text(value, context.text):
                return False
        elif key in _TYPED_FACT_OPERATORS:
            if not _typed_scope_matches(str(key), value, context):
                return False
        else:
            return False
    return True


def explain_rule_miss(rule: Rule, context: RuleContext) -> list[str]:
    reasons = _scope_miss_reasons(rule, context)
    if reasons:
        return reasons
    match_data = rule.match or {}
    reasons.extend(_match_miss_reasons(match_data, context))
    if reasons:
        return reasons
    if match_regex_rule(rule, context):
        return []
    return ["rule did not produce a match"]


def _scope_miss_reasons(rule: Rule, context: RuleContext) -> list[str]:
    reasons = []
    scope = rule.scope or {}
    for key, value in scope.items():
        if key == "calls_any" and not _any_string_in_set(value, context.calls):
            reasons.append("scope.calls_any missing: %s" % _join_values(value))
        elif key == "calls_all" and not _all_strings_in_set(value, context.calls):
            reasons.append("scope.calls_all missing: %s" % _join_values(value))
        elif key == "lvars_any" and not _any_string_in_set(value, context.lvar_names):
            reasons.append("scope.lvars_any missing: %s" % _join_values(value))
        elif key == "function_name_regex" and re.search(str(value), context.capture.name or "") is None:
            reasons.append("scope.function_name_regex did not match function name")
        elif key == "prototype_contains" and str(value) not in (context.capture.prototype or ""):
            reasons.append("scope.prototype_contains not present")
        elif key == "requires_comment_kind" and not _any_string_in_set(value, context.semantic_comment_kinds):
            reasons.append("scope.requires_comment_kind missing: %s" % _join_values(value))
        elif key == "text_contains" and str(value) not in context.text:
            reasons.append("scope.text_contains not present")
        elif key == "text_contains_all" and not _all_strings_in_text(value, context.text):
            reasons.append("scope.text_contains_all not fully present: %s" % _join_values(value))
        elif key in _TYPED_FACT_OPERATORS and not _typed_scope_matches(str(key), value, context):
            reasons.append("scope.%s did not match any fact" % key)
        elif key not in {
            "calls_all",
            "calls_any",
            "function_name_regex",
            "lvars_any",
            "prototype_contains",
            "requires_comment_kind",
            "text_contains",
            "text_contains_all",
        } | _TYPED_FACT_OPERATORS:
            reasons.append("scope.%s is unsupported at runtime" % key)
    return reasons


def _match_miss_reasons(match_data: dict[str, object], context: RuleContext) -> list[str]:
    reasons = []
    if "text_contains" in match_data and str(match_data.get("text_contains", "")) not in context.text:
        reasons.append("match.text_contains not present")
    if "text_contains_all" in match_data and not _all_strings_in_text(match_data.get("text_contains_all"), context.text):
        reasons.append("match.text_contains_all not fully present: %s" % _join_values(match_data.get("text_contains_all")))
    if reasons:
        return reasons
    call_arg_matches = _call_arg_gate_matches(match_data, context)
    if call_arg_matches == []:
        reasons.append("match call-argument gates did not match a single call site")
    flow_matches = _flow_gate_matches(match_data, context)
    if flow_matches == []:
        reasons.append("match flow gates did not match recovered flow facts")
    typed_matches = _typed_fact_matches(None, match_data, context)
    if typed_matches == []:
        typed_key = next((key for key in _TYPED_FACT_OPERATORS if key in match_data), "typed fact")
        reasons.append("match.%s did not match any fact" % typed_key)
    if reasons:
        return reasons
    for key, assignment in (("assignment_regex", True), ("before_regex", False), ("regex", False)):
        pattern = str(match_data.get(key, "") or "")
        if pattern and not _regex_matches_for_pattern(context, pattern, assignment):
            return ["match.%s did not match text" % key]
    if not any(key in match_data for key in _TYPED_FACT_OPERATORS | {"assignment_regex", "before_regex", "call_arg_count", "call_arg_literal", "flow_body_state_any", "flow_case_count_min", "flow_dispatcher_regex", "regex", "text_contains", "text_contains_all"}):
        return ["match has no supported runtime operator"]
    return []


def _match_text_gates(match_data: dict[str, object], text: str) -> bool:
    if "text_contains" in match_data and str(match_data.get("text_contains", "")) not in text:
        return False
    if "text_contains_all" in match_data and not _all_strings_in_text(match_data.get("text_contains_all"), text):
        return False
    return True


def _call_arg_gate_matches(match_data: dict[str, object], context: RuleContext) -> list[CallSiteFact] | None:
    gates = []
    if "call_arg_count" in match_data:
        gates.append(("count", match_data.get("call_arg_count")))
    if "call_arg_literal" in match_data:
        gates.append(("literal", match_data.get("call_arg_literal")))
    if not gates:
        return None
    result = []
    for call_site in context.call_sites:
        if all(_call_site_matches_gate(call_site, kind, value) for kind, value in gates):
            result.append(call_site)
    return result


def _flow_gate_matches(match_data: dict[str, object], context: RuleContext) -> list[FlowFact] | None:
    gates = []
    if "flow_case_count_min" in match_data:
        gates.append(("case_count_min", match_data.get("flow_case_count_min")))
    if "flow_dispatcher_regex" in match_data:
        gates.append(("dispatcher_regex", match_data.get("flow_dispatcher_regex")))
    if "flow_body_state_any" in match_data:
        gates.append(("body_state_any", match_data.get("flow_body_state_any")))
    if not gates:
        return None
    result = []
    for flow in context.flow_facts:
        if all(_flow_matches_gate(flow, kind, value) for kind, value in gates):
            result.append(flow)
    return result


def _flow_matches_gate(flow: FlowFact, kind: str, value: object) -> bool:
    if kind == "case_count_min":
        if not isinstance(value, int) or isinstance(value, bool) or value < 3:
            return False
        return len(flow.recovered_cases) >= value
    if kind == "dispatcher_regex":
        if not isinstance(value, str) or not value:
            return False
        return re.search(value, flow.dispatcher or "") is not None
    if kind == "body_state_any":
        states = _string_list(value)
        if not states:
            return False
        present = {str(item) for item in flow.case_body_states.values()}
        return any(state in present for state in states)
    return False


def _flow_fact_payload(flow: FlowFact) -> dict[str, object]:
    return {
        "flow_kind": flow.kind,
        "dispatcher": flow.dispatcher,
        "case_count": len(flow.recovered_cases),
        "recovered_cases": list(flow.recovered_cases),
        "case_body_states": {str(key): value for key, value in flow.case_body_states.items()},
        "case_anchors": {str(key): value for key, value in flow.case_anchors.items()},
        "case_labels": {str(key): value for key, value in flow.case_labels.items()},
        "flow_confidence": flow.confidence,
        "export_only": flow.export_only,
        "flow_evidence": flow.evidence,
    }


def _typed_fact_matches(rule: Rule | None, match_data: dict[str, object], context: RuleContext) -> list[RuleMatch] | None:
    for key in sorted(_TYPED_FACT_OPERATORS):
        if key in match_data:
            return _typed_matches_for(rule, key, match_data.get(key), context)
    return None


def _typed_scope_matches(kind: str, selector: object, context: RuleContext) -> bool:
    return bool(_typed_matches_for(None, kind, selector, context))


def _typed_matches_for(rule: Rule | None, kind: str, selector: object, context: RuleContext) -> list[RuleMatch]:
    if not isinstance(selector, dict) or not selector:
        return []
    if kind == "lvar":
        return [
            _fact_rule_match(
                rule,
                span=None,
                bindings=_lvar_bindings(fact),
                metadata={"lvar": _lvar_payload(fact)},
            )
            for fact in context.lvar_facts
            if _lvar_matches(fact, selector)
        ]
    if kind == "assignment":
        return [
            _fact_rule_match(
                rule,
                span=fact.span,
                bindings=_assignment_bindings(fact),
                metadata={"assignment": _assignment_payload(fact)},
            )
            for fact in context.assignments
            if _assignment_matches(fact, selector)
        ]
    if kind == "call_site":
        return [
            _fact_rule_match(
                rule,
                span=fact.span,
                bindings=_call_site_bindings(fact),
                metadata={"call_site": _call_site_payload(fact)},
            )
            for fact in context.call_sites
            if _call_site_selector_matches(fact, selector)
        ]
    if kind == "profile_function":
        return [
            _fact_rule_match(
                rule,
                span=None,
                bindings=_profile_function_bindings(fact, selector),
                metadata={"profile_function": _profile_function_payload(fact)},
            )
            for fact in context.profile_functions.values()
            if _profile_function_matches(fact, selector)
        ]
    return []


def _fact_rule_match(
    rule: Rule | None,
    span: tuple[int, int] | None,
    bindings: dict[str, str],
    metadata: dict[str, Any],
) -> RuleMatch:
    if isinstance(rule, Rule):
        return RuleMatch(
            rule_id=rule.id,
            phase=rule.phase,
            confidence=rule.confidence,
            bindings=bindings,
            span=span,
            evidence=str(rule.emit.get("evidence", "") or rule.id),
            emission_kind=str(rule.emit.get("kind", "")),
            metadata=metadata,
        )
    return RuleMatch(
        rule_id="",
        phase="",
        confidence=0.0,
        bindings=bindings,
        span=span,
        evidence="typed fact match",
        metadata=metadata,
    )


def _lvar_matches(fact: LvarFact, selector: dict[str, object]) -> bool:
    if "name" in selector and fact.name != str(selector.get("name", "")):
        return False
    if "name_regex" in selector and re.search(str(selector.get("name_regex", "")), fact.name or "") is None:
        return False
    if "type_contains" in selector and str(selector.get("type_contains", "")) not in (fact.type or ""):
        return False
    if "type_regex" in selector and re.search(str(selector.get("type_regex", "")), fact.type or "") is None:
        return False
    if "is_arg" in selector and fact.is_arg is not bool(selector.get("is_arg")):
        return False
    if "index" in selector and fact.index != selector.get("index"):
        return False
    return True


def _assignment_matches(fact: AssignmentFact, selector: dict[str, object]) -> bool:
    if "target" in selector and fact.target != str(selector.get("target", "")):
        return False
    if "target_regex" in selector and re.search(str(selector.get("target_regex", "")), fact.target or "") is None:
        return False
    if "rhs_identifier_any" in selector and not _any_string_in_set(selector.get("rhs_identifier_any"), set(fact.rhs_identifiers)):
        return False
    if "rhs_identifier_all" in selector and not _all_strings_in_set(selector.get("rhs_identifier_all"), set(fact.rhs_identifiers)):
        return False
    if "rhs_literal_any" in selector and not _any_string_in_set(selector.get("rhs_literal_any"), set(fact.rhs_literals)):
        return False
    if "rhs_literal_all" in selector and not _all_strings_in_set(selector.get("rhs_literal_all"), set(fact.rhs_literals)):
        return False
    if "rhs_call_name" in selector and fact.rhs_call_name != str(selector.get("rhs_call_name", "")):
        return False
    if "rhs_call_arg_count" in selector and len(fact.rhs_call_arguments) != selector.get("rhs_call_arg_count"):
        return False
    if "rhs_call_arg_literal" in selector and not _argument_value_matches(fact.rhs_call_arguments, selector.get("rhs_call_arg_literal"), mode="literal"):
        return False
    if "rhs_call_arg_contains" in selector and not _argument_value_matches(fact.rhs_call_arguments, selector.get("rhs_call_arg_contains"), mode="contains"):
        return False
    if "rhs_call_arg_regex" in selector and not _argument_value_matches(fact.rhs_call_arguments, selector.get("rhs_call_arg_regex"), mode="regex"):
        return False
    return True


def _call_site_selector_matches(fact: CallSiteFact, selector: dict[str, object]) -> bool:
    if "function_name" in selector and fact.name != str(selector.get("function_name", "")):
        return False
    if "function_name_regex" in selector and re.search(str(selector.get("function_name_regex", "")), fact.name or "") is None:
        return False
    if "arg_count" in selector and len(fact.arguments) != selector.get("arg_count"):
        return False
    if "arg_literal" in selector and not _argument_value_matches(fact.arguments, selector.get("arg_literal"), mode="literal"):
        return False
    if "arg_contains" in selector and not _argument_value_matches(fact.arguments, selector.get("arg_contains"), mode="contains"):
        return False
    if "arg_regex" in selector and not _argument_value_matches(fact.arguments, selector.get("arg_regex"), mode="regex"):
        return False
    return True


def _profile_function_matches(fact: ProfileFunctionFact, selector: dict[str, object]) -> bool:
    if "function_name" in selector and fact.name != str(selector.get("function_name", "")):
        return False
    if "function_name_regex" in selector and re.search(str(selector.get("function_name_regex", "")), fact.name or "") is None:
        return False
    if "header_contains" in selector and str(selector.get("header_contains", "")) not in (fact.header or ""):
        return False
    if "return_type_contains" in selector and str(selector.get("return_type_contains", "")) not in (fact.return_type or ""):
        return False
    if "return_type_regex" in selector and re.search(str(selector.get("return_type_regex", "")), fact.return_type or "") is None:
        return False
    if "param_count" in selector and fact.param_count != selector.get("param_count"):
        return False
    if "alias_of" in selector and fact.alias_of != str(selector.get("alias_of", "")):
        return False
    if "alias_kind" in selector and fact.alias_kind != str(selector.get("alias_kind", "")):
        return False
    if "param" in selector and not _profile_param_matches(fact, selector.get("param")):
        return False
    return True


def _profile_param_matches(fact: ProfileFunctionFact, selector: object) -> bool:
    if not isinstance(selector, dict):
        return False
    index = selector.get("index")
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        return False
    if index >= fact.param_count:
        return False
    name = fact.parameter_names[index] if index < len(fact.parameter_names) else ""
    type_text = fact.parameter_types[index] if index < len(fact.parameter_types) else ""
    kind = fact.parameter_kinds[index] if index < len(fact.parameter_kinds) else ""
    enum = fact.parameter_enums[index] if index < len(fact.parameter_enums) else ""
    if "name" in selector and name != str(selector.get("name", "")):
        return False
    if "type_contains" in selector and str(selector.get("type_contains", "")) not in type_text:
        return False
    if "type_regex" in selector and re.search(str(selector.get("type_regex", "")), type_text) is None:
        return False
    if "kind" in selector and kind != str(selector.get("kind", "")):
        return False
    if "enum" in selector and enum != str(selector.get("enum", "")):
        return False
    return True


def _argument_value_matches(arguments: list[str], selector: object, mode: str) -> bool:
    if not isinstance(selector, dict):
        return False
    argument_index = selector.get("argument_index")
    if not isinstance(argument_index, int) or isinstance(argument_index, bool) or argument_index < 0:
        return False
    if argument_index >= len(arguments):
        return False
    argument = arguments[argument_index].strip()
    if mode == "literal":
        return argument == str(selector.get("value", ""))
    if mode == "contains":
        return str(selector.get("value", "")) in argument
    if mode == "regex":
        return re.search(str(selector.get("regex", "")), argument) is not None
    return False


def _lvar_bindings(fact: LvarFact) -> dict[str, str]:
    return {
        "lvar": fact.name,
        "lvar_index": str(fact.index),
        "lvar_location": fact.location,
        "lvar_name": fact.name,
        "lvar_type": fact.type,
    }


def _assignment_bindings(fact: AssignmentFact) -> dict[str, str]:
    bindings = {
        "assignment_rhs": fact.expression,
        "assignment_target": fact.target,
        "rhs_call": fact.rhs_call_name,
    }
    for index, argument in enumerate(fact.rhs_call_arguments):
        bindings["rhs_arg%d" % index] = argument
    return bindings


def _call_site_bindings(fact: CallSiteFact) -> dict[str, str]:
    bindings = {
        "call": fact.name,
        "call_line": str(fact.line_index),
        "call_name": fact.name,
    }
    for index, argument in enumerate(fact.arguments):
        bindings["call_arg%d" % index] = argument
    return bindings


def _profile_function_bindings(fact: ProfileFunctionFact, selector: dict[str, object]) -> dict[str, str]:
    bindings = {
        "profile_alias_kind": fact.alias_kind,
        "profile_alias_of": fact.alias_of,
        "profile_function": fact.name,
        "profile_header": fact.header,
        "profile_return_type": fact.return_type,
    }
    param = selector.get("param")
    if isinstance(param, dict):
        index = param.get("index")
        if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < fact.param_count:
            bindings["profile_param_index"] = str(index)
            bindings["profile_param_name"] = fact.parameter_names[index] if index < len(fact.parameter_names) else ""
            bindings["profile_param_type"] = fact.parameter_types[index] if index < len(fact.parameter_types) else ""
            bindings["profile_param_kind"] = fact.parameter_kinds[index] if index < len(fact.parameter_kinds) else ""
            bindings["profile_param_enum"] = fact.parameter_enums[index] if index < len(fact.parameter_enums) else ""
    return bindings


def _lvar_payload(fact: LvarFact) -> dict[str, object]:
    return {
        "identity": fact.identity,
        "index": fact.index,
        "is_arg": fact.is_arg,
        "location": fact.location,
        "name": fact.name,
        "type": fact.type,
    }


def _assignment_payload(fact: AssignmentFact) -> dict[str, object]:
    return {
        "expression": fact.expression,
        "rhs_call_arguments": list(fact.rhs_call_arguments),
        "rhs_call_name": fact.rhs_call_name,
        "rhs_identifiers": list(fact.rhs_identifiers),
        "rhs_literals": list(fact.rhs_literals),
        "span": list(fact.span),
        "target": fact.target,
    }


def _call_site_payload(fact: CallSiteFact) -> dict[str, object]:
    return {
        "argument_spans": [list(span) for span in fact.argument_spans],
        "arguments": list(fact.arguments),
        "line_index": fact.line_index,
        "name": fact.name,
        "span": list(fact.span),
    }


def _profile_function_payload(fact: ProfileFunctionFact) -> dict[str, object]:
    return {
        "alias_kind": fact.alias_kind,
        "alias_of": fact.alias_of,
        "header": fact.header,
        "name": fact.name,
        "param_count": fact.param_count,
        "parameter_enums": list(fact.parameter_enums),
        "parameter_kinds": list(fact.parameter_kinds),
        "parameter_names": list(fact.parameter_names),
        "parameter_types": list(fact.parameter_types),
        "return_type": fact.return_type,
    }


def _call_site_matches_gate(call_site: CallSiteFact, kind: str, value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if call_site.name != str(value.get("function_name", "")):
        return False
    if kind == "count":
        count = value.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            return False
        return len(call_site.arguments) == count
    if kind == "literal":
        argument_index = value.get("argument_index")
        expected = value.get("value")
        if not isinstance(argument_index, int) or isinstance(argument_index, bool) or argument_index < 0:
            return False
        if not isinstance(expected, str) or expected == "":
            return False
        if argument_index >= len(call_site.arguments):
            return False
        return call_site.arguments[argument_index].strip() == expected
    return False


def _has_text_match_operator(match_data: dict[str, object]) -> bool:
    return "text_contains" in match_data or "text_contains_all" in match_data


def _any_string_in_set(value: object, candidates: set[str]) -> bool:
    values = _string_list(value)
    return any(item in candidates for item in values)


def _all_strings_in_set(value: object, candidates: set[str]) -> bool:
    values = _string_list(value)
    return bool(values) and all(item in candidates for item in values)


def _all_strings_in_text(value: object, text: str) -> bool:
    values = _string_list(value)
    return bool(values) and all(item in text for item in values)


def _join_values(value: object) -> str:
    return ", ".join(_string_list(value))


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]

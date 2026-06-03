from __future__ import annotations

from typing import Any

from ida_pseudoforge.core.deterministic.context import RuleContext


SCAFFOLD_KINDS = {
    "assignment-rename",
    "call-arg-rewrite",
    "exact-local-rename",
    "flow-report",
    "semantic-comment",
    "text-rewrite",
}


def rule_context_fact_payload(context: RuleContext) -> dict[str, Any]:
    return {
        "function": {
            "name": context.capture.name,
            "prototype": context.capture.prototype,
        },
        "calls": sorted(context.calls),
        "lvars": [
            {
                "identity": item.identity,
                "index": item.index,
                "is_arg": item.is_arg,
                "location": item.location,
                "name": item.name,
                "type": item.type,
            }
            for item in context.lvar_facts
        ],
        "assignments": [
            {
                "expression": item.expression,
                "rhs_call_arguments": list(item.rhs_call_arguments),
                "rhs_call_name": item.rhs_call_name,
                "rhs_identifiers": list(item.rhs_identifiers),
                "rhs_literals": list(item.rhs_literals),
                "span": list(item.span),
                "target": item.target,
            }
            for item in context.assignments
        ],
        "call_sites": [
            {
                "argument_spans": [list(span) for span in item.argument_spans],
                "arguments": list(item.arguments),
                "line_index": item.line_index,
                "name": item.name,
                "span": list(item.span),
            }
            for item in context.call_sites
        ],
        "profile_functions": [
            {
                "alias_kind": item.alias_kind,
                "alias_of": item.alias_of,
                "header": item.header,
                "name": item.name,
                "param_count": item.param_count,
                "parameter_enums": list(item.parameter_enums),
                "parameter_kinds": list(item.parameter_kinds),
                "parameter_names": list(item.parameter_names),
                "parameter_types": list(item.parameter_types),
                "return_type": item.return_type,
            }
            for item in sorted(context.profile_functions.values(), key=lambda fact: fact.name)
        ],
        "labels": [{"name": item.name, "span": list(item.span)} for item in context.labels],
        "literals": [{"value": item.value, "span": list(item.span)} for item in context.literals],
        "flow_facts": [
            {
                "case_anchors": {str(key): value for key, value in item.case_anchors.items()},
                "case_body_states": {str(key): value for key, value in item.case_body_states.items()},
                "case_labels": {str(key): value for key, value in item.case_labels.items()},
                "confidence": item.confidence,
                "dispatcher": item.dispatcher,
                "evidence": item.evidence,
                "export_only": item.export_only,
                "kind": item.kind,
                "recovered_cases": list(item.recovered_cases),
            }
            for item in context.flow_facts
        ],
        "semantic_comment_kinds": sorted(context.semantic_comment_kinds),
    }


def scaffold_rule_pack(kind: str, pack_id: str = "project.rules", rule_id: str = "") -> dict[str, Any]:
    normalized = str(kind or "").strip()
    if normalized not in SCAFFOLD_KINDS:
        raise ValueError("unsupported scaffold kind: %s" % normalized)
    rule = _scaffold_rule(normalized, rule_id)
    return {
        "schema_version": 2,
        "id": pack_id,
        "description": "Project-local PseudoForge deterministic rules.",
        "rules": [rule],
    }


def _scaffold_rule(kind: str, rule_id: str) -> dict[str, Any]:
    if kind == "exact-local-rename":
        return {
            "id": rule_id or "project.rename.exact_local",
            "phase": "rename",
            "priority": 100,
            "confidence": 0.95,
            "scope": {"lvar": {"name": "v1"}},
            "match": {"lvar": {"name": "v1"}},
            "emit": {
                "kind": "rename",
                "rename_kind": "lvar",
                "target": "$lvar",
                "new_name": "meaningfulName",
                "evidence": "Project-local exact local rename",
            },
        }
    if kind == "assignment-rename":
        return {
            "id": rule_id or "project.rename.assignment_target",
            "phase": "rename",
            "priority": 100,
            "confidence": 0.92,
            "scope": {"assignment": {"rhs_call_name": "PsGetCurrentProcessId"}},
            "match": {
                "assignment": {
                    "rhs_call_name": "PsGetCurrentProcessId",
                    "rhs_call_arg_count": 0,
                }
            },
            "emit": {
                "kind": "rename",
                "rename_kind": "lvar",
                "target": "$assignment_target",
                "new_name": "requesterProcessId",
                "evidence": "Local receives current process id",
            },
        }
    if kind == "semantic-comment":
        return {
            "id": rule_id or "project.comment.object_reference",
            "phase": "semantic_comment",
            "priority": 80,
            "confidence": 0.90,
            "scope": {"call_site": {"function_name": "ObReferenceObjectByHandle"}},
            "match": {"call_site": {"function_name": "ObReferenceObjectByHandle"}},
            "emit": {
                "kind": "semantic_comment",
                "comment_kind": "object_reference",
                "text": "Object reference path is present",
                "evidence": "ObReferenceObjectByHandle call is present",
            },
        }
    if kind == "call-arg-rewrite":
        return {
            "id": rule_id or "project.call_arg.probe_size",
            "phase": "call_arg_rewrite",
            "priority": 70,
            "confidence": 0.90,
            "scope": {"calls_any": ["ProbeForRead"]},
            "match": {
                "call_site": {
                    "function_name": "ProbeForRead",
                    "arg_count": 3,
                    "arg_literal": {"argument_index": 2, "value": "1"},
                }
            },
            "emit": {
                "kind": "call_arg_rewrite",
                "function_name": "ProbeForRead",
                "argument_index": 1,
                "replacement": "sizeof(*$call_arg0)",
                "preview_only": True,
                "evidence": "Preview-only ProbeForRead size rewrite candidate",
            },
        }
    if kind == "text-rewrite":
        return {
            "id": rule_id or "project.text.probe_size",
            "phase": "text_rewrite",
            "priority": 60,
            "confidence": 0.90,
            "scope": {
                "requires_comment_kind": "probe_for_read",
                "text_contains": "ProbeForRead",
            },
            "match": {
                "before_regex": "ProbeForRead\\((?P<arg>[A-Za-z_][A-Za-z0-9_]*), 8, 1\\)"
            },
            "emit": {
                "kind": "text_rewrite",
                "replacement": "ProbeForRead($arg, sizeof(*$arg), 1)",
                "preview_only": True,
                "evidence": "Preview-only text rewrite candidate",
            },
        }
    return {
        "id": rule_id or "project.flow.dispatcher_review",
        "phase": "flow",
        "priority": 50,
        "confidence": 0.90,
        "scope": {"text_contains": "switch"},
        "match": {
            "flow_case_count_min": 3,
            "flow_dispatcher_regex": "^[A-Za-z_][A-Za-z0-9_]*$",
        },
        "emit": {
            "kind": "flow",
            "flow_kind": "switch_recovery_review",
            "summary": "Recovered $case_count cases for $dispatcher",
            "preview_only": True,
            "evidence": "Preview-only recovered flow report",
        },
    }

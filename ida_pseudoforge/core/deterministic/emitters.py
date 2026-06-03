from __future__ import annotations

import re
from typing import Any

from ida_pseudoforge.core.deterministic.schema import Rule, RuleEmission, RuleMatch, RuleReport
from ida_pseudoforge.core.plan_schema import RenameSuggestion


def emissions_to_renames(emissions: list[RuleEmission]) -> list[RenameSuggestion]:
    suggestions = []
    for emission in emissions:
        if emission.kind != "rename":
            continue
        payload = emission.payload
        suggestions.append(
            RenameSuggestion(
                kind=str(payload.get("rename_kind", "lvar")),
                old=str(payload.get("target", "")),
                new=str(payload.get("new_name", "")),
                confidence=float(emission.confidence),
                source=str(payload.get("source", "rule")),
                evidence=str(emission.evidence or payload.get("evidence", "")),
            )
        )
    return suggestions


def emissions_to_comments(emissions: list[RuleEmission]) -> list[dict[str, Any]]:
    comments = []
    for emission in emissions:
        if emission.kind != "semantic_comment":
            continue
        payload = emission.payload
        comments.append(
            {
                "kind": str(payload.get("comment_kind", "rule")),
                "text": str(payload.get("text", "")),
                "confidence": float(emission.confidence),
                "rule_id": emission.rule_id,
            }
        )
    return comments


def build_emission(rule: Rule, match: RuleMatch, report: RuleReport) -> RuleEmission | None:
    emit = rule.emit or {}
    kind = str(emit.get("kind", ""))
    if kind == "rename":
        return _build_rename_emission(rule, match, report)
    if kind == "semantic_comment":
        return _build_comment_emission(rule, match, report)
    if kind == "call_arg_rewrite":
        return _build_call_arg_rewrite_emission(rule, match, report)
    if kind == "flow":
        return _build_flow_emission(rule, match, report)
    if kind == "text_rewrite":
        return _build_text_rewrite_emission(rule, match, report)
    _reject(report, rule, "unsupported emission kind %s" % kind)
    return None


def _build_rename_emission(rule: Rule, match: RuleMatch, report: RuleReport) -> RuleEmission | None:
    emit = rule.emit or {}
    target = _resolve_binding(str(emit.get("target", "")), match.bindings)
    new_name = _resolve_binding(str(emit.get("new_name", "")), match.bindings)
    if not target or not new_name:
        _reject(report, rule, "rename emission target or new_name could not be resolved")
        return None
    evidence = _resolve_binding(str(emit.get("evidence", "") or rule.id), match.bindings)
    return RuleEmission(
        kind="rename",
        rule_id=rule.id,
        confidence=rule.confidence,
        priority=rule.priority,
        source_path=rule.source_path,
        source_label=rule.source_label,
        source_order=rule.source_order,
        override_of=rule.override_of,
        evidence=evidence,
        payload={
            "rename_kind": str(emit.get("rename_kind", "lvar")),
            "target": target,
            "new_name": new_name,
            "source": "rule",
            "evidence": evidence,
        },
    )


def _build_comment_emission(rule: Rule, match: RuleMatch, report: RuleReport) -> RuleEmission | None:
    emit = rule.emit or {}
    comment_kind = _resolve_binding(str(emit.get("comment_kind", "")), match.bindings)
    text = _resolve_binding(str(emit.get("text", "")), match.bindings)
    if not comment_kind or not text:
        _reject(report, rule, "semantic_comment emission kind or text could not be resolved")
        return None
    evidence = _resolve_binding(str(emit.get("evidence", "") or rule.id), match.bindings)
    return RuleEmission(
        kind="semantic_comment",
        rule_id=rule.id,
        confidence=rule.confidence,
        priority=rule.priority,
        source_path=rule.source_path,
        source_label=rule.source_label,
        source_order=rule.source_order,
        override_of=rule.override_of,
        evidence=evidence,
        payload={
            "comment_kind": comment_kind,
            "text": text,
            "evidence": evidence,
        },
    )


def _build_call_arg_rewrite_emission(rule: Rule, match: RuleMatch, report: RuleReport) -> RuleEmission | None:
    emit = rule.emit or {}
    function_name = _resolve_binding(str(emit.get("function_name", "")), match.bindings)
    replacement = _resolve_binding(str(emit.get("replacement", "")), match.bindings)
    argument_index = emit.get("argument_index")
    if not function_name or not replacement:
        _reject(report, rule, "call_arg_rewrite function_name or replacement could not be resolved")
        return None
    if not isinstance(argument_index, int) or isinstance(argument_index, bool) or argument_index < 0:
        _reject(report, rule, "call_arg_rewrite argument_index is invalid")
        return None
    if emit.get("preview_only") is not True:
        _reject(report, rule, "call_arg_rewrite must be preview_only")
        return None
    evidence = _resolve_binding(str(emit.get("evidence", "") or rule.id), match.bindings)
    return RuleEmission(
        kind="call_arg_rewrite",
        rule_id=rule.id,
        confidence=rule.confidence,
        priority=rule.priority,
        source_path=rule.source_path,
        source_label=rule.source_label,
        source_order=rule.source_order,
        override_of=rule.override_of,
        evidence=evidence,
        payload={
            "function_name": function_name,
            "argument_index": argument_index,
            "replacement": replacement,
            "preview_only": True,
            "source": "rule",
            "evidence": evidence,
        },
    )


def _build_text_rewrite_emission(rule: Rule, match: RuleMatch, report: RuleReport) -> RuleEmission | None:
    emit = rule.emit or {}
    replacement = _resolve_binding(str(emit.get("replacement", "")), match.bindings)
    before_regex = str((rule.match or {}).get("before_regex", ""))
    if not before_regex or not replacement:
        _reject(report, rule, "text_rewrite before_regex or replacement could not be resolved")
        return None
    if emit.get("preview_only") is not True:
        _reject(report, rule, "text_rewrite must be preview_only")
        return None
    if match.span is None or match.span[0] >= match.span[1]:
        _reject(report, rule, "text_rewrite match span is invalid")
        return None
    evidence = _resolve_binding(str(emit.get("evidence", "") or rule.id), match.bindings)
    requires_comment_kind = _scope_value_payload((rule.scope or {}).get("requires_comment_kind", ""))
    return RuleEmission(
        kind="text_rewrite",
        rule_id=rule.id,
        confidence=rule.confidence,
        priority=rule.priority,
        source_path=rule.source_path,
        source_label=rule.source_label,
        source_order=rule.source_order,
        override_of=rule.override_of,
        evidence=evidence,
        payload={
            "before_regex": before_regex,
            "replacement": replacement,
            "span": [match.span[0], match.span[1]],
            "preview_only": True,
            "requires_comment_kind": requires_comment_kind,
            "source": "rule",
            "evidence": evidence,
        },
    )


def _build_flow_emission(rule: Rule, match: RuleMatch, report: RuleReport) -> RuleEmission | None:
    emit = rule.emit or {}
    flow_kind = _resolve_binding(str(emit.get("flow_kind", "")), match.bindings)
    if not flow_kind:
        _reject(report, rule, "flow emission flow_kind could not be resolved")
        return None
    if emit.get("preview_only") is not True:
        _reject(report, rule, "flow emission must be preview_only")
        return None
    flow_payload = match.metadata.get("flow") if isinstance(match.metadata, dict) else None
    if not isinstance(flow_payload, dict) or not flow_payload.get("dispatcher"):
        _reject(report, rule, "flow emission has no matched flow fact")
        return None
    evidence = _resolve_binding(str(emit.get("evidence", "") or match.evidence or rule.id), match.bindings)
    summary = _resolve_binding(str(emit.get("summary", "") or ""), match.bindings)
    payload = dict(flow_payload)
    payload.update(
        {
            "flow_kind": flow_kind,
            "preview_only": True,
            "summary": summary,
            "source": "rule",
            "evidence": evidence,
        }
    )
    return RuleEmission(
        kind="flow",
        rule_id=rule.id,
        confidence=rule.confidence,
        priority=rule.priority,
        source_path=rule.source_path,
        source_label=rule.source_label,
        source_order=rule.source_order,
        override_of=rule.override_of,
        evidence=evidence,
        payload=payload,
    )


def _resolve_binding(value: str, bindings: dict[str, str]) -> str:
    result = value
    for key, replacement in sorted(bindings.items(), key=lambda item: len(item[0]), reverse=True):
        result = result.replace("$" + key, replacement)
    if re.search(r"\$[A-Za-z_][A-Za-z0-9_]*", result):
        return ""
    return result


def _scope_value_payload(value: Any) -> str | list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return str(value)


def _reject(report: RuleReport, rule: Rule, reason: str) -> None:
    report.rejected_emissions.append(
        {
            "rule_id": rule.id,
            "reason": reason,
            "source": rule.source_label or rule.pack_id,
        }
    )
    if _is_rewrite_rule(rule):
        report.rewrite_emissions.append(
            {
                "rule_id": rule.id,
                "kind": str((rule.emit or {}).get("kind", "")),
                "status": "rejected",
                "reason": reason,
                "source": rule.source_label or rule.pack_id,
            }
        )


def _is_rewrite_rule(rule: Rule) -> bool:
    kind = str((rule.emit or {}).get("kind", ""))
    return rule.phase in {"call_arg_rewrite", "flow", "text_rewrite"} or kind in {
        "call_arg_rewrite",
        "flow",
        "text_rewrite",
    }

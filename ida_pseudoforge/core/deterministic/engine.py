from __future__ import annotations

from collections import defaultdict

from ida_pseudoforge.core.deterministic.context import RuleContext
from ida_pseudoforge.core.deterministic.emitters import build_emission
from ida_pseudoforge.core.deterministic.matchers.regex import explain_rule_miss, match_regex_rule
from ida_pseudoforge.core.deterministic.schema import RulePack, RuleReport, RuleRunResult


class RuleEngine:
    def __init__(self, packs: list[RulePack]):
        self._packs = packs

    def run(
        self,
        context: RuleContext,
        phases: set[str] | None = None,
        report: RuleReport | None = None,
        explain_misses: bool = False,
    ) -> RuleRunResult:
        run_report = report or RuleReport()
        emissions = []
        for rule in self._ordered_rules():
            if not rule.enabled:
                if explain_misses:
                    _record_missed_rule(run_report, rule, ["rule is disabled"])
                continue
            if phases is not None and rule.phase not in phases:
                continue
            try:
                matches = match_regex_rule(rule, context)
            except Exception as exc:
                _reject_rule(run_report, rule, "rule runtime error: %s" % exc)
                continue
            if explain_misses and not matches:
                _record_missed_rule(run_report, rule, explain_rule_miss(rule, context))
            for match in matches:
                run_report.matched_rules.append(
                    {
                        "rule_id": rule.id,
                        "phase": rule.phase,
                        "confidence": rule.confidence,
                        "priority": rule.priority,
                        "bindings": dict(match.bindings),
                        "span": list(match.span) if match.span is not None else None,
                        "emission_kind": str(rule.emit.get("kind", "")),
                        "evidence": match.evidence,
                        "source": rule.source_label or rule.pack_id or rule.id,
                    }
                )
                try:
                    emission = build_emission(rule, match, run_report)
                except Exception as exc:
                    _reject_rule(run_report, rule, "emission runtime error: %s" % exc)
                    continue
                if emission is not None:
                    emissions.append(emission)
        return RuleRunResult(emissions=_resolve_conflicts(emissions, run_report), report=run_report)

    def _ordered_rules(self):
        rules = []
        for pack_index, pack in enumerate(self._packs):
            for rule in pack.rules:
                rules.append((pack_index, rule))
        return [
            item[1]
            for item in sorted(
                rules,
                key=lambda item: (
                    item[1].phase,
                    -item[1].priority,
                    -item[1].confidence,
                    item[0],
                    item[1].id,
                ),
            )
        ]


def _resolve_conflicts(emissions, report: RuleReport):
    rename_groups = defaultdict(list)
    call_arg_rewrite_groups = defaultdict(list)
    flow_groups = defaultdict(list)
    text_rewrites = []
    seen_renames = set()
    passthrough = []
    for emission in emissions:
        if emission.kind == "rename":
            target = str(emission.payload.get("target", ""))
            new_name = str(emission.payload.get("new_name", ""))
            dedupe_key = (emission.rule_id, target, new_name)
            if dedupe_key in seen_renames:
                continue
            seen_renames.add(dedupe_key)
            rename_groups[target].append(emission)
        elif emission.kind == "call_arg_rewrite":
            key = _call_arg_rewrite_key(emission)
            if not key:
                _record_rewrite_emission(report, emission, "rejected", "call_arg_rewrite target is incomplete")
                continue
            call_arg_rewrite_groups[key].append(emission)
        elif emission.kind == "flow":
            key = _flow_rewrite_key(emission)
            if not key:
                _record_rewrite_emission(report, emission, "rejected", "flow target is incomplete")
                continue
            flow_groups[key].append(emission)
        elif emission.kind == "text_rewrite":
            span = _text_rewrite_span(emission)
            if span is None:
                _record_rewrite_emission(report, emission, "rejected", "text_rewrite span is incomplete")
                continue
            text_rewrites.append(emission)
        else:
            passthrough.append(emission)

    result = []
    for target, group in rename_groups.items():
        if len(group) == 1:
            result.extend(group)
            continue
        winner = max(group, key=lambda emission: _rename_emission_rank(emission, group))
        result.append(winner)
        for emission in group:
            if emission is winner:
                continue
            report.rejected_emissions.append(
                {
                    "rule_id": emission.rule_id,
                    "reason": "rename conflict on %s won by %s" % (target, winner.rule_id),
                    "source": emission.source_label,
                }
            )
    for key, group in call_arg_rewrite_groups.items():
        winner = max(group, key=lambda emission: _emission_rank(emission, group))
        result.append(winner)
        _record_rewrite_emission(report, winner, "applied")
        for emission in group:
            if emission is winner:
                continue
            _record_rewrite_emission(
                report,
                emission,
                "shadowed",
                "call_arg_rewrite conflict on %s[%s] won by %s" % (key[0], key[1], winner.rule_id),
                winner_rule_id=winner.rule_id,
            )
    for key, group in flow_groups.items():
        winner = max(group, key=lambda emission: _emission_rank(emission, group))
        result.append(winner)
        _record_rewrite_emission(report, winner, "applied")
        for emission in group:
            if emission is winner:
                continue
            _record_rewrite_emission(
                report,
                emission,
                "shadowed",
                "flow conflict on %s/%s won by %s" % (key[0], key[1], winner.rule_id),
                winner_rule_id=winner.rule_id,
            )
    result.extend(_resolve_text_rewrite_conflicts(text_rewrites, report))
    result.extend(passthrough)
    return result


def _rename_emission_rank(emission, group) -> tuple[int, int, float, int, str]:
    return _emission_rank(emission, group)


def _emission_rank(emission, group) -> tuple[int, int, float, int, str]:
    group_rule_ids = {item.rule_id for item in group}
    override_bonus = 1 if emission.override_of and emission.override_of in group_rule_ids else 0
    return (
        override_bonus,
        emission.priority,
        emission.confidence,
        emission.source_order,
        emission.rule_id,
    )


def _call_arg_rewrite_key(emission) -> tuple[str, int] | None:
    function_name = str(emission.payload.get("function_name", ""))
    argument_index = emission.payload.get("argument_index")
    if not function_name or not isinstance(argument_index, int) or isinstance(argument_index, bool) or argument_index < 0:
        return None
    return (function_name, argument_index)


def _flow_rewrite_key(emission) -> tuple[str, str] | None:
    dispatcher = str(emission.payload.get("dispatcher", ""))
    flow_kind = str(emission.payload.get("flow_kind", ""))
    if not dispatcher or not flow_kind:
        return None
    return (dispatcher, flow_kind)


def _text_rewrite_span(emission) -> tuple[int, int] | None:
    span = emission.payload.get("span")
    if not isinstance(span, list) or len(span) != 2:
        return None
    start, end = span
    if not isinstance(start, int) or isinstance(start, bool):
        return None
    if not isinstance(end, int) or isinstance(end, bool):
        return None
    if start < 0 or end <= start:
        return None
    return (start, end)


def _resolve_text_rewrite_conflicts(emissions, report: RuleReport):
    accepted = []
    accepted_spans: list[tuple[tuple[int, int], object]] = []
    ranked = sorted(emissions, key=lambda emission: _emission_rank(emission, emissions), reverse=True)
    for emission in ranked:
        span = _text_rewrite_span(emission)
        if span is None:
            _record_rewrite_emission(report, emission, "rejected", "text_rewrite span is incomplete")
            continue
        conflict = next((item for item in accepted_spans if _spans_overlap(span, item[0])), None)
        if conflict is not None:
            winner = conflict[1]
            _record_rewrite_emission(
                report,
                emission,
                "shadowed",
                "text_rewrite span conflict won by %s" % winner.rule_id,
                winner_rule_id=winner.rule_id,
            )
            continue
        accepted.append(emission)
        accepted_spans.append((span, emission))
        _record_rewrite_emission(report, emission, "applied")
    return accepted


def _spans_overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _record_rewrite_emission(
    report: RuleReport,
    emission,
    status: str,
    reason: str = "",
    winner_rule_id: str = "",
) -> None:
    payload = dict(emission.payload)
    item = {
        "rule_id": emission.rule_id,
        "kind": emission.kind,
        "status": status,
        "confidence": emission.confidence,
        "priority": emission.priority,
        "payload": payload,
        "preview_only": bool(payload.get("preview_only", False)),
        "evidence": emission.evidence,
        "source": emission.source_label,
    }
    if reason:
        item["reason"] = reason
    if winner_rule_id:
        item["winner_rule_id"] = winner_rule_id
    report.rewrite_emissions.append(item)


def _reject_rule(report: RuleReport, rule, reason: str) -> None:
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


def _record_missed_rule(report: RuleReport, rule, reasons: list[str]) -> None:
    report.missed_rules.append(
        {
            "rule_id": rule.id,
            "phase": rule.phase,
            "source": rule.source_label or rule.pack_id,
            "reasons": [str(item) for item in reasons if str(item).strip()],
        }
    )


def _is_rewrite_rule(rule) -> bool:
    kind = str((rule.emit or {}).get("kind", ""))
    return rule.phase in {"call_arg_rewrite", "flow", "text_rewrite"} or kind in {
        "call_arg_rewrite",
        "flow",
        "text_rewrite",
    }

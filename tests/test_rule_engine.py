from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.deterministic.context import build_rule_context
from ida_pseudoforge.core.deterministic.emitters import emissions_to_comments, emissions_to_renames
from ida_pseudoforge.core.deterministic.engine import RuleEngine
from ida_pseudoforge.core.deterministic.schema import Rule, RulePack
from ida_pseudoforge.core.flow_recovery import recover_flow
from tests.helpers import _call_arg_gate_match, _flow_rule


FLOW_RULE_SAMPLE = """
__int64 __fastcall RuleFlowSample(int code)
{
  switch ( code )
  {
    case 1:
      return 1;
    case 2:
      return 2;
    case 3:
      return 3;
    case 4:
      return 4;
    default:
      return 0;
  }
}
"""


class RuleEngineTests(unittest.TestCase):
    def test_rule_engine_emits_v2_flow_without_plan_conversion(self) -> None:
        capture = capture_from_pseudocode(FLOW_RULE_SAMPLE)
        flows = recover_flow(capture)
        pack = RulePack(
            schema_version=2,
            id="test.rules",
            description="test",
            rules=[
                Rule(
                    id="test.flow.v2",
                    phase="flow",
                    priority=50,
                    confidence=0.90,
                    scope={"text_contains": "switch"},
                    match={
                        "flow_case_count_min": 4,
                        "flow_dispatcher_regex": "^code$",
                        "flow_body_state_any": "single_statement_body",
                    },
                    emit={
                        "kind": "flow",
                        "flow_kind": "switch_recovery_review",
                        "summary": "Recovered $case_count cases for $dispatcher",
                        "preview_only": True,
                        "evidence": "preview-only flow report",
                    },
                )
            ],
        )

        result = RuleEngine([pack]).run(
            build_rule_context(capture, flow_rewrites=flows),
            phases={"flow"},
        )

        self.assertEqual(1, len(result.emissions))
        emission = result.emissions[0]
        self.assertEqual("flow", emission.kind)
        self.assertEqual("switch_recovery_review", emission.payload["flow_kind"])
        self.assertEqual("code", emission.payload["dispatcher"])
        self.assertEqual(4, emission.payload["case_count"])
        self.assertEqual([1, 2, 3, 4], emission.payload["recovered_cases"])
        self.assertTrue(emission.payload["preview_only"])
        self.assertEqual("Recovered 4 cases for code", emission.payload["summary"])
        self.assertEqual(1, len(result.report.rewrite_emissions))
        self.assertEqual("applied", result.report.rewrite_emissions[0]["status"])
        self.assertEqual("flow", result.report.rewrite_emissions[0]["kind"])
        self.assertTrue(result.report.rewrite_emissions[0]["preview_only"])
        self.assertEqual([], emissions_to_renames(result.emissions))
        self.assertEqual([], emissions_to_comments(result.emissions))

    def test_rule_engine_reports_shadowed_v2_flow_rewrites(self) -> None:
        capture = capture_from_pseudocode(FLOW_RULE_SAMPLE)
        flows = recover_flow(capture)
        pack = RulePack(
            schema_version=2,
            id="test.rules",
            description="test",
            rules=[
                Rule(**_flow_rule(rule_id="test.flow.low", priority=10)),
                Rule(**_flow_rule(rule_id="test.flow.high", priority=90)),
            ],
        )

        result = RuleEngine([pack]).run(
            build_rule_context(capture, flow_rewrites=flows),
            phases={"flow"},
        )

        self.assertEqual(1, len(result.emissions))
        self.assertEqual("test.flow.high", result.emissions[0].rule_id)
        statuses = {item["rule_id"]: item["status"] for item in result.report.rewrite_emissions}
        self.assertEqual("applied", statuses["test.flow.high"])
        self.assertEqual("shadowed", statuses["test.flow.low"])
        shadowed = next(item for item in result.report.rewrite_emissions if item["rule_id"] == "test.flow.low")
        self.assertEqual("test.flow.high", shadowed["winner_rule_id"])
        self.assertIn("flow conflict", shadowed["reason"])

    def test_rule_engine_flow_requires_recovered_flow_fact(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleFlowNoFactSample(int code)
{
  return code;
}
"""
        )
        pack = RulePack(
            schema_version=2,
            id="test.rules",
            description="test",
            rules=[Rule(**_flow_rule())],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"flow"})

        self.assertEqual([], result.emissions)
        self.assertEqual([], result.report.rewrite_emissions)

    def test_rule_engine_flow_runtime_rejects_weak_case_count_gate(self) -> None:
        capture = capture_from_pseudocode(FLOW_RULE_SAMPLE)
        flows = recover_flow(capture)
        pack = RulePack(
            schema_version=2,
            id="test.rules",
            description="test",
            rules=[Rule(**_flow_rule(min_cases=2))],
        )

        result = RuleEngine([pack]).run(
            build_rule_context(capture, flow_rewrites=flows),
            phases={"flow"},
        )

        self.assertEqual([], result.emissions)
        self.assertEqual([], result.report.rewrite_emissions)

    def test_rule_engine_emits_v2_call_arg_rewrite_without_plan_conversion(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleCallArgSample(void *inputBuffer)
{
  ProbeForRead(inputBuffer, 8, 1);
  return 0;
}
"""
        )
        pack = RulePack(
            schema_version=2,
            id="test.rules",
            description="test",
            rules=[
                Rule(
                    id="test.call_arg_rewrite.v2",
                    phase="call_arg_rewrite",
                    priority=50,
                    confidence=0.90,
                    scope={"calls_any": ["ProbeForRead"]},
                    match={"text_contains": "ProbeForRead"},
                    emit={
                        "kind": "call_arg_rewrite",
                        "function_name": "ProbeForRead",
                        "argument_index": 1,
                        "replacement": "sizeof(*inputBuffer)",
                        "preview_only": True,
                        "evidence": "preview-only call argument rewrite",
                    },
                )
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"call_arg_rewrite"})

        self.assertEqual(1, len(result.emissions))
        emission = result.emissions[0]
        self.assertEqual("call_arg_rewrite", emission.kind)
        self.assertEqual("ProbeForRead", emission.payload["function_name"])
        self.assertEqual(1, emission.payload["argument_index"])
        self.assertTrue(emission.payload["preview_only"])
        self.assertEqual(1, len(result.report.rewrite_emissions))
        self.assertEqual("applied", result.report.rewrite_emissions[0]["status"])
        self.assertEqual("call_arg_rewrite", result.report.rewrite_emissions[0]["kind"])
        self.assertEqual("ProbeForRead", result.report.rewrite_emissions[0]["payload"]["function_name"])
        self.assertEqual([], emissions_to_renames(result.emissions))
        self.assertEqual([], emissions_to_comments(result.emissions))

    def test_rule_engine_reports_shadowed_v2_call_arg_rewrites(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleCallArgShadowSample(void *inputBuffer)
{
  ProbeForRead(inputBuffer, 8, 1);
  return 0;
}
"""
        )
        pack = RulePack(
            schema_version=2,
            id="test.rules",
            description="test",
            rules=[
                Rule(
                    id="test.call_arg.low",
                    phase="call_arg_rewrite",
                    priority=10,
                    confidence=0.95,
                    scope={"calls_any": ["ProbeForRead"]},
                    match={"text_contains": "ProbeForRead"},
                    emit={
                        "kind": "call_arg_rewrite",
                        "function_name": "ProbeForRead",
                        "argument_index": 1,
                        "replacement": "sizeof(low)",
                        "preview_only": True,
                    },
                ),
                Rule(
                    id="test.call_arg.high",
                    phase="call_arg_rewrite",
                    priority=90,
                    confidence=0.80,
                    scope={"calls_any": ["ProbeForRead"]},
                    match={"text_contains": "ProbeForRead"},
                    emit={
                        "kind": "call_arg_rewrite",
                        "function_name": "ProbeForRead",
                        "argument_index": 1,
                        "replacement": "sizeof(*inputBuffer)",
                        "preview_only": True,
                    },
                ),
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"call_arg_rewrite"})

        self.assertEqual(1, len(result.emissions))
        self.assertEqual("test.call_arg.high", result.emissions[0].rule_id)
        statuses = {item["rule_id"]: item["status"] for item in result.report.rewrite_emissions}
        self.assertEqual("applied", statuses["test.call_arg.high"])
        self.assertEqual("shadowed", statuses["test.call_arg.low"])
        shadowed = next(item for item in result.report.rewrite_emissions if item["rule_id"] == "test.call_arg.low")
        self.assertEqual("test.call_arg.high", shadowed["winner_rule_id"])
        self.assertIn("won by test.call_arg.high", shadowed["reason"])
        self.assertEqual([], result.report.rejected_emissions)

    def test_rule_engine_reports_rejected_v2_call_arg_rewrite_runtime_guard(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleCallArgRejectedSample(void *inputBuffer)
{
  ProbeForRead(inputBuffer, 8, 1);
  return 0;
}
"""
        )
        pack = RulePack(
            schema_version=2,
            id="test.rules",
            description="test",
            rules=[
                Rule(
                    id="test.call_arg.rejected",
                    phase="call_arg_rewrite",
                    priority=50,
                    confidence=0.90,
                    scope={"calls_any": ["ProbeForRead"]},
                    match={"text_contains": "ProbeForRead"},
                    emit={
                        "kind": "call_arg_rewrite",
                        "function_name": "ProbeForRead",
                        "argument_index": -1,
                        "replacement": "sizeof(*inputBuffer)",
                        "preview_only": True,
                    },
                )
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"call_arg_rewrite"})

        self.assertEqual([], result.emissions)
        self.assertEqual("rejected", result.report.rewrite_emissions[0]["status"])
        self.assertIn("argument_index is invalid", result.report.rewrite_emissions[0]["reason"])
        self.assertTrue(any("argument_index is invalid" in item["reason"] for item in result.report.rejected_emissions))

    def test_rule_engine_reports_v2_text_rewrite_span_conflicts(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleTextRewriteShadowSample(void *inputBuffer)
{
  ProbeForRead(inputBuffer, 8, 1);
  return 0;
}
"""
        )
        pack = RulePack(
            schema_version=2,
            id="test.rules",
            description="test",
            rules=[
                Rule(
                    id="test.text.low",
                    phase="text_rewrite",
                    priority=10,
                    confidence=0.95,
                    scope={"requires_comment_kind": "test_semantic_gate", "text_contains": "ProbeForRead"},
                    match={"before_regex": r"ProbeForRead\((?P<arg>inputBuffer), 8, 1\)"},
                    emit={
                        "kind": "text_rewrite",
                        "replacement": "ProbeForRead($arg, sizeof(low), 1)",
                        "preview_only": True,
                    },
                ),
                Rule(
                    id="test.text.high",
                    phase="text_rewrite",
                    priority=90,
                    confidence=0.80,
                    scope={"requires_comment_kind": "test_semantic_gate", "text_contains": "ProbeForRead"},
                    match={"before_regex": r"ProbeForRead\((?P<arg>inputBuffer), 8, 1\)"},
                    emit={
                        "kind": "text_rewrite",
                        "replacement": "ProbeForRead($arg, sizeof(*inputBuffer), 1)",
                        "preview_only": True,
                    },
                ),
            ],
        )
        context = build_rule_context(capture, semantic_comments=[{"kind": "test_semantic_gate"}])

        result = RuleEngine([pack]).run(context, phases={"text_rewrite"})

        self.assertEqual(1, len(result.emissions))
        self.assertEqual("test.text.high", result.emissions[0].rule_id)
        self.assertEqual("text_rewrite", result.emissions[0].kind)
        self.assertEqual("ProbeForRead(inputBuffer, sizeof(*inputBuffer), 1)", result.emissions[0].payload["replacement"])
        statuses = {item["rule_id"]: item["status"] for item in result.report.rewrite_emissions}
        self.assertEqual("applied", statuses["test.text.high"])
        self.assertEqual("shadowed", statuses["test.text.low"])
        shadowed = next(item for item in result.report.rewrite_emissions if item["rule_id"] == "test.text.low")
        self.assertEqual("test.text.high", shadowed["winner_rule_id"])
        self.assertIn("span conflict", shadowed["reason"])
        self.assertEqual([], emissions_to_renames(result.emissions))
        self.assertEqual([], emissions_to_comments(result.emissions))

    def test_rule_engine_text_rewrite_requires_semantic_comment_gate(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleTextRewriteGateSample(void *inputBuffer)
{
  ProbeForRead(inputBuffer, 8, 1);
  return 0;
}
"""
        )
        pack = RulePack(
            schema_version=2,
            id="test.rules",
            description="test",
            rules=[
                Rule(
                    id="test.text.gated",
                    phase="text_rewrite",
                    priority=50,
                    confidence=0.90,
                    scope={"requires_comment_kind": "missing_gate", "text_contains": "ProbeForRead"},
                    match={"before_regex": r"ProbeForRead\((?P<arg>inputBuffer), 8, 1\)"},
                    emit={
                        "kind": "text_rewrite",
                        "replacement": "ProbeForRead($arg, sizeof(*inputBuffer), 1)",
                        "preview_only": True,
                    },
                )
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"text_rewrite"})

        self.assertEqual([], result.emissions)
        self.assertEqual([], result.report.rewrite_emissions)

    def test_rule_engine_call_arg_gates_match_same_call_site(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleCallArgGateSample(void *inputBuffer)
{
  ProbeForRead(inputBuffer, 8, 1);
  ProbeForRead(inputBuffer, 8, 0);
  ProbeForRead(inputBuffer, 8);
  return 0;
}
"""
        )
        pack = RulePack(
            schema_version=2,
            id="test.rules",
            description="test",
            rules=[
                Rule(
                    id="test.comment.call_arg_gates",
                    phase="semantic_comment",
                    priority=100,
                    confidence=0.91,
                    scope={"calls_any": ["ProbeForRead"]},
                    match=_call_arg_gate_match(),
                    emit={
                        "kind": "semantic_comment",
                        "comment_kind": "validated_probe",
                        "text": "ProbeForRead has expected arity and literal mode",
                        "evidence": "call argument gates",
                    },
                ),
                Rule(
                    id="test.comment.cross_site_blocked",
                    phase="semantic_comment",
                    priority=100,
                    confidence=0.91,
                    scope={"calls_any": ["ProbeForRead"]},
                    match=_call_arg_gate_match(count=2),
                    emit={
                        "kind": "semantic_comment",
                        "comment_kind": "invalid_probe",
                        "text": "This would require gates from different call sites",
                        "evidence": "cross-site gate should not match",
                    },
                ),
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"semantic_comment"})

        self.assertEqual(["test.comment.call_arg_gates"], [item["rule_id"] for item in result.report.matched_rules])
        self.assertEqual(1, len(result.emissions))
        comments = emissions_to_comments(result.emissions)
        self.assertEqual("validated_probe", comments[0]["kind"])
        self.assertIn("expected arity", comments[0]["text"])

    def test_rule_engine_typed_fact_operators_emit_bindings(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleTypedFactsSample(void *inputBuffer)
{
  int v1;
  int v2;

  v1 = 0;
  v2 = ProbeForRead(inputBuffer, 8, 1);
  return v2;
}
"""
        )
        pack = RulePack(
            schema_version=2,
            id="test.typed",
            description="typed fact rules",
            rules=[
                Rule(
                    id="test.rename.lvar",
                    phase="rename",
                    priority=100,
                    confidence=0.93,
                    scope={"lvar": {"name_regex": "^v[12]$"}},
                    match={"lvar": {"name": "v1", "type_contains": "int", "is_arg": False}},
                    emit={"kind": "rename", "rename_kind": "lvar", "target": "$lvar", "new_name": "zeroStatus"},
                ),
                Rule(
                    id="test.rename.assignment",
                    phase="rename",
                    priority=90,
                    confidence=0.91,
                    scope={"assignment": {"rhs_call_name": "ProbeForRead"}},
                    match={
                        "assignment": {
                            "rhs_call_name": "ProbeForRead",
                            "rhs_identifier_any": ["inputBuffer"],
                            "rhs_literal_all": ["8", "1"],
                            "rhs_call_arg_count": 3,
                            "rhs_call_arg_literal": {"argument_index": 2, "value": "1"},
                        }
                    },
                    emit={
                        "kind": "rename",
                        "rename_kind": "lvar",
                        "target": "$assignment_target",
                        "new_name": "probeStatus",
                    },
                ),
                Rule(
                    id="test.comment.call_site",
                    phase="semantic_comment",
                    priority=80,
                    confidence=0.90,
                    scope={"call_site": {"function_name": "ProbeForRead"}},
                    match={
                        "call_site": {
                            "function_name": "ProbeForRead",
                            "arg_count": 3,
                            "arg_contains": {"argument_index": 0, "value": "input"},
                            "arg_regex": {"argument_index": 1, "regex": "^8$"},
                        }
                    },
                    emit={
                        "kind": "semantic_comment",
                        "comment_kind": "probe",
                        "text": "Probe call uses $call_arg0",
                    },
                ),
            ],
        )

        rename_result = RuleEngine([pack]).run(build_rule_context(capture), phases={"rename"})
        comment_result = RuleEngine([pack]).run(build_rule_context(capture), phases={"semantic_comment"})
        renames = {(item.old, item.new) for item in emissions_to_renames(rename_result.emissions)}
        comments = emissions_to_comments(comment_result.emissions)

        self.assertEqual({("v1", "zeroStatus"), ("v2", "probeStatus")}, renames)
        self.assertTrue(any(item["bindings"].get("assignment_target") == "v2" for item in rename_result.report.matched_rules))
        self.assertEqual("probe", comments[0]["kind"])
        self.assertIn("inputBuffer", comments[0]["text"])

    def test_rule_engine_profile_function_operator_uses_profile_facts(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleProfileFactsSample(void *inputBuffer)
{
  ProbeForRead(inputBuffer, 8, 1);
  return 0;
}
"""
        )

        def lookup(name: str):
            if name == "ProbeForRead":
                return {
                    "header": "wdm.h",
                    "return_type": "VOID",
                    "params": [
                        {"name": "Address", "type": "PVOID", "kind": "value"},
                        {"name": "Length", "type": "SIZE_T", "kind": "size"},
                        {"name": "Alignment", "type": "ULONG", "kind": "flags", "enum": "PROBE_FLAGS"},
                    ],
                    "profile_alias_of": "ProbeForRead",
                    "profile_alias_kind": "explicit",
                }
            return {}

        pack = RulePack(
            schema_version=2,
            id="test.profile",
            description="profile fact rule",
            rules=[
                Rule(
                    id="test.comment.profile",
                    phase="semantic_comment",
                    priority=100,
                    confidence=0.92,
                    scope={"profile_function": {"function_name": "ProbeForRead", "header_contains": "wdm"}},
                    match={
                        "profile_function": {
                            "function_name": "ProbeForRead",
                            "param_count": 3,
                            "return_type_contains": "VOID",
                            "param": {
                                "index": 2,
                                "name": "Alignment",
                                "type_regex": "^ULONG$",
                                "kind": "flags",
                                "enum": "PROBE_FLAGS",
                            },
                        }
                    },
                    emit={
                        "kind": "semantic_comment",
                        "comment_kind": "profile_probe",
                        "text": "$profile_function argument $profile_param_name is $profile_param_kind",
                    },
                )
            ],
        )

        result = RuleEngine([pack]).run(
            build_rule_context(capture, profile_function_lookup=lookup),
            phases={"semantic_comment"},
        )
        comments = emissions_to_comments(result.emissions)

        self.assertEqual("profile_probe", comments[0]["kind"])
        self.assertIn("Alignment is flags", comments[0]["text"])
        self.assertEqual("Alignment", result.report.matched_rules[0]["bindings"]["profile_param_name"])

    def test_rule_engine_explain_misses_is_opt_in(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleExplainMissSample()
{
  int v1;

  return 0;
}
"""
        )
        pack = RulePack(
            schema_version=2,
            id="test.explain",
            description="explain misses",
            rules=[
                Rule(
                    id="test.rename.missing_lvar",
                    phase="rename",
                    priority=100,
                    confidence=0.90,
                    scope={"lvar": {"name": "missingLocal"}},
                    match={"lvar": {"name": "missingLocal"}},
                    emit={"kind": "rename", "rename_kind": "lvar", "target": "$lvar", "new_name": "missingLocalRole"},
                ),
                Rule(
                    id="test.rename.missing_legacy_lvar_gate",
                    phase="rename",
                    priority=90,
                    confidence=0.90,
                    scope={"lvars_any": ["legacyMissingLocal"]},
                    match={"text_contains": "return 0"},
                    emit={"kind": "rename", "rename_kind": "lvar", "target": "legacyMissingLocal", "new_name": "legacyRole"},
                )
            ],
        )

        normal = RuleEngine([pack]).run(build_rule_context(capture), phases={"rename"})
        explained = RuleEngine([pack]).run(build_rule_context(capture), phases={"rename"}, explain_misses=True)

        self.assertNotIn("missed_rules", normal.report.to_dict())
        self.assertEqual("test.rename.missing_lvar", explained.report.missed_rules[0]["rule_id"])
        self.assertTrue(any("scope.lvar" in reason for reason in explained.report.missed_rules[0]["reasons"]))
        self.assertTrue(
            any(
                item["rule_id"] == "test.rename.missing_legacy_lvar_gate"
                and any("scope.lvars_any" in reason for reason in item["reasons"])
                for item in explained.report.missed_rules
            )
        )

    def test_rule_engine_assignment_regex_binding_and_scope_gate(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleBindingSample(int a1)
{
  int v1;

  v1 = a1;
  return v1;
}
"""
        )
        pack = RulePack(
            schema_version=1,
            id="test.rules",
            description="test",
            rules=[
                Rule(
                    id="test.rename.v1",
                    phase="rename",
                    priority=100,
                    confidence=0.91,
                    scope={"text_contains": "v1 = a1"},
                    match={"assignment_regex": r"\b(?P<dst>v1)\s*=\s*a1\b"},
                    emit={
                        "kind": "rename",
                        "rename_kind": "lvar",
                        "target": "$dst",
                        "new_name": "inputValue",
                        "source": "rule",
                        "evidence": "test binding",
                    },
                ),
                Rule(
                    id="test.rename.blocked",
                    phase="rename",
                    priority=100,
                    confidence=0.91,
                    scope={"calls_any": ["MissingCall"]},
                    match={"assignment_regex": r"\b(?P<dst>v1)\s*=\s*a1\b"},
                    emit={
                        "kind": "rename",
                        "rename_kind": "lvar",
                        "target": "$dst",
                        "new_name": "blockedValue",
                    },
                ),
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"rename"})
        renames = emissions_to_renames(result.emissions)

        self.assertEqual(len(renames), 1)
        self.assertEqual(renames[0].old, "v1")
        self.assertEqual(renames[0].new, "inputValue")
        self.assertEqual(result.report.matched_rules[0]["bindings"]["dst"], "v1")

    def test_rule_engine_text_match_gate_constrains_assignment_regex(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleTextGateSample(int a1)
{
  int v1;

  v1 = a1;
  return v1;
}
"""
        )
        pack = RulePack(
            schema_version=1,
            id="test.text_gate",
            description="test",
            rules=[
                Rule(
                    id="test.rename.blocked_by_match_gate",
                    phase="rename",
                    priority=100,
                    confidence=0.91,
                    scope={"text_contains": "v1 = a1"},
                    match={
                        "assignment_regex": r"\b(?P<dst>v1)\s*=\s*a1\b",
                        "text_contains": "guard that is not present",
                    },
                    emit={"kind": "rename", "rename_kind": "lvar", "target": "$dst", "new_name": "inputValue"},
                )
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"rename"})

        self.assertEqual(result.emissions, [])
        self.assertEqual(result.report.matched_rules, [])

    def test_rule_engine_semantic_comment_emission(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleCommentSample()
{
  ExAcquireResourceExclusiveLite(&Resource, 1u);
  ExReleaseResourceLite(&Resource);
  return 0;
}
"""
        )
        pack = RulePack(
            schema_version=1,
            id="test.comments",
            description="test",
            rules=[
                Rule(
                    id="test.comment.resource",
                    phase="semantic_comment",
                    priority=80,
                    confidence=0.92,
                    scope={"calls_all": ["ExAcquireResourceExclusiveLite", "ExReleaseResourceLite"]},
                    match={"text_contains_all": ["ExAcquireResourceExclusiveLite", "ExReleaseResourceLite"]},
                    emit={
                        "kind": "semantic_comment",
                        "comment_kind": "resource",
                        "text": "resource pair",
                        "evidence": "test comment",
                    },
                )
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"semantic_comment"})
        comments = emissions_to_comments(result.emissions)

        self.assertEqual(comments[0]["kind"], "resource")
        self.assertEqual(comments[0]["text"], "resource pair")

    def test_rule_engine_runtime_errors_are_reported_not_raised(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuntimeGuardSample()
{
  return 0;
}
"""
        )
        pack = RulePack(
            schema_version=1,
            id="test.runtime",
            description="test",
            rules=[
                Rule(
                    id="test.bad.scope.regex",
                    phase="semantic_comment",
                    priority=80,
                    confidence=0.8,
                    scope={"function_name_regex": "("},
                    match={"text_contains": "return"},
                    emit={"kind": "semantic_comment", "comment_kind": "bad", "text": "bad"},
                )
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"semantic_comment"})

        self.assertEqual(result.emissions, [])
        self.assertTrue(any("runtime error" in item["reason"] for item in result.report.rejected_emissions))

    def test_rule_conflicts_use_override_and_report_loser(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleConflictSample(int a1)
{
  int v1;

  v1 = a1;
  return v1;
}
"""
        )
        pack = RulePack(
            schema_version=1,
            id="test.conflict",
            description="test",
            rules=[
                Rule(
                    id="test.rename.base",
                    phase="rename",
                    priority=200,
                    confidence=0.99,
                    scope={"text_contains": "v1 = a1"},
                    match={"assignment_regex": r"\b(?P<dst>v1)\s*=\s*a1\b"},
                    emit={"kind": "rename", "rename_kind": "lvar", "target": "$dst", "new_name": "baseName"},
                ),
                Rule(
                    id="test.rename.override",
                    phase="rename",
                    priority=10,
                    confidence=0.50,
                    scope={"text_contains": "v1 = a1"},
                    match={"assignment_regex": r"\b(?P<dst>v1)\s*=\s*a1\b"},
                    emit={"kind": "rename", "rename_kind": "lvar", "target": "$dst", "new_name": "overrideName"},
                    override_of="test.rename.base",
                ),
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"rename"})
        renames = emissions_to_renames(result.emissions)

        self.assertEqual(len(renames), 1)
        self.assertEqual(renames[0].new, "overrideName")
        self.assertTrue(any("won by test.rename.override" in item["reason"] for item in result.report.rejected_emissions))

    def test_rule_conflicts_use_priority_before_confidence(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RulePriorityConflictSample(int a1)
{
  int v1;

  v1 = a1;
  return v1;
}
"""
        )
        pack = RulePack(
            schema_version=1,
            id="test.priority_conflict",
            description="test",
            rules=[
                Rule(
                    id="test.rename.low_priority",
                    phase="rename",
                    priority=10,
                    confidence=0.99,
                    scope={"text_contains": "v1 = a1"},
                    match={"assignment_regex": r"\b(?P<dst>v1)\s*=\s*a1\b"},
                    emit={"kind": "rename", "rename_kind": "lvar", "target": "$dst", "new_name": "lowPriorityName"},
                ),
                Rule(
                    id="test.rename.high_priority",
                    phase="rename",
                    priority=200,
                    confidence=0.50,
                    scope={"text_contains": "v1 = a1"},
                    match={"assignment_regex": r"\b(?P<dst>v1)\s*=\s*a1\b"},
                    emit={"kind": "rename", "rename_kind": "lvar", "target": "$dst", "new_name": "highPriorityName"},
                ),
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"rename"})
        renames = emissions_to_renames(result.emissions)

        self.assertEqual(len(renames), 1)
        self.assertEqual(renames[0].new, "highPriorityName")
        self.assertTrue(any("won by test.rename.high_priority" in item["reason"] for item in result.report.rejected_emissions))

    def test_rule_engine_dedupes_repeated_identical_rename_emission(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleDuplicateMatchSample(int a1)
{
  int v1;

  v1 = a1;
  v1 = a1;
  return v1;
}
"""
        )
        pack = RulePack(
            schema_version=1,
            id="test.duplicate_match",
            description="test",
            rules=[
                Rule(
                    id="test.rename.duplicate_match",
                    phase="rename",
                    priority=100,
                    confidence=0.91,
                    scope={"text_contains": "v1 = a1"},
                    match={"assignment_regex": r"\b(?P<dst>v1)\s*=\s*a1\b"},
                    emit={"kind": "rename", "rename_kind": "lvar", "target": "$dst", "new_name": "inputValue"},
                )
            ],
        )

        result = RuleEngine([pack]).run(build_rule_context(capture), phases={"rename"})
        renames = emissions_to_renames(result.emissions)

        self.assertEqual(len(renames), 1)
        self.assertEqual(renames[0].new, "inputValue")
        self.assertEqual(result.report.rejected_emissions, [])


if __name__ == "__main__":
    unittest.main()

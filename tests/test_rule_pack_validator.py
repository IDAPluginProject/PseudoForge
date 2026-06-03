from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.deterministic.validators import validate_rule_pack_file
from tests.helpers import (
    _call_arg_gate_match,
    _call_arg_rewrite_rule,
    _flow_rule,
    _rename_rule,
    _rule_pack,
    _text_rewrite_rule,
)


class RulePackValidatorTests(unittest.TestCase):
    def test_rule_pack_validator_reports_invalid_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            valid_path = temp_path / "valid.json"
            valid_path.write_text(json.dumps(_rule_pack([_rename_rule()])), encoding="utf-8")
            self.assertEqual(validate_rule_pack_file(valid_path), [])

            invalid_json_path = temp_path / "invalid_json.json"
            invalid_json_path.write_text("{", encoding="utf-8")
            self.assertTrue(any("invalid JSON" in error for error in validate_rule_pack_file(invalid_json_path)))

            duplicate_path = temp_path / "duplicate.json"
            duplicate_path.write_text(json.dumps(_rule_pack([_rename_rule(), _rename_rule()])), encoding="utf-8")
            self.assertTrue(any("duplicate rule id" in error for error in validate_rule_pack_file(duplicate_path)))

            invalid_phase = _rename_rule()
            invalid_phase["phase"] = "text_rewrite"
            invalid_phase_path = temp_path / "invalid_phase.json"
            invalid_phase_path.write_text(json.dumps(_rule_pack([invalid_phase])), encoding="utf-8")
            self.assertTrue(any("phase" in error for error in validate_rule_pack_file(invalid_phase_path)))

            invalid_confidence = _rename_rule()
            invalid_confidence["confidence"] = 2.0
            invalid_confidence_path = temp_path / "invalid_confidence.json"
            invalid_confidence_path.write_text(json.dumps(_rule_pack([invalid_confidence])), encoding="utf-8")
            self.assertTrue(any("confidence" in error for error in validate_rule_pack_file(invalid_confidence_path)))

            bool_confidence = _rename_rule()
            bool_confidence["confidence"] = True
            bool_confidence_path = temp_path / "bool_confidence.json"
            bool_confidence_path.write_text(json.dumps(_rule_pack([bool_confidence])), encoding="utf-8")
            self.assertTrue(any("confidence" in error for error in validate_rule_pack_file(bool_confidence_path)))

            bool_priority = _rename_rule()
            bool_priority["priority"] = True
            bool_priority_path = temp_path / "bool_priority.json"
            bool_priority_path.write_text(json.dumps(_rule_pack([bool_priority])), encoding="utf-8")
            self.assertTrue(any("priority" in error for error in validate_rule_pack_file(bool_priority_path)))

            invalid_regex = _rename_rule()
            invalid_regex["match"]["assignment_regex"] = "("
            invalid_regex_path = temp_path / "invalid_regex.json"
            invalid_regex_path.write_text(json.dumps(_rule_pack([invalid_regex])), encoding="utf-8")
            self.assertTrue(any("invalid regex" in error for error in validate_rule_pack_file(invalid_regex_path)))

            missing_emit = _rename_rule()
            del missing_emit["emit"]["new_name"]
            missing_emit_path = temp_path / "missing_emit.json"
            missing_emit_path.write_text(json.dumps(_rule_pack([missing_emit])), encoding="utf-8")
            self.assertTrue(any("new_name is required" in error for error in validate_rule_pack_file(missing_emit_path)))

            invalid_scope_regex = _rename_rule()
            invalid_scope_regex["scope"] = {"function_name_regex": "("}
            invalid_scope_regex_path = temp_path / "invalid_scope_regex.json"
            invalid_scope_regex_path.write_text(json.dumps(_rule_pack([invalid_scope_regex])), encoding="utf-8")
            self.assertTrue(
                any("function_name_regex invalid regex" in error for error in validate_rule_pack_file(invalid_scope_regex_path))
            )

            empty_match = _rename_rule()
            empty_match["match"] = {}
            empty_match_path = temp_path / "empty_match.json"
            empty_match_path.write_text(json.dumps(_rule_pack([empty_match])), encoding="utf-8")
            self.assertTrue(any("match must define at least one supported operator" in error for error in validate_rule_pack_file(empty_match_path)))

            empty_text_match = _rename_rule()
            empty_text_match["match"] = {"text_contains": ""}
            empty_text_match_path = temp_path / "empty_text_match.json"
            empty_text_match_path.write_text(json.dumps(_rule_pack([empty_text_match])), encoding="utf-8")
            self.assertTrue(any("text_contains must be a non-empty string" in error for error in validate_rule_pack_file(empty_text_match_path)))

            empty_scope_gate = _rename_rule()
            empty_scope_gate["scope"] = {"calls_any": []}
            empty_scope_gate_path = temp_path / "empty_scope_gate.json"
            empty_scope_gate_path.write_text(json.dumps(_rule_pack([empty_scope_gate])), encoding="utf-8")
            self.assertTrue(any("calls_any must be a non-empty string or non-empty string list" in error for error in validate_rule_pack_file(empty_scope_gate_path)))

            v1_comment_gate = _rename_rule()
            v1_comment_gate["scope"]["requires_comment_kind"] = "test_semantic_gate"
            v1_comment_gate_path = temp_path / "v1_comment_gate.json"
            v1_comment_gate_path.write_text(json.dumps(_rule_pack([v1_comment_gate])), encoding="utf-8")
            self.assertTrue(any("requires_comment_kind is not supported" in error for error in validate_rule_pack_file(v1_comment_gate_path)))

            ambiguous_regex = _rename_rule()
            ambiguous_regex["match"]["regex"] = r"\bv1\b"
            ambiguous_regex_path = temp_path / "ambiguous_regex.json"
            ambiguous_regex_path.write_text(json.dumps(_rule_pack([ambiguous_regex])), encoding="utf-8")
            self.assertTrue(any("must not combine regex" in error for error in validate_rule_pack_file(ambiguous_regex_path)))

            invalid_schema = _rule_pack([_rename_rule()])
            invalid_schema["schema_version"] = True
            invalid_schema_path = temp_path / "invalid_schema.json"
            invalid_schema_path.write_text(json.dumps(invalid_schema), encoding="utf-8")
            self.assertTrue(any("unsupported schema_version" in error for error in validate_rule_pack_file(invalid_schema_path)))

    def test_rule_pack_validator_accepts_v2_call_arg_rewrite_preview_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            valid_path = temp_path / "valid_v2_call_arg.json"
            valid_path.write_text(json.dumps(_rule_pack([_call_arg_rewrite_rule()], schema_version=2)), encoding="utf-8")

            self.assertEqual(validate_rule_pack_file(valid_path), [])

            typed_scope = _call_arg_rewrite_rule()
            typed_scope["scope"] = {"call_site": {"function_name": "ProbeForRead", "arg_count": 3}}
            typed_scope_path = temp_path / "valid_v2_call_arg_typed_scope.json"
            typed_scope_path.write_text(json.dumps(_rule_pack([typed_scope], schema_version=2)), encoding="utf-8")
            self.assertEqual(validate_rule_pack_file(typed_scope_path), [])

            v1_path = temp_path / "v1_call_arg_rejected.json"
            v1_path.write_text(json.dumps(_rule_pack([_call_arg_rewrite_rule()])), encoding="utf-8")
            self.assertTrue(any("phase" in error for error in validate_rule_pack_file(v1_path)))

            not_preview = _call_arg_rewrite_rule()
            not_preview["emit"]["preview_only"] = False
            not_preview_path = temp_path / "not_preview.json"
            not_preview_path.write_text(json.dumps(_rule_pack([not_preview], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("preview_only must be true" in error for error in validate_rule_pack_file(not_preview_path)))

            bad_argument = _call_arg_rewrite_rule()
            bad_argument["emit"]["argument_index"] = -1
            bad_argument_path = temp_path / "bad_argument.json"
            bad_argument_path.write_text(json.dumps(_rule_pack([bad_argument], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("argument_index" in error for error in validate_rule_pack_file(bad_argument_path)))

            missing_call_gate = _call_arg_rewrite_rule()
            missing_call_gate["scope"] = {"text_contains": "ProbeForRead"}
            missing_call_gate_path = temp_path / "missing_call_gate.json"
            missing_call_gate_path.write_text(json.dumps(_rule_pack([missing_call_gate], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("must gate call_arg_rewrite" in error for error in validate_rule_pack_file(missing_call_gate_path)))

            binding_function = _call_arg_rewrite_rule()
            binding_function["emit"]["function_name"] = "$callee"
            binding_function["scope"] = {"text_contains": "ProbeForRead"}
            binding_function_path = temp_path / "binding_function.json"
            binding_function_path.write_text(json.dumps(_rule_pack([binding_function], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("must gate call_arg_rewrite" in error for error in validate_rule_pack_file(binding_function_path)))

    def test_rule_pack_validator_accepts_v2_text_rewrite_preview_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            valid_path = temp_path / "valid_v2_text_rewrite.json"
            valid_path.write_text(json.dumps(_rule_pack([_text_rewrite_rule()], schema_version=2)), encoding="utf-8")

            self.assertEqual(validate_rule_pack_file(valid_path), [])

            v1_path = temp_path / "v1_text_rewrite_rejected.json"
            v1_path.write_text(json.dumps(_rule_pack([_text_rewrite_rule()])), encoding="utf-8")
            self.assertTrue(any("phase" in error for error in validate_rule_pack_file(v1_path)))

            not_preview = _text_rewrite_rule()
            not_preview["emit"]["preview_only"] = False
            not_preview_path = temp_path / "text_not_preview.json"
            not_preview_path.write_text(json.dumps(_rule_pack([not_preview], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("preview_only must be true" in error for error in validate_rule_pack_file(not_preview_path)))

            missing_gate = _text_rewrite_rule()
            missing_gate["scope"] = {"text_contains": "ProbeForRead"}
            missing_gate_path = temp_path / "text_missing_gate.json"
            missing_gate_path.write_text(json.dumps(_rule_pack([missing_gate], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("requires_comment_kind is required" in error for error in validate_rule_pack_file(missing_gate_path)))

            missing_before = _text_rewrite_rule()
            missing_before["match"] = {"text_contains": "ProbeForRead"}
            missing_before_path = temp_path / "text_missing_before.json"
            missing_before_path.write_text(json.dumps(_rule_pack([missing_before], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("before_regex is required" in error for error in validate_rule_pack_file(missing_before_path)))

    def test_rule_pack_validator_accepts_v2_flow_preview_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            valid_path = temp_path / "valid_v2_flow.json"
            valid_path.write_text(json.dumps(_rule_pack([_flow_rule()], schema_version=2)), encoding="utf-8")

            self.assertEqual(validate_rule_pack_file(valid_path), [])

            v1_path = temp_path / "v1_flow_rejected.json"
            v1_path.write_text(json.dumps(_rule_pack([_flow_rule()])), encoding="utf-8")
            self.assertTrue(any("phase" in error for error in validate_rule_pack_file(v1_path)))

            not_preview = _flow_rule()
            not_preview["emit"]["preview_only"] = False
            not_preview_path = temp_path / "flow_not_preview.json"
            not_preview_path.write_text(json.dumps(_rule_pack([not_preview], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("preview_only must be true" in error for error in validate_rule_pack_file(not_preview_path)))

            missing_flow_kind = _flow_rule()
            del missing_flow_kind["emit"]["flow_kind"]
            missing_flow_kind_path = temp_path / "flow_missing_kind.json"
            missing_flow_kind_path.write_text(
                json.dumps(_rule_pack([missing_flow_kind], schema_version=2)),
                encoding="utf-8",
            )
            self.assertTrue(any("flow_kind is required" in error for error in validate_rule_pack_file(missing_flow_kind_path)))

            missing_case_count = _flow_rule()
            del missing_case_count["match"]["flow_case_count_min"]
            missing_case_count_path = temp_path / "flow_missing_count.json"
            missing_case_count_path.write_text(
                json.dumps(_rule_pack([missing_case_count], schema_version=2)),
                encoding="utf-8",
            )
            self.assertTrue(
                any("flow_case_count_min is required" in error for error in validate_rule_pack_file(missing_case_count_path))
            )

            weak_case_count = _flow_rule(min_cases=2)
            weak_case_count_path = temp_path / "flow_weak_count.json"
            weak_case_count_path.write_text(json.dumps(_rule_pack([weak_case_count], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("flow_case_count_min must be an integer >= 3" in error for error in validate_rule_pack_file(weak_case_count_path)))

            regex_flow = _flow_rule()
            regex_flow["match"]["regex"] = "switch"
            regex_flow_path = temp_path / "flow_regex.json"
            regex_flow_path.write_text(json.dumps(_rule_pack([regex_flow], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("regex is not supported for flow" in error for error in validate_rule_pack_file(regex_flow_path)))

    def test_rule_pack_validator_accepts_v2_call_arg_match_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            valid_rule = _call_arg_rewrite_rule()
            valid_rule["match"] = _call_arg_gate_match()
            valid_path = temp_path / "valid_call_arg_gates.json"
            valid_path.write_text(json.dumps(_rule_pack([valid_rule], schema_version=2)), encoding="utf-8")
            self.assertEqual(validate_rule_pack_file(valid_path), [])

            v1_rule = _rename_rule()
            v1_rule["match"] = {
                "call_arg_count": {
                    "function_name": "ProbeForRead",
                    "count": 3,
                }
            }
            v1_path = temp_path / "v1_call_arg_gate.json"
            v1_path.write_text(json.dumps(_rule_pack([v1_rule])), encoding="utf-8")
            self.assertTrue(any("call_arg_count is not supported" in error for error in validate_rule_pack_file(v1_path)))

            invalid_count = _call_arg_rewrite_rule()
            invalid_count["match"] = {
                "call_arg_count": {
                    "function_name": "ProbeForRead",
                    "count": True,
                }
            }
            invalid_count_path = temp_path / "invalid_count.json"
            invalid_count_path.write_text(json.dumps(_rule_pack([invalid_count], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("count must be a non-negative integer" in error for error in validate_rule_pack_file(invalid_count_path)))

    def test_rule_pack_validator_accepts_typed_fact_operators_only_in_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            typed_rule = {
                "id": "test.rename.typed",
                "phase": "rename",
                "priority": 100,
                "confidence": 0.91,
                "scope": {
                    "lvar": {
                        "name_regex": "^v\\d+$",
                        "type_contains": "int",
                        "is_arg": False,
                    },
                    "profile_function": {
                        "function_name": "ProbeForRead",
                        "param": {
                            "index": 2,
                            "type_regex": "^ULONG$",
                            "kind": "flags",
                        },
                    },
                },
                "match": {
                    "assignment": {
                        "target_regex": "^v\\d+$",
                        "rhs_call_name": "ProbeForRead",
                        "rhs_identifier_any": ["inputBuffer"],
                        "rhs_literal_all": ["8", "1"],
                        "rhs_call_arg_count": 3,
                        "rhs_call_arg_regex": {
                            "argument_index": 0,
                            "regex": "input",
                        },
                    }
                },
                "emit": {
                    "kind": "rename",
                    "rename_kind": "lvar",
                    "target": "$assignment_target",
                    "new_name": "probeStatus",
                },
            }
            valid_path = temp_path / "typed_v2.json"
            valid_path.write_text(json.dumps(_rule_pack([typed_rule], schema_version=2)), encoding="utf-8")
            self.assertEqual(validate_rule_pack_file(valid_path), [])

            v1_path = temp_path / "typed_v1.json"
            v1_path.write_text(json.dumps(_rule_pack([typed_rule], schema_version=1)), encoding="utf-8")
            self.assertTrue(any("assignment is not supported" in error or "lvar is not supported" in error for error in validate_rule_pack_file(v1_path)))

            ambiguous = dict(typed_rule)
            ambiguous["match"] = {
                "assignment": typed_rule["match"]["assignment"],
                "regex": "ProbeForRead",
            }
            ambiguous_path = temp_path / "typed_ambiguous.json"
            ambiguous_path.write_text(json.dumps(_rule_pack([ambiguous], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("must not combine regex matchers" in error for error in validate_rule_pack_file(ambiguous_path)))

            ambiguous_call_arg_gate = dict(typed_rule)
            ambiguous_call_arg_gate["match"] = {
                "call_site": {
                    "function_name": "ProbeForRead",
                    "arg_count": 3,
                },
                "call_arg_literal": {
                    "function_name": "ProbeForRead",
                    "argument_index": 2,
                    "value": "1",
                },
            }
            ambiguous_call_arg_gate_path = temp_path / "typed_call_arg_gate_ambiguous.json"
            ambiguous_call_arg_gate_path.write_text(json.dumps(_rule_pack([ambiguous_call_arg_gate], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("typed fact match operators with call_arg" in error for error in validate_rule_pack_file(ambiguous_call_arg_gate_path)))

            ambiguous_flow_gate = dict(typed_rule)
            ambiguous_flow_gate["match"] = {
                "assignment": typed_rule["match"]["assignment"],
                "flow_case_count_min": 4,
            }
            ambiguous_flow_gate_path = temp_path / "typed_flow_gate_ambiguous.json"
            ambiguous_flow_gate_path.write_text(json.dumps(_rule_pack([ambiguous_flow_gate], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("typed fact match operators with call_arg or flow" in error for error in validate_rule_pack_file(ambiguous_flow_gate_path)))

            invalid_inner_regex = dict(typed_rule)
            invalid_inner_regex["match"] = {
                "call_site": {
                    "function_name": "ProbeForRead",
                    "arg_regex": {
                        "argument_index": 0,
                        "regex": "(",
                    },
                }
            }
            invalid_inner_regex_path = temp_path / "typed_bad_regex.json"
            invalid_inner_regex_path.write_text(json.dumps(_rule_pack([invalid_inner_regex], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("arg_regex.regex invalid regex" in error for error in validate_rule_pack_file(invalid_inner_regex_path)))

            invalid_literal = _call_arg_rewrite_rule()
            invalid_literal["match"] = {
                "call_arg_literal": {
                    "function_name": "ProbeForRead",
                    "argument_index": -1,
                    "value": "1",
                }
            }
            invalid_literal_path = temp_path / "invalid_literal.json"
            invalid_literal_path.write_text(json.dumps(_rule_pack([invalid_literal], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("argument_index must be a non-negative integer" in error for error in validate_rule_pack_file(invalid_literal_path)))


if __name__ == "__main__":
    unittest.main()

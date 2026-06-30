from __future__ import annotations

import json

from ida_pseudoforge.core.plan_schema import FunctionCapture


SYSTEM_RENAME_PROMPT = (
    "You are a defensive static-code readability assistant. "
    "Your only task is to suggest clearer local variable and argument names "
    "for analyst review. Do not rewrite code, do not explain exploitability, "
    "do not provide bypass, evasion, persistence, exploitation, or operational "
    "guidance, and do not infer behavior beyond the supplied pseudocode. "
    "Return strict JSON only."
)


SYSTEM_CANDIDATE_PROMPT = (
    "You are a defensive static-code readability assistant. "
    "Suggest review-only field, type-role, and intent-comment candidates "
    "from the supplied pseudocode. Do not rewrite code, do not claim a fact "
    "without local evidence, do not provide bypass, evasion, persistence, "
    "exploitation, or operational guidance, and do not infer behavior beyond "
    "the supplied pseudocode. Return strict JSON only."
)


def build_rename_prompt(capture: FunctionCapture) -> str:
    locals_summary = [
        {
            "name": var.name,
            "type": var.type,
            "is_arg": var.is_arg,
        }
        for var in capture.lvars
    ]
    facts = {
        "function_name": capture.name,
        "prototype": capture.prototype,
        "locals": locals_summary,
        "calls": capture.calls[:128],
        "pseudocode_excerpt": capture.pseudocode[:12000],
        "required_json_shape": {
            "renames": [
                {
                    "old": "v5",
                    "new": "infoClass",
                    "confidence": 0.95,
                    "reason": "short evidence",
                }
            ],
            "warnings": [],
        },
    }
    return json.dumps(facts, ensure_ascii=False)


def build_field_candidate_prompt(capture: FunctionCapture) -> str:
    facts = _candidate_base_facts(capture)
    facts["task"] = "field_candidates"
    facts["required_json_shape"] = {
        "field_candidates": [
            {
                "base": "ctx",
                "offset": "0x18",
                "name": "sessionId",
                "confidence": 0.82,
                "evidence": "ctx + 0x18 is compared with a session id local",
            }
        ],
        "warnings": [],
    }
    return json.dumps(facts, ensure_ascii=False)


def build_type_role_candidate_prompt(capture: FunctionCapture) -> str:
    facts = _candidate_base_facts(capture)
    facts["task"] = "type_role_candidates"
    facts["required_json_shape"] = {
        "type_role_candidates": [
            {
                "target": "v3",
                "role": "byte_length",
                "type": "size_t",
                "confidence": 0.82,
                "evidence": "v3 bounds a byte-copy loop",
            }
        ],
        "warnings": [],
    }
    return json.dumps(facts, ensure_ascii=False)


def build_intent_comment_candidate_prompt(capture: FunctionCapture) -> str:
    facts = _candidate_base_facts(capture)
    facts["task"] = "intent_comments"
    facts["required_json_shape"] = {
        "intent_comments": [
            {
                "anchor": "function",
                "text": "Validates input length before copying the buffer.",
                "confidence": 0.82,
                "evidence": "length check dominates the copy loop",
            }
        ],
        "warnings": [],
    }
    return json.dumps(facts, ensure_ascii=False)


def build_candidate_prompt(capture: FunctionCapture) -> str:
    facts = _candidate_base_facts(capture)
    facts["tasks"] = [
        "field_candidates",
        "type_role_candidates",
        "intent_comments",
    ]
    facts["required_json_shape"] = {
        "field_candidates": [
            {
                "base": "ctx",
                "offset": "0x18",
                "name": "sessionId",
                "confidence": 0.82,
                "evidence": "short local evidence",
            }
        ],
        "type_role_candidates": [
            {
                "target": "v3",
                "role": "byte_length",
                "type": "size_t",
                "confidence": 0.82,
                "evidence": "short local evidence",
            }
        ],
        "intent_comments": [
            {
                "anchor": "function",
                "text": "One short review-only intent sentence.",
                "confidence": 0.82,
                "evidence": "short local evidence",
            }
        ],
        "warnings": [],
    }
    return json.dumps(facts, ensure_ascii=False)


def build_cli_rename_prompt(capture: FunctionCapture) -> str:
    return (
        SYSTEM_RENAME_PROMPT
        + "\n\nInput JSON:\n"
        + build_rename_prompt(capture)
        + "\n\nReturn only a JSON object matching required_json_shape."
    )


def build_cli_candidate_prompt(capture: FunctionCapture) -> str:
    return (
        SYSTEM_CANDIDATE_PROMPT
        + "\n\nInput JSON:\n"
        + build_candidate_prompt(capture)
        + "\n\nReturn only a JSON object matching required_json_shape."
    )


def _candidate_base_facts(capture: FunctionCapture) -> dict[str, object]:
    locals_summary = [
        {
            "name": var.name,
            "type": var.type,
            "is_arg": var.is_arg,
        }
        for var in capture.lvars
    ]
    return {
        "function_name": capture.name,
        "prototype": capture.prototype,
        "locals": locals_summary,
        "calls": capture.calls[:128],
        "target_context": capture.target_context.to_dict(),
        "pseudocode_excerpt": capture.pseudocode[:12000],
    }

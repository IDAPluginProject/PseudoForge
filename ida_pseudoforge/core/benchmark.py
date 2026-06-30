from __future__ import annotations

from collections import Counter
from time import perf_counter
from typing import Any

from ida_pseudoforge.core.benchmark_schema import BenchmarkFixture, BenchmarkObservation
from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.claim_gate import evaluate_claim_gate
from ida_pseudoforge.core.generic_candidates import generic_candidate_json_payload
from ida_pseudoforge.core.ir_evidence import ir_evidence_summary
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.quality_score import score_pseudocode_quality


REPORT_SCHEMA = "pseudoforge_general_benchmark_v1"


def run_benchmark(
    fixtures: list[BenchmarkFixture],
    measure_runtime: bool = True,
    corpus_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    results = [_run_fixture(fixture, measure_runtime=measure_runtime) for fixture in fixtures]
    status_counts = Counter(str(item.get("status", "")) for item in results)
    accepted_observations = sum(int(item.get("accepted_observations", 0) or 0) for item in results)
    false_positives = sum(int(item.get("false_positives", 0) or 0) for item in results)
    candidate_count = sum(int(item.get("candidate_count", 0) or 0) for item in results)
    blocked_suggestions = sum(int(item.get("blocked_suggestions", 0) or 0) for item in results)
    rewrite_eligible_count = sum(int(item.get("rewrite_eligible_count", 0) or 0) for item in results)
    runtime_ms = sum(int(item.get("runtime_ms", 0) or 0) for item in results)
    report = {
        "schema": REPORT_SCHEMA,
        "claim_level": "foundation prototype",
        "fixture_count": len(results),
        "passed": int(status_counts.get("passed", 0)),
        "failed": int(status_counts.get("failed", 0)),
        "accepted_observations": accepted_observations,
        "false_positives": false_positives,
        "candidate_count": candidate_count,
        "blocked_suggestions": blocked_suggestions,
        "rewrite_eligible_count": rewrite_eligible_count,
        "runtime_ms": runtime_ms,
        "fixtures": results,
    }
    if corpus_evidence is not None:
        report["corpus_evidence"] = dict(corpus_evidence)
    claim_gate = evaluate_claim_gate(report)
    report["claim_gate"] = claim_gate
    report["claim_level"] = claim_gate["claim_level"]
    return report


def _run_fixture(fixture: BenchmarkFixture, measure_runtime: bool) -> dict[str, Any]:
    start = perf_counter()
    capture = capture_from_pseudocode(
        fixture.pseudocode,
        name=fixture.name,
        ea=fixture.ea,
        source_path=fixture.source_path,
        profile_context=fixture.profile_context,
    )
    plan = build_clean_plan(capture)
    cleaned = render_cleaned_pseudocode(capture, plan)
    generic_payload = generic_candidate_json_payload(capture, plan)
    ir_summary = ir_evidence_summary(capture.ir_evidence)
    quality = score_pseudocode_quality(cleaned, capture.pseudocode)
    runtime_ms = int(round((perf_counter() - start) * 1000)) if measure_runtime else 0
    expectation_results = [
        _expected_result(observation, capture, plan, generic_payload)
        for observation in fixture.expected_observations
    ]
    negative_results = [
        _negative_result(observation, capture, plan, generic_payload)
        for observation in fixture.negative_controls
    ]
    failed = [item for item in expectation_results if not item["passed"]]
    false_positive_failures = [item for item in negative_results if not item["passed"]]
    comments = [item for item in plan.comments if isinstance(item, dict)]
    contract_comments = [
        item
        for item in comments
        if str(item.get("kind", "") or "") == "contract_pack_api"
    ]
    generic_candidate_count = int(generic_payload.get("candidate_count", 0) or 0)
    rewrite_eligible_count = int(generic_payload.get("rewrite_eligible_count", 0) or 0)
    blocked_suggestions = max(0, generic_candidate_count - rewrite_eligible_count)
    blocked_suggestions += sum(1 for item in plan.llm_candidates if str(item.status or "") == "blocked")
    return {
        "name": fixture.name,
        "status": "failed" if failed or false_positive_failures else "passed",
        "source_path": fixture.source_path,
        "target_family": capture.target_context.target_family,
        "target_confidence": capture.target_context.confidence,
        "active_domain_packs": list(capture.target_context.active_domain_packs),
        "eligible_domain_packs": list(capture.target_context.eligible_domain_packs),
        "rejected_domain_packs": list(capture.target_context.rejected_domain_packs),
        "domain_pack_activation_report": list(capture.target_context.domain_pack_activation_report),
        "import_families": list(capture.target_context.import_families),
        "section_clues": list(capture.target_context.section_clues),
        "runtime_clues": list(capture.target_context.runtime_clues),
        "comment_kinds": sorted({str(item.get("kind", "") or "") for item in comments if item.get("kind")}),
        "contract_profiles": sorted(
            {
                str(item.get("contract_profile", "") or "")
                for item in contract_comments
                if item.get("contract_profile")
            }
        ),
        "contract_domains": sorted(
            {
                str(item.get("contract_domain", "") or "")
                for item in contract_comments
                if item.get("contract_domain")
            }
        ),
        "contract_symbols": sorted(
            {
                str(item.get("contract_symbol", "") or "")
                for item in contract_comments
                if item.get("contract_symbol")
            }
        ),
        "matched_rule_ids": [
            str(item.get("rule_id", "") or "")
            for item in plan.rule_report.get("matched_rules", [])
            if isinstance(item, dict) and item.get("rule_id")
        ],
        "ir_evidence_summary": ir_summary,
        "candidate_count": generic_candidate_count,
        "blocked_suggestions": blocked_suggestions,
        "rewrite_eligible_count": rewrite_eligible_count,
        "quality_score": quality.score,
        "quality_opportunity": quality.opportunity,
        "accepted_observations": sum(1 for item in expectation_results if item["passed"]),
        "false_positives": len(false_positive_failures),
        "runtime_ms": runtime_ms,
        "expectation_results": expectation_results,
        "negative_control_results": negative_results,
    }


def _expected_result(
    observation: BenchmarkObservation,
    capture: Any,
    plan: Any,
    generic_payload: dict[str, Any],
) -> dict[str, Any]:
    observed = _observation_matches(observation, capture, plan, generic_payload)
    return {
        "kind": observation.kind,
        "value": observation.value,
        "description": observation.description,
        "passed": observed,
        "message": "observed" if observed else "expected observation was not present",
    }


def _negative_result(
    observation: BenchmarkObservation,
    capture: Any,
    plan: Any,
    generic_payload: dict[str, Any],
) -> dict[str, Any]:
    observed = _observation_matches(observation, capture, plan, generic_payload)
    return {
        "kind": observation.kind,
        "value": observation.value,
        "description": observation.description,
        "passed": not observed,
        "message": "not observed" if not observed else "negative control was observed",
    }


def _observation_matches(
    observation: BenchmarkObservation,
    capture: Any,
    plan: Any,
    generic_payload: dict[str, Any],
) -> bool:
    kind = str(observation.kind or "")
    value = str(observation.value or "")
    target = capture.target_context
    if kind == "target_family":
        return target.target_family == value
    if kind == "target_field":
        return _target_field_matches(target, value)
    if kind == "import_family":
        return value in target.import_families
    if kind == "section_clue":
        return value in target.section_clues
    if kind == "runtime_clue":
        return value in target.runtime_clues
    if kind == "active_domain_pack":
        return value in target.active_domain_packs
    if kind == "eligible_domain_pack":
        return value in target.eligible_domain_packs
    if kind == "rejected_domain_pack":
        return value in target.rejected_domain_packs
    if kind == "comment_kind":
        return any(isinstance(item, dict) and item.get("kind") == value for item in plan.comments)
    if kind == "contract_symbol":
        return _contract_comment_matches(plan, "contract_symbol", value)
    if kind == "contract_domain":
        return _contract_comment_matches(plan, "contract_domain", value)
    if kind == "contract_profile":
        return _contract_comment_matches(plan, "contract_profile", value)
    if kind == "matched_rule_id":
        return any(_rule_id(item) == value for item in plan.rule_report.get("matched_rules", []))
    if kind == "matched_rule_prefix":
        return any(_rule_id(item).startswith(value) for item in plan.rule_report.get("matched_rules", []))
    if kind == "generic_candidate_min":
        return int(generic_payload.get("candidate_count", 0) or 0) >= _int_value(value, 0)
    if kind == "ir_available":
        return bool(getattr(capture.ir_evidence, "available", False)) == _bool_value(value)
    if kind == "ir_call_site_min":
        return len(getattr(capture.ir_evidence, "call_site_signatures", []) or []) >= _int_value(value, 0)
    if kind == "ir_call_argument":
        return _ir_call_argument_matches(capture.ir_evidence, value)
    if kind == "ir_use_def_min":
        return len(getattr(capture.ir_evidence, "use_def_chains", []) or []) >= _int_value(value, 0)
    if kind == "ir_diagnostic":
        return value in [str(item) for item in getattr(capture.ir_evidence, "diagnostics", []) or []]
    return False


def _target_field_matches(target: Any, value: str) -> bool:
    if "=" not in value:
        return False
    field_name, expected = value.split("=", 1)
    return str(getattr(target, field_name.strip(), "") or "") == expected.strip()


def _rule_id(item: object) -> str:
    if isinstance(item, dict):
        return str(item.get("rule_id", "") or "")
    return ""


def _contract_comment_matches(plan: Any, field_name: str, value: str) -> bool:
    return any(
        isinstance(item, dict)
        and str(item.get("kind", "") or "") == "contract_pack_api"
        and str(item.get(field_name, "") or "") == value
        for item in getattr(plan, "comments", []) or []
    )


def _ir_call_argument_matches(ir_evidence: Any, value: str) -> bool:
    if ":" not in value:
        return False
    call_name, argument = value.split(":", 1)
    call_name = call_name.strip()
    argument = argument.strip()
    if not call_name or not argument:
        return False
    for signature in getattr(ir_evidence, "call_site_signatures", []) or []:
        if str(getattr(signature, "call_name", "") or "") != call_name:
            continue
        arguments = [str(item) for item in getattr(signature, "argument_names", []) or []]
        if argument in arguments:
            return True
    return False


def _int_value(value: object, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)


def _bool_value(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}

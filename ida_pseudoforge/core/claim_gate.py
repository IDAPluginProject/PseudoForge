from __future__ import annotations

from collections import defaultdict
from typing import Any


CLAIM_GATE_SCHEMA = "pseudoforge_general_claim_gate_v1"

CLAIM_LEVELS = [
    "foundation prototype",
    "useful general assistant",
    "advanced general cleanup",
    "world-class candidate",
]


def evaluate_claim_gate(
    report: dict[str, Any],
    baseline_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metrics = _collect_metrics(report)
    corpus = _corpus_evidence(report)
    family_dashboard = _target_family_dashboard(report)
    blockers: list[str] = []
    passed_gates: list[str] = []

    if metrics["failed"] > 0:
        blockers.append("benchmark_failures_present")
    else:
        passed_gates.append("all_fixtures_passed")

    if metrics["false_positives"] > 0:
        blockers.append("false_positive_failures_present")
    else:
        passed_gates.append("no_false_positive_failures")

    if metrics["negative_controls"] <= 0:
        blockers.append("missing_false_positive_data")
    else:
        passed_gates.append("false_positive_data_present")

    if metrics["target_family_count"] >= 2:
        passed_gates.append("multi_family_coverage")
    else:
        blockers.append("single_family_or_unknown_coverage")

    if metrics["contract_profile_count"] > 0:
        passed_gates.append("contract_profiles_observed")
    else:
        blockers.append("contract_profiles_missing")

    if corpus["real_corpus_count"] <= 0:
        blockers.append("real_corpus_gate_missing")
    if corpus["qualified_ground_truth_pair_count"] <= 0:
        blockers.append("qualified_ground_truth_pairs_missing")

    claim_level = "foundation prototype"
    if _passes_useful(metrics, corpus):
        claim_level = "useful general assistant"
        passed_gates.append("useful_general_assistant_threshold")
    else:
        blockers.append("useful_general_assistant_threshold_not_met")

    if _passes_advanced(metrics, corpus):
        claim_level = "advanced general cleanup"
        passed_gates.append("advanced_general_cleanup_threshold")
    else:
        blockers.append("advanced_general_cleanup_threshold_not_met")

    if _passes_world_class(metrics, corpus):
        claim_level = "world-class candidate"
        passed_gates.append("world_class_candidate_threshold")
    else:
        blockers.append("world_class_candidate_threshold_not_met")

    regressions = _regressions(report, baseline_report, claim_level) if baseline_report is not None else []
    status = "failed" if metrics["failed"] > 0 or metrics["false_positives"] > 0 or regressions else "passed"
    rank = _claim_rank(claim_level)
    return {
        "schema": CLAIM_GATE_SCHEMA,
        "status": status,
        "claim_level": claim_level,
        "claim_rank": rank,
        "world_class_claim_allowed": claim_level == "world-class candidate" and status == "passed",
        "release_claim": _release_claim(claim_level, status),
        "metrics": metrics,
        "corpus_evidence": corpus,
        "target_families": family_dashboard,
        "passed_gates": sorted(set(passed_gates)),
        "blockers": sorted(set(blockers)),
        "regressions": regressions,
    }


def _passes_useful(metrics: dict[str, Any], corpus: dict[str, Any]) -> bool:
    if metrics["failed"] != 0 or metrics["false_positives"] != 0:
        return False
    if metrics["negative_controls"] <= 0:
        return False
    if metrics["fixture_count"] < 2 or metrics["target_family_count"] < 2:
        return False
    if metrics["accepted_observations"] < 10:
        return False
    if metrics["eligible_domain_pack_count"] < 2 and metrics["contract_profile_count"] < 2:
        return False
    if corpus["real_corpus_count"] < 2 or corpus["real_corpus_function_count"] < 25:
        return False
    if corpus["ground_truth_pair_count"] < 2 or corpus["qualified_ground_truth_pair_count"] < 2:
        return False
    return True


def _passes_advanced(metrics: dict[str, Any], corpus: dict[str, Any]) -> bool:
    if not _passes_useful(metrics, corpus):
        return False
    if metrics["target_family_count"] < 3:
        return False
    if metrics["accepted_observations"] < 40:
        return False
    if metrics["precision"] is None or metrics["precision"] < 0.97:
        return False
    if corpus["real_corpus_count"] < 4 or corpus["real_corpus_function_count"] < 250:
        return False
    if corpus["qualified_ground_truth_pair_count"] < 50:
        return False
    if corpus["ir_evidence_coverage"] < 0.5:
        return False
    if corpus["qualified_cross_function_contract_count"] < 25:
        return False
    return True


def _passes_world_class(metrics: dict[str, Any], corpus: dict[str, Any]) -> bool:
    if not _passes_advanced(metrics, corpus):
        return False
    if metrics["target_family_count"] < 5:
        return False
    if metrics["precision"] is None or metrics["precision"] < 0.98:
        return False
    if corpus["real_corpus_function_count"] < 1000:
        return False
    if corpus["qualified_ground_truth_pair_count"] < 250:
        return False
    if corpus["qualified_external_baseline_count"] < 2:
        return False
    if corpus["qualified_analyst_audit_count"] < 1:
        return False
    return True


def _collect_metrics(report: dict[str, Any]) -> dict[str, Any]:
    fixtures = [item for item in report.get("fixtures", []) or [] if isinstance(item, dict)]
    corpus = _corpus_evidence(report)
    fixture_families = sorted({str(item.get("target_family", "") or "") for item in fixtures if item.get("target_family")})
    corpus_families = _string_list(corpus.get("target_families"))
    families = sorted(set(fixture_families) | set(corpus_families))
    active_packs = _unique_from_fixtures(fixtures, "active_domain_packs")
    eligible_packs = _unique_from_fixtures(fixtures, "eligible_domain_packs")
    contract_profiles = _unique_from_fixtures(fixtures, "contract_profiles")
    negative_controls = sum(len(item.get("negative_control_results", []) or []) for item in fixtures)
    expected_observations = sum(len(item.get("expectation_results", []) or []) for item in fixtures)
    rewrite_eligible_count = sum(_int(item.get("rewrite_eligible_count"), 0) for item in fixtures)
    false_positives = _int(report.get("false_positives"), 0)
    accepted_observations = _int(report.get("accepted_observations"), 0)
    precision = None
    if negative_controls > 0:
        denominator = accepted_observations + false_positives
        precision = 1.0 if denominator <= 0 else accepted_observations / denominator
    return {
        "fixture_count": _int(report.get("fixture_count"), len(fixtures)),
        "passed": _int(report.get("passed"), 0),
        "failed": _int(report.get("failed"), 0),
        "accepted_observations": accepted_observations,
        "expected_observations": expected_observations,
        "false_positives": false_positives,
        "negative_controls": negative_controls,
        "precision": precision,
        "candidate_count": _int(report.get("candidate_count"), 0),
        "blocked_suggestions": _int(report.get("blocked_suggestions"), 0),
        "rewrite_eligible_count": rewrite_eligible_count,
        "runtime_ms": _int(report.get("runtime_ms"), 0),
        "target_family_count": len(families),
        "target_families": families,
        "fixture_target_family_count": len(fixture_families),
        "corpus_target_family_count": len(corpus_families),
        "active_domain_pack_count": len(active_packs),
        "eligible_domain_pack_count": len(eligible_packs),
        "contract_profile_count": len(contract_profiles),
        "contract_profiles": contract_profiles,
    }


def _target_family_dashboard(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    fixtures = [item for item in report.get("fixtures", []) or [] if isinstance(item, dict)]
    grouped: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "fixtures": 0,
            "passed": 0,
            "failed": 0,
            "accepted_observations": 0,
            "false_positives": 0,
            "negative_controls": 0,
            "candidate_count": 0,
            "blocked_suggestions": 0,
            "runtime_ms": 0,
            "eligible_domain_packs": set(),
            "contract_profiles": set(),
        }
    )
    for fixture in fixtures:
        family = str(fixture.get("target_family", "") or "unknown")
        item = grouped[family]
        item["fixtures"] += 1
        if str(fixture.get("status", "") or "") == "passed":
            item["passed"] += 1
        else:
            item["failed"] += 1
        item["accepted_observations"] += _int(fixture.get("accepted_observations"), 0)
        item["false_positives"] += _int(fixture.get("false_positives"), 0)
        item["negative_controls"] += len(fixture.get("negative_control_results", []) or [])
        item["candidate_count"] += _int(fixture.get("candidate_count"), 0)
        item["blocked_suggestions"] += _int(fixture.get("blocked_suggestions"), 0)
        item["runtime_ms"] += _int(fixture.get("runtime_ms"), 0)
        item["eligible_domain_packs"].update(str(value) for value in fixture.get("eligible_domain_packs", []) or [] if str(value))
        item["contract_profiles"].update(str(value) for value in fixture.get("contract_profiles", []) or [] if str(value))
    result: dict[str, dict[str, Any]] = {}
    for family in sorted(grouped):
        item = grouped[family]
        result[family] = {
            "fixtures": item["fixtures"],
            "passed": item["passed"],
            "failed": item["failed"],
            "accepted_observations": item["accepted_observations"],
            "false_positives": item["false_positives"],
            "negative_controls": item["negative_controls"],
            "candidate_count": item["candidate_count"],
            "blocked_suggestions": item["blocked_suggestions"],
            "runtime_ms": item["runtime_ms"],
            "eligible_domain_packs": sorted(item["eligible_domain_packs"]),
            "contract_profiles": sorted(item["contract_profiles"]),
        }
    return result


def _regressions(
    report: dict[str, Any],
    baseline_report: dict[str, Any] | None,
    current_claim_level: str,
) -> list[dict[str, Any]]:
    if baseline_report is None:
        return []
    current = _collect_metrics(report)
    baseline = _collect_metrics(baseline_report)
    regressions: list[dict[str, Any]] = []
    _append_regression(regressions, "failed", baseline["failed"], current["failed"], "max")
    _append_regression(regressions, "false_positives", baseline["false_positives"], current["false_positives"], "max")
    _append_regression(regressions, "accepted_observations", baseline["accepted_observations"], current["accepted_observations"], "min")
    _append_regression(regressions, "target_family_count", baseline["target_family_count"], current["target_family_count"], "min")
    current_corpus = _corpus_evidence(report)
    baseline_corpus = _corpus_evidence(baseline_report)
    _append_regression(regressions, "real_corpus_count", baseline_corpus["real_corpus_count"], current_corpus["real_corpus_count"], "min")
    _append_regression(
        regressions,
        "real_corpus_function_count",
        baseline_corpus["real_corpus_function_count"],
        current_corpus["real_corpus_function_count"],
        "min",
    )
    _append_regression(
        regressions,
        "qualified_ground_truth_pair_count",
        baseline_corpus["qualified_ground_truth_pair_count"],
        current_corpus["qualified_ground_truth_pair_count"],
        "min",
    )
    _append_float_regression(
        regressions,
        "ir_evidence_coverage",
        baseline_corpus["ir_evidence_coverage"],
        current_corpus["ir_evidence_coverage"],
        "min",
    )
    _append_regression(
        regressions,
        "cross_function_contract_count",
        baseline_corpus["cross_function_contract_count"],
        current_corpus["cross_function_contract_count"],
        "min",
    )
    _append_regression(
        regressions,
        "qualified_cross_function_contract_count",
        baseline_corpus["qualified_cross_function_contract_count"],
        current_corpus["qualified_cross_function_contract_count"],
        "min",
    )
    _append_regression(
        regressions,
        "qualified_external_baseline_count",
        baseline_corpus["qualified_external_baseline_count"],
        current_corpus["qualified_external_baseline_count"],
        "min",
    )
    _append_regression(
        regressions,
        "qualified_analyst_audit_count",
        baseline_corpus["qualified_analyst_audit_count"],
        current_corpus["qualified_analyst_audit_count"],
        "min",
    )
    baseline_rank = _claim_rank(_report_claim_level(baseline_report))
    current_rank = _claim_rank(current_claim_level)
    if current_rank < baseline_rank:
        regressions.append(
            {
                "metric": "claim_rank",
                "baseline": baseline_rank,
                "current": current_rank,
                "direction": "min",
            }
        )
    return regressions


def _append_regression(
    regressions: list[dict[str, Any]],
    metric: str,
    baseline: int,
    current: int,
    direction: str,
) -> None:
    if direction == "max" and current > baseline:
        regressions.append(
            {
                "metric": metric,
                "baseline": baseline,
                "current": current,
                "direction": direction,
            }
        )
    if direction == "min" and current < baseline:
        regressions.append(
            {
                "metric": metric,
                "baseline": baseline,
                "current": current,
                "direction": direction,
            }
        )


def _append_float_regression(
    regressions: list[dict[str, Any]],
    metric: str,
    baseline: float,
    current: float,
    direction: str,
) -> None:
    if direction == "min" and current < baseline:
        regressions.append(
            {
                "metric": metric,
                "baseline": baseline,
                "current": current,
                "direction": direction,
            }
        )


def _release_claim(claim_level: str, status: str) -> str:
    if status == "failed":
        return "General-analysis quality claims are blocked because the benchmark or regression gate failed."
    if claim_level == "world-class candidate":
        return "PseudoForge is a world-class candidate for general decompile cleanup based on passed multi-corpus precision, IR, baseline, and analyst-audit gates."
    if claim_level == "advanced general cleanup":
        return "PseudoForge has advanced general cleanup evidence across measured corpora, with IR-backed promotion and low false-positive gates."
    if claim_level == "useful general assistant":
        return "PseudoForge has measured evidence as a useful general decompile assistant across multiple general-analysis corpora."
    return "PseudoForge has a foundation prototype for general-analysis cleanup; broad quality claims remain blocked until real-corpus precision gates pass."


def _corpus_evidence(report: dict[str, Any]) -> dict[str, Any]:
    raw = report.get("corpus_evidence", {})
    if not isinstance(raw, dict):
        raw = {}
    return {
        "manifest_count": _int(raw.get("manifest_count"), 0),
        "real_corpus_count": _int(raw.get("real_corpus_count"), 0),
        "real_corpus_function_count": _int(raw.get("real_corpus_function_count"), 0),
        "ground_truth_pair_count": _int(raw.get("ground_truth_pair_count"), 0),
        "qualified_ground_truth_pair_count": _int(raw.get("qualified_ground_truth_pair_count"), 0),
        "ir_evidence_coverage": _float(raw.get("ir_evidence_coverage"), 0.0),
        "cross_function_contract_count": _int(raw.get("cross_function_contract_count"), 0),
        "qualified_cross_function_contract_count": _int(raw.get("qualified_cross_function_contract_count"), 0),
        "external_baseline_count": _int(raw.get("external_baseline_count"), 0),
        "qualified_external_baseline_count": _int(raw.get("qualified_external_baseline_count"), 0),
        "analyst_audit_count": _int(raw.get("analyst_audit_count"), 0),
        "qualified_analyst_audit_count": _int(raw.get("qualified_analyst_audit_count"), 0),
        "target_families": _string_list(raw.get("target_families")),
    }


def _unique_from_fixtures(fixtures: list[dict[str, Any]], field_name: str) -> list[str]:
    values: set[str] = set()
    for fixture in fixtures:
        values.update(str(value) for value in fixture.get(field_name, []) or [] if str(value))
    return sorted(values)


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(item) for item in value if str(item)})


def _report_claim_level(report: dict[str, Any]) -> str:
    gate = report.get("claim_gate", {})
    if isinstance(gate, dict) and gate.get("claim_level"):
        return str(gate.get("claim_level", "") or "")
    return str(report.get("claim_level", "") or "")


def _claim_rank(claim_level: str) -> int:
    try:
        return CLAIM_LEVELS.index(claim_level) + 1
    except ValueError:
        return 0


def _int(value: object, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)


def _float(value: object, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(fallback)

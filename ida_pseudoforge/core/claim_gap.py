from __future__ import annotations

from typing import Any

from ida_pseudoforge.core.claim_gate import evaluate_claim_gate


CLAIM_GAP_SCHEMA = "pseudoforge_general_claim_gap_v1"


def world_class_gap_report(report: dict[str, Any]) -> dict[str, Any]:
    gate = evaluate_claim_gate(report)
    metrics = gate.get("metrics", {}) if isinstance(gate.get("metrics"), dict) else {}
    corpus = gate.get("corpus_evidence", {}) if isinstance(gate.get("corpus_evidence"), dict) else {}
    gaps: list[dict[str, Any]] = []
    _add_max_gap(gaps, "metrics.failed", _int(metrics.get("failed"), 0), 0)
    _add_max_gap(gaps, "metrics.false_positives", _int(metrics.get("false_positives"), 0), 0)
    _add_min_gap(gaps, "metrics.negative_controls", _int(metrics.get("negative_controls"), 0), 1)
    _add_min_gap(gaps, "metrics.fixture_count", _int(metrics.get("fixture_count"), 0), 2)
    _add_min_gap(gaps, "metrics.target_family_count", _int(metrics.get("target_family_count"), 0), 5)
    _add_min_gap(gaps, "metrics.accepted_observations", _int(metrics.get("accepted_observations"), 0), 40)
    _add_precision_gap(gaps, metrics.get("precision"), 0.98)
    _add_domain_pack_gap(gaps, metrics)
    _add_min_gap(gaps, "corpus.real_corpus_count", _int(corpus.get("real_corpus_count"), 0), 4)
    _add_min_gap(gaps, "corpus.real_corpus_function_count", _int(corpus.get("real_corpus_function_count"), 0), 1000)
    _add_min_gap(
        gaps,
        "corpus.qualified_ground_truth_pair_count",
        _int(corpus.get("qualified_ground_truth_pair_count"), 0),
        250,
    )
    _add_min_gap(
        gaps,
        "corpus.ir_evidence_coverage",
        _float(corpus.get("ir_evidence_coverage"), 0.0),
        0.5,
    )
    _add_min_gap(
        gaps,
        "corpus.qualified_cross_function_contract_count",
        _int(corpus.get("qualified_cross_function_contract_count"), 0),
        25,
    )
    _add_min_gap(
        gaps,
        "corpus.qualified_external_baseline_count",
        _int(corpus.get("qualified_external_baseline_count"), 0),
        2,
    )
    _add_min_gap(
        gaps,
        "corpus.qualified_analyst_audit_count",
        _int(corpus.get("qualified_analyst_audit_count"), 0),
        1,
    )
    return {
        "schema": CLAIM_GAP_SCHEMA,
        "target_claim_level": "world-class candidate",
        "current_claim_level": str(gate.get("claim_level", "") or ""),
        "world_class_claim_allowed": bool(gate.get("world_class_claim_allowed", False)),
        "status": str(gate.get("status", "") or ""),
        "gap_count": len(gaps),
        "gaps": gaps,
    }


def render_world_class_gap_markdown(gap_report: dict[str, Any]) -> str:
    lines = [
        "# PseudoForge World-Class Claim Gap",
        "",
        "- Current claim level: `%s`" % _md(gap_report.get("current_claim_level")),
        "- World-class allowed: `%s`" % str(bool(gap_report.get("world_class_claim_allowed", False))).lower(),
        "- Gap count: `%s`" % _md(gap_report.get("gap_count", 0)),
        "",
    ]
    gaps = [item for item in gap_report.get("gaps", []) or [] if isinstance(item, dict)]
    if not gaps:
        lines.append("No world-class gaps remain.")
        return "\n".join(lines).rstrip() + "\n"
    lines.extend(["| Metric | Current | Required | Missing |", "|---|---:|---:|---:|"])
    for gap in gaps:
        lines.append(
            "| `%s` | `%s` | `%s` | `%s` |"
            % (
                _md(gap.get("metric", "")),
                _md(gap.get("current", "")),
                _md(gap.get("required", "")),
                _md(gap.get("missing", "")),
            )
        )
    return "\n".join(lines).rstrip() + "\n"


def _add_min_gap(
    gaps: list[dict[str, Any]],
    metric: str,
    current: int | float,
    required: int | float,
) -> None:
    if current >= required:
        return
    gaps.append(
        {
            "metric": metric,
            "direction": "min",
            "current": current,
            "required": required,
            "missing": required - current,
        }
    )


def _add_max_gap(gaps: list[dict[str, Any]], metric: str, current: int, required: int) -> None:
    if current <= required:
        return
    gaps.append(
        {
            "metric": metric,
            "direction": "max",
            "current": current,
            "required": required,
            "missing": current - required,
        }
    )


def _add_precision_gap(gaps: list[dict[str, Any]], current: object, required: float) -> None:
    if current is None:
        gaps.append(
            {
                "metric": "metrics.precision",
                "direction": "min",
                "current": None,
                "required": required,
                "missing": required,
            }
        )
        return
    _add_min_gap(gaps, "metrics.precision", _float(current, 0.0), required)


def _add_domain_pack_gap(gaps: list[dict[str, Any]], metrics: dict[str, Any]) -> None:
    eligible = _int(metrics.get("eligible_domain_pack_count"), 0)
    contracts = _int(metrics.get("contract_profile_count"), 0)
    if eligible >= 2 or contracts >= 2:
        return
    gaps.append(
        {
            "metric": "metrics.domain_pack_or_contract_profile_count",
            "direction": "any_min",
            "current": max(eligible, contracts),
            "required": 2,
            "missing": 2 - max(eligible, contracts),
        }
    )


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


def _md(value: object) -> str:
    return str(value).replace("|", "\\|")

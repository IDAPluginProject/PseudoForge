from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def benchmark_report_to_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = [
        "# PseudoForge General Analysis Benchmark",
        "",
        "- Schema: `%s`" % str(report.get("schema", "") or ""),
        "- Claim level: `%s`" % str(report.get("claim_level", "") or ""),
        "- Fixtures: `%d`" % int(report.get("fixture_count", 0) or 0),
        "- Passed: `%d`" % int(report.get("passed", 0) or 0),
        "- Failed: `%d`" % int(report.get("failed", 0) or 0),
        "- Accepted observations: `%d`" % int(report.get("accepted_observations", 0) or 0),
        "- False positives: `%d`" % int(report.get("false_positives", 0) or 0),
        "- Candidate count: `%d`" % int(report.get("candidate_count", 0) or 0),
        "- Blocked suggestions: `%d`" % int(report.get("blocked_suggestions", 0) or 0),
        "- Rewrite eligible: `%d`" % int(report.get("rewrite_eligible_count", 0) or 0),
        "- Runtime ms: `%d`" % int(report.get("runtime_ms", 0) or 0),
    ]
    claim_gate = report.get("claim_gate", {})
    if isinstance(claim_gate, dict):
        _append_claim_gate(lines, claim_gate)
    lines.extend(
        [
            "",
            "## Fixtures",
            "",
            "| Fixture | Status | Target family | Eligible packs | Accepted | False positives | Runtime ms |",
            "| --- | --- | --- | --- | ---: | ---: | ---: |",
        ]
    )
    for fixture in report.get("fixtures", []) or []:
        if not isinstance(fixture, dict):
            continue
        lines.append(
            "| `%s` | `%s` | `%s` | %s | %s | %s | %s |"
            % (
                _md(fixture.get("name", "")),
                _md(fixture.get("status", "")),
                _md(fixture.get("target_family", "")),
                _list_text(fixture.get("eligible_domain_packs", []) or []),
                fixture.get("accepted_observations", 0),
                fixture.get("false_positives", 0),
                fixture.get("runtime_ms", 0),
            )
        )
    lines.extend(["", "## Failures", ""])
    failures = _failure_rows(report)
    if not failures:
        lines.append("none")
    else:
        lines.extend(["| Fixture | Kind | Value | Message |", "| --- | --- | --- | --- |"])
        for item in failures:
            lines.append(
                "| `%s` | `%s` | `%s` | %s |"
                % (
                    _md(item.get("fixture", "")),
                    _md(item.get("kind", "")),
                    _md(item.get("value", "")),
                    _md(item.get("message", "")),
                )
            )
    lines.extend(["", "## Notes", ""])
    if isinstance(claim_gate, dict) and claim_gate.get("release_claim"):
        lines.append(str(claim_gate.get("release_claim", "") or ""))
    else:
        lines.append("Claim level is unavailable because no claim gate was attached to this report.")
    return "\n".join(lines).rstrip() + "\n"


def write_benchmark_report(report: dict[str, Any], json_path: str | Path, markdown_path: str | Path | None = None) -> None:
    target = Path(json_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    if markdown_path is not None:
        markdown_target = Path(markdown_path)
        markdown_target.parent.mkdir(parents=True, exist_ok=True)
        markdown_target.write_text(benchmark_report_to_markdown(report), encoding="utf-8")


def _failure_rows(report: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for fixture in report.get("fixtures", []) or []:
        if not isinstance(fixture, dict):
            continue
        name = str(fixture.get("name", "") or "")
        for item in fixture.get("expectation_results", []) or []:
            if isinstance(item, dict) and not item.get("passed", False):
                rows.append(
                    {
                        "fixture": name,
                        "kind": str(item.get("kind", "") or ""),
                        "value": str(item.get("value", "") or ""),
                        "message": str(item.get("message", "") or ""),
                    }
                )
        for item in fixture.get("negative_control_results", []) or []:
            if isinstance(item, dict) and not item.get("passed", False):
                rows.append(
                    {
                        "fixture": name,
                        "kind": str(item.get("kind", "") or ""),
                        "value": str(item.get("value", "") or ""),
                        "message": str(item.get("message", "") or ""),
                    }
                )
    return rows


def _list_text(values: list[Any]) -> str:
    items = [str(item) for item in values if str(item)]
    if not items:
        return "`none`"
    return ", ".join("`%s`" % _md(item) for item in items[:6])


def _append_claim_gate(lines: list[str], claim_gate: dict[str, Any]) -> None:
    metrics = claim_gate.get("metrics", {})
    if not isinstance(metrics, dict):
        metrics = {}
    lines.extend(
        [
            "",
            "## Claim Gate",
            "",
            "- Status: `%s`" % _md(claim_gate.get("status", "")),
            "- Claim rank: `%s`" % _md(claim_gate.get("claim_rank", "")),
            "- Precision: `%s`" % _precision(metrics.get("precision")),
            "- Negative controls: `%s`" % _md(metrics.get("negative_controls", "")),
            "- Target families: %s" % _list_text(metrics.get("target_families", []) or []),
            "- Contract profiles: %s" % _list_text(metrics.get("contract_profiles", []) or []),
            "- Release-safe claim: %s" % _md(claim_gate.get("release_claim", "")),
            "- Blockers: %s" % _list_text(claim_gate.get("blockers", []) or []),
            "- Regressions: %s" % _regression_text(claim_gate.get("regressions", []) or []),
            "",
            "## Corpus Evidence",
            "",
        ]
    )
    corpus = claim_gate.get("corpus_evidence", {})
    if isinstance(corpus, dict):
        lines.extend(
            [
                "- Manifests: `%s`" % _md(corpus.get("manifest_count", 0)),
                "- Real corpora: `%s`" % _md(corpus.get("real_corpus_count", 0)),
                "- Real functions: `%s`" % _md(corpus.get("real_corpus_function_count", 0)),
                "- Ground-truth pairs: `%s`" % _md(corpus.get("ground_truth_pair_count", 0)),
                "- Qualified ground-truth pairs: `%s`" % _md(corpus.get("qualified_ground_truth_pair_count", 0)),
                "- IR coverage: `%s`" % _precision(corpus.get("ir_evidence_coverage")),
                "- Cross-function contracts: `%s`" % _md(corpus.get("cross_function_contract_count", 0)),
                "- Qualified cross-function contracts: `%s`" % _md(
                    corpus.get("qualified_cross_function_contract_count", 0)
                ),
                "- External baselines: `%s`" % _md(corpus.get("external_baseline_count", 0)),
                "- Qualified external baselines: `%s`" % _md(corpus.get("qualified_external_baseline_count", 0)),
                "- Analyst audits: `%s`" % _md(corpus.get("analyst_audit_count", 0)),
                "- Qualified analyst audits: `%s`" % _md(corpus.get("qualified_analyst_audit_count", 0)),
            ]
        )
    else:
        lines.append("none")
    lines.extend(
        [
            "",
            "## Target Families",
            "",
        ]
    )
    families = claim_gate.get("target_families", {})
    if not isinstance(families, dict) or not families:
        lines.append("none")
        return
    lines.extend(
        [
            "| Family | Fixtures | Passed | Failed | Accepted | False positives | Negative controls | Eligible packs |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for family in sorted(families):
        item = families.get(family, {})
        if not isinstance(item, dict):
            continue
        lines.append(
            "| `%s` | %s | %s | %s | %s | %s | %s | %s |"
            % (
                _md(family),
                item.get("fixtures", 0),
                item.get("passed", 0),
                item.get("failed", 0),
                item.get("accepted_observations", 0),
                item.get("false_positives", 0),
                item.get("negative_controls", 0),
                _list_text(item.get("eligible_domain_packs", []) or []),
            )
        )


def _precision(value: Any) -> str:
    if value is None:
        return "n/a"
    try:
        return "%.4f" % float(value)
    except (TypeError, ValueError):
        return "n/a"


def _regression_text(values: list[Any]) -> str:
    items: list[str] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        items.append(
            "%s baseline=%s current=%s"
            % (
                _md(item.get("metric", "")),
                _md(item.get("baseline", "")),
                _md(item.get("current", "")),
            )
        )
    return _list_text(items)


def _md(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")

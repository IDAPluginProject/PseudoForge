from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from ida_pseudoforge.core.corpus_evidence import CORPUS_MANIFEST_SCHEMA


DEFAULT_REPLAY_ORIGIN = "benchmark_replay_summary"


def load_benchmark_report(path: str | Path) -> dict[str, Any]:
    report_path = Path(path)
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("benchmark report file not found: %s" % report_path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid benchmark report JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("benchmark report root must be an object")
    return payload


def corpus_manifest_from_benchmark_reports(
    reports: list[dict[str, Any]],
    name_prefix: str = "benchmark_replay",
    source_reference: str = "",
    claim_eligible: bool = False,
) -> dict[str, Any]:
    corpora: list[dict[str, Any]] = []
    for report_index, report in enumerate(reports):
        corpora.extend(
            _corpora_from_report(
                report,
                report_index,
                name_prefix=name_prefix,
                source_reference=source_reference,
                claim_eligible=claim_eligible,
            )
        )
    return {
        "schema": CORPUS_MANIFEST_SCHEMA,
        "corpora": corpora,
    }


def _corpora_from_report(
    report: dict[str, Any],
    report_index: int,
    name_prefix: str,
    source_reference: str,
    claim_eligible: bool,
) -> list[dict[str, Any]]:
    fixtures = [item for item in report.get("fixtures", []) or [] if isinstance(item, dict)]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fixture in fixtures:
        family = str(fixture.get("target_family", "") or "unknown")
        grouped[family].append(fixture)
    result: list[dict[str, Any]] = []
    for family in sorted(grouped):
        family_fixtures = grouped[family]
        ground_truth_pairs = _ground_truth_pairs(family, family_fixtures, report_index)
        ir_total = len(family_fixtures)
        ir_covered = sum(1 for fixture in family_fixtures if _ir_available(fixture))
        result.append(
            {
                "name": "%s_%s_%d" % (_slug(name_prefix), _slug(family), report_index),
                "target_family": family,
                "origin": DEFAULT_REPLAY_ORIGIN,
                "claim_eligible": bool(claim_eligible),
                "source_reference": source_reference or _report_reference(report, report_index),
                "function_count": len(family_fixtures),
                "ground_truth_pair_count": len(ground_truth_pairs),
                "ground_truth_pairs": ground_truth_pairs,
                "ir_evidence_function_count": ir_covered,
                "ir_total_function_count": ir_total,
                "cross_function_contract_count": _cross_function_contract_count(family_fixtures),
                "external_baselines": [],
                "analyst_audit_count": 0,
            }
        )
    return result


def _ground_truth_pairs(
    family: str,
    fixtures: list[dict[str, Any]],
    report_index: int,
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for fixture in fixtures:
        fixture_name = str(fixture.get("name", "") or "fixture")
        for item_index, item in enumerate(fixture.get("expectation_results", []) or []):
            if not isinstance(item, dict) or not bool(item.get("passed", False)):
                continue
            kind = str(item.get("kind", "") or "")
            value = str(item.get("value", "") or "")
            pair_id = "%s_%s_%d" % (_slug(fixture_name), _slug(kind), item_index)
            result.append(
                {
                    "id": pair_id,
                    "reference": "benchmark-replay://%d/%s/%s/%d" % (
                        report_index,
                        _slug(family),
                        _slug(fixture_name),
                        item_index,
                    ),
                    "expectation": "%s=%s" % (kind, value),
                }
            )
    return result


def _ir_available(fixture: dict[str, Any]) -> bool:
    summary = fixture.get("ir_evidence_summary", {})
    return isinstance(summary, dict) and bool(summary.get("available", False))


def _cross_function_contract_count(fixtures: list[dict[str, Any]]) -> int:
    return sum(int(fixture.get("cross_function_contract_count", 0) or 0) for fixture in fixtures)


def _report_reference(report: dict[str, Any], report_index: int) -> str:
    schema = str(report.get("schema", "") or "unknown")
    return "benchmark-report://%s/%d" % (schema, report_index)


def _slug(value: object) -> str:
    text = str(value or "").strip().lower()
    chars = [char if char.isalnum() else "_" for char in text]
    slug = "_".join(part for part in "".join(chars).split("_") if part)
    return slug or "unknown"

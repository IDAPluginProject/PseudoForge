from __future__ import annotations

import json
from pathlib import Path
from typing import Any


BASELINE_ADAPTER_REPORT_SCHEMA = "pseudoforge_baseline_adapter_report_v1"
QUALIFYING_STATUS = {"passed"}


def load_baseline_adapter_report(path: str | Path) -> dict[str, Any]:
    report_path = Path(path)
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("baseline adapter report file not found: %s" % report_path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid baseline adapter report JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("baseline adapter report root must be an object")
    schema = str(payload.get("schema", BASELINE_ADAPTER_REPORT_SCHEMA) or BASELINE_ADAPTER_REPORT_SCHEMA)
    if schema != BASELINE_ADAPTER_REPORT_SCHEMA:
        raise ValueError("unsupported baseline adapter report schema in %s: %s" % (report_path, schema))
    comparisons = payload.get("comparisons", [])
    if not isinstance(comparisons, list):
        raise ValueError("baseline adapter report comparisons must be a list in %s" % report_path)
    tool = _required_string(payload, "tool", report_path, "report")
    normalized = [_comparison(tool, item, report_path, index) for index, item in enumerate(comparisons)]
    return {
        "schema": BASELINE_ADAPTER_REPORT_SCHEMA,
        "source_path": str(report_path),
        "tool": tool,
        "comparisons": normalized,
        "summary": summarize_baseline_comparisons(normalized),
    }


def summarize_baseline_comparisons(comparisons: list[dict[str, Any]]) -> dict[str, Any]:
    qualified = [
        item
        for item in comparisons
        if str(item.get("status", "") or "") in QUALIFYING_STATUS
    ]
    return {
        "comparison_count": len(comparisons),
        "qualified_comparison_count": len(qualified),
        "qualified_tools": sorted(
            {
                str(item.get("tool", "") or "")
                for item in qualified
                if str(item.get("tool", "") or "")
            }
        ),
    }


def corpus_baseline_records_from_adapter_reports(reports: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "tool": str(item.get("tool", "") or ""),
            "reference": str(item.get("reference", "") or ""),
            "metric": str(item.get("metric", "") or ""),
            "pseudoforge_value": str(item.get("pseudoforge_value", "") or ""),
            "baseline_value": str(item.get("baseline_value", "") or ""),
            "status": str(item.get("status", "") or ""),
        }
        for report in reports
        for item in report.get("comparisons", []) or []
        if isinstance(item, dict)
    ]


def _comparison(tool: str, item: object, path: Path, index: int) -> dict[str, str]:
    if not isinstance(item, dict):
        raise ValueError("baseline adapter report comparisons[%d] must be an object in %s" % (index, path))
    return {
        "tool": tool,
        "reference": _required_string(item, "reference", path, index),
        "metric": _required_string(item, "metric", path, index),
        "pseudoforge_value": _required_string(item, "pseudoforge_value", path, index),
        "baseline_value": _required_string(item, "baseline_value", path, index),
        "status": _required_string(item, "status", path, index),
    }


def _required_string(payload: dict[str, Any], key: str, path: Path, index: int | str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("baseline adapter report %s.%s is required in %s" % (index, key, path))
    return value.strip()

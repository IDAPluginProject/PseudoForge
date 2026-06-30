from __future__ import annotations

import json
from pathlib import Path
from typing import Any


MULTI_IR_EVIDENCE_SCHEMA = "pseudoforge_multi_ir_evidence_v1"
QUALIFYING_STATUS = {"passed", "validated"}


def load_multi_ir_evidence(path: str | Path) -> dict[str, Any]:
    evidence_path = Path(path)
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("multi-IR evidence file not found: %s" % evidence_path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid multi-IR evidence JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("multi-IR evidence root must be an object")
    schema = str(payload.get("schema", MULTI_IR_EVIDENCE_SCHEMA) or MULTI_IR_EVIDENCE_SCHEMA)
    if schema != MULTI_IR_EVIDENCE_SCHEMA:
        raise ValueError("unsupported multi-IR evidence schema in %s: %s" % (evidence_path, schema))
    records = payload.get("records", [])
    if not isinstance(records, list):
        raise ValueError("multi-IR evidence records must be a list in %s" % evidence_path)
    normalized = [_record(item, evidence_path, index) for index, item in enumerate(records)]
    return {
        "schema": MULTI_IR_EVIDENCE_SCHEMA,
        "source_path": str(evidence_path),
        "records": normalized,
        "summary": summarize_multi_ir_records(normalized),
    }


def summarize_multi_ir_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    qualified = [
        item
        for item in records
        if str(item.get("status", "") or "") in QUALIFYING_STATUS
    ]
    views = sorted(
        {
            str(view)
            for item in qualified
            for view in item.get("views", []) or []
            if str(view)
        }
    )
    return {
        "record_count": len(records),
        "qualified_record_count": len(qualified),
        "qualified_views": views,
        "qualified_view_count": len(views),
    }


def corpus_records_from_multi_ir_evidence(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "function": str(item.get("function", "") or ""),
            "views": list(item.get("views", []) or []),
            "reference": str(item.get("reference", "") or ""),
            "status": str(item.get("status", "") or ""),
        }
        for item in evidence.get("records", []) or []
        if isinstance(item, dict)
    ]


def _record(item: object, path: Path, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("multi-IR evidence records[%d] must be an object in %s" % (index, path))
    return {
        "function": _required_string(item, "function", path, index),
        "views": _views(item.get("views"), path, index),
        "reference": _required_string(item, "reference", path, index),
        "status": _required_string(item, "status", path, index),
    }


def _views(value: object, path: Path, index: int) -> list[str]:
    if isinstance(value, list):
        result = sorted({str(item).strip() for item in value if str(item).strip()})
    else:
        result = sorted({item.strip() for item in str(value or "").replace(";", ",").split(",") if item.strip()})
    if not result:
        raise ValueError("multi-IR evidence records[%d].views must not be empty in %s" % (index, path))
    return result


def _required_string(payload: dict[str, Any], key: str, path: Path, index: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("multi-IR evidence records[%d].%s is required in %s" % (index, key, path))
    return value.strip()

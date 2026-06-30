from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REAL_REPLAY_TARGETS_SCHEMA = "pseudoforge_real_replay_targets_v1"
QUALIFYING_STATUS = {"passed", "validated"}


def load_real_replay_targets(path: str | Path) -> dict[str, Any]:
    target_path = Path(path)
    try:
        payload = json.loads(target_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("real replay targets file not found: %s" % target_path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid real replay targets JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("real replay targets root must be an object")
    schema = str(payload.get("schema", REAL_REPLAY_TARGETS_SCHEMA) or REAL_REPLAY_TARGETS_SCHEMA)
    if schema != REAL_REPLAY_TARGETS_SCHEMA:
        raise ValueError("unsupported real replay targets schema in %s: %s" % (target_path, schema))
    targets = payload.get("targets", [])
    if not isinstance(targets, list):
        raise ValueError("real replay targets must be a list in %s" % target_path)
    normalized = [_target(item, target_path, index) for index, item in enumerate(targets)]
    return {
        "schema": REAL_REPLAY_TARGETS_SCHEMA,
        "source_path": str(target_path),
        "targets": normalized,
        "summary": summarize_real_replay_targets(normalized),
    }


def summarize_real_replay_targets(targets: list[dict[str, Any]]) -> dict[str, Any]:
    qualified = [
        item
        for item in targets
        if str(item.get("status", "") or "") in QUALIFYING_STATUS
        and _int(item.get("function_count"), 0) > 0
    ]
    return {
        "target_count": len(targets),
        "qualified_target_count": len(qualified),
        "qualified_families": sorted(
            {
                str(item.get("family", "") or "")
                for item in qualified
                if str(item.get("family", "") or "")
            }
        ),
        "qualified_function_count": sum(_int(item.get("function_count"), 0) for item in qualified),
    }


def corpus_real_replay_records_from_targets(targets: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "family": str(item.get("family", "") or ""),
            "tool": str(item.get("tool", "") or ""),
            "reference": str(item.get("reference", "") or ""),
            "function_count": str(item.get("function_count", "") or ""),
            "status": str(item.get("status", "") or ""),
        }
        for item in targets.get("targets", []) or []
        if isinstance(item, dict)
    ]


def _target(item: object, path: Path, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("real replay targets[%d] must be an object in %s" % (index, path))
    return {
        "family": _required_string(item, "family", path, index),
        "tool": _required_string(item, "tool", path, index),
        "reference": _required_string(item, "reference", path, index),
        "function_count": _positive_int(item.get("function_count"), "function_count", path, index),
        "status": _required_string(item, "status", path, index),
    }


def _required_string(payload: dict[str, Any], key: str, path: Path, index: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("real replay targets[%d].%s is required in %s" % (index, key, path))
    return value.strip()


def _positive_int(value: object, field_name: str, path: Path, index: int) -> int:
    result = _int(value, -1)
    if result <= 0:
        raise ValueError("real replay targets[%d].%s must be positive in %s" % (index, field_name, path))
    return result


def _int(value: object, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SEMANTIC_GT_PACK_SCHEMA = "pseudoforge_semantic_ground_truth_pack_v1"
QUALIFYING_STATUS = {"passed", "validated"}


def load_semantic_ground_truth_pack(path: str | Path) -> dict[str, Any]:
    pack_path = Path(path)
    try:
        payload = json.loads(pack_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("semantic ground-truth pack file not found: %s" % pack_path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid semantic ground-truth pack JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("semantic ground-truth pack root must be an object")
    schema = str(payload.get("schema", SEMANTIC_GT_PACK_SCHEMA) or SEMANTIC_GT_PACK_SCHEMA)
    if schema != SEMANTIC_GT_PACK_SCHEMA:
        raise ValueError("unsupported semantic ground-truth pack schema in %s: %s" % (pack_path, schema))
    pairs = payload.get("pairs", [])
    if not isinstance(pairs, list):
        raise ValueError("semantic ground-truth pack pairs must be a list in %s" % pack_path)
    normalized = [_pair(item, pack_path, index) for index, item in enumerate(pairs)]
    return {
        "schema": SEMANTIC_GT_PACK_SCHEMA,
        "source_path": str(pack_path),
        "pairs": normalized,
        "summary": {
            "pair_count": len(normalized),
            "qualified_pair_count": sum(
                1 for item in normalized if str(item.get("status", "") or "") in QUALIFYING_STATUS
            ),
        },
    }


def corpus_semantic_records_from_pack(pack: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "id": str(item.get("id", "") or ""),
            "reference": str(item.get("reference", "") or ""),
            "function": str(item.get("function", "") or ""),
            "semantic_kind": str(item.get("semantic_kind", "") or ""),
            "oracle": str(item.get("oracle", "") or ""),
            "validation": str(item.get("validation", "") or ""),
            "status": str(item.get("status", "") or ""),
        }
        for item in pack.get("pairs", []) or []
        if isinstance(item, dict)
    ]


def _pair(item: object, path: Path, index: int) -> dict[str, str]:
    if not isinstance(item, dict):
        raise ValueError("semantic ground-truth pack pairs[%d] must be an object in %s" % (index, path))
    return {
        "id": _required_string(item, "id", path, index),
        "reference": _required_string(item, "reference", path, index),
        "source_path": _required_string(item, "source_path", path, index),
        "binary_path": _required_string(item, "binary_path", path, index),
        "function": _required_string(item, "function", path, index),
        "semantic_kind": _required_string(item, "semantic_kind", path, index),
        "oracle": _required_string(item, "oracle", path, index),
        "validation": _required_string(item, "validation", path, index),
        "status": _required_string(item, "status", path, index),
    }


def _required_string(payload: dict[str, Any], key: str, path: Path, index: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("semantic ground-truth pack pairs[%d].%s is required in %s" % (index, key, path))
    return value.strip()

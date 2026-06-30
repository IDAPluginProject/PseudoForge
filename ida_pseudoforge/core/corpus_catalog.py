from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ida_pseudoforge.core.corpus_evidence import CORPUS_MANIFEST_SCHEMA


PUBLIC_CORPUS_CATALOG_SCHEMA = "pseudoforge_public_corpus_catalog_v1"
CATALOG_ORIGIN = "public_corpus_catalog"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ALLOWED_ARTIFACT_URI_SCHEMES = {"file", "http", "https", "s3", "gs", "artifact"}


def load_public_corpus_catalog(path: str | Path) -> dict[str, Any]:
    catalog_path = Path(path)
    try:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("public corpus catalog file not found: %s" % catalog_path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid public corpus catalog JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("public corpus catalog root must be an object")
    schema = str(payload.get("schema", PUBLIC_CORPUS_CATALOG_SCHEMA) or PUBLIC_CORPUS_CATALOG_SCHEMA)
    if schema != PUBLIC_CORPUS_CATALOG_SCHEMA:
        raise ValueError("unsupported public corpus catalog schema in %s: %s" % (catalog_path, schema))
    artifacts = payload.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise ValueError("public corpus catalog artifacts must be a list in %s" % catalog_path)
    return {
        "schema": PUBLIC_CORPUS_CATALOG_SCHEMA,
        "source_path": str(catalog_path),
        "artifacts": [
            _artifact(item, catalog_path, index)
            for index, item in enumerate(artifacts)
        ],
    }


def corpus_manifest_from_public_catalog(catalog: dict[str, Any]) -> dict[str, Any]:
    artifacts = [item for item in catalog.get("artifacts", []) or [] if isinstance(item, dict)]
    return {
        "schema": CORPUS_MANIFEST_SCHEMA,
        "corpora": [_corpus_from_artifact(item) for item in artifacts],
    }


def _corpus_from_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": artifact["name"],
        "target_family": artifact["target_family"],
        "origin": CATALOG_ORIGIN,
        "claim_eligible": bool(artifact.get("claim_eligible", False)),
        "source_reference": artifact["source_reference"],
        "function_count": int(artifact.get("function_count", 0) or 0),
        "ground_truth_pair_count": 0,
        "ground_truth_pairs": [],
        "ir_evidence_function_count": 0,
        "ir_total_function_count": int(artifact.get("function_count", 0) or 0),
        "cross_function_contract_count": 0,
        "external_baselines": [],
        "analyst_audit_count": 0,
    }


def _artifact(item: object, path: Path, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("public corpus catalog artifacts[%d] must be an object in %s" % (index, path))
    claim_eligible = bool(item.get("claim_eligible", False))
    result = {
        "name": _required_string(item, "name", path, index),
        "target_family": _required_string(item, "target_family", path, index),
        "source_reference": _required_string(item, "source_reference", path, index),
        "artifact_uri": _string(item.get("artifact_uri")),
        "license": _string(item.get("license")),
        "sha256": _string(item.get("sha256")),
        "function_count": _nonnegative_int(item.get("function_count"), "function_count", path, index),
        "claim_eligible": claim_eligible,
    }
    if claim_eligible:
        _require_claim_field(result, "artifact_uri", path, index)
        _require_claim_field(result, "license", path, index)
        _require_claim_field(result, "sha256", path, index)
        _require_valid_artifact_uri(str(result["artifact_uri"]), path, index)
        _require_valid_sha256(str(result["sha256"]), path, index)
        if int(result["function_count"]) <= 0:
            raise ValueError("public corpus catalog artifacts[%d].function_count must be positive for claim evidence in %s" % (index, path))
    return result


def _require_claim_field(payload: dict[str, Any], key: str, path: Path, index: int) -> None:
    if not str(payload.get(key, "") or ""):
        raise ValueError("public corpus catalog artifacts[%d].%s is required for claim evidence in %s" % (index, key, path))


def _require_valid_sha256(value: str, path: Path, index: int) -> None:
    if not SHA256_RE.fullmatch(value or ""):
        raise ValueError("public corpus catalog artifacts[%d].sha256 must be a 64-character hex digest in %s" % (index, path))


def _require_valid_artifact_uri(value: str, path: Path, index: int) -> None:
    parsed = urlparse(value or "")
    if parsed.scheme not in ALLOWED_ARTIFACT_URI_SCHEMES:
        raise ValueError("public corpus catalog artifacts[%d].artifact_uri has unsupported scheme in %s" % (index, path))
    if parsed.scheme in {"http", "https", "s3", "gs"} and not parsed.netloc:
        raise ValueError("public corpus catalog artifacts[%d].artifact_uri must include a host in %s" % (index, path))
    if parsed.scheme in {"file", "artifact"} and not parsed.path:
        raise ValueError("public corpus catalog artifacts[%d].artifact_uri must include a path in %s" % (index, path))


def _required_string(payload: dict[str, Any], key: str, path: Path, index: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("public corpus catalog artifacts[%d].%s is required in %s" % (index, key, path))
    return value.strip()


def _string(value: object) -> str:
    return str(value or "").strip()


def _nonnegative_int(value: object, field_name: str, path: Path, index: int) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        raise ValueError("public corpus catalog artifacts[%d].%s must be an integer in %s" % (index, field_name, path))
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("public corpus catalog artifacts[%d].%s must be an integer in %s" % (index, field_name, path)) from exc
    if result < 0:
        raise ValueError("public corpus catalog artifacts[%d].%s must be non-negative in %s" % (index, field_name, path))
    return result

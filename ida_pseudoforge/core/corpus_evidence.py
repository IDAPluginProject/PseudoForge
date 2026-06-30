from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CORPUS_MANIFEST_SCHEMA = "pseudoforge_general_corpus_manifest_v1"
CORPUS_EVIDENCE_SCHEMA = "pseudoforge_general_corpus_evidence_v1"
SYNTHETIC_ORIGINS = {"synthetic", "unit_fixture", "toy"}


def load_corpus_evidence(paths: list[str | Path]) -> dict[str, Any]:
    manifests = [load_corpus_manifest(path) for path in paths]
    return summarize_corpus_manifests(manifests)


def load_corpus_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("corpus manifest file not found: %s" % manifest_path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid corpus manifest JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("corpus manifest root must be an object")
    schema = str(payload.get("schema", CORPUS_MANIFEST_SCHEMA) or CORPUS_MANIFEST_SCHEMA)
    if schema != CORPUS_MANIFEST_SCHEMA:
        raise ValueError("unsupported corpus manifest schema in %s: %s" % (manifest_path, schema))
    corpora = payload.get("corpora", [])
    if not isinstance(corpora, list):
        raise ValueError("corpus manifest corpora must be a list in %s" % manifest_path)
    return {
        "schema": CORPUS_MANIFEST_SCHEMA,
        "source_path": str(manifest_path),
        "corpora": [
            _normalize_corpus(item, manifest_path, index)
            for index, item in enumerate(corpora)
        ],
    }


def summarize_corpus_manifests(manifests: list[dict[str, Any]]) -> dict[str, Any]:
    corpora = [
        item
        for manifest in manifests
        for item in manifest.get("corpora", []) or []
        if isinstance(item, dict)
    ]
    claim_eligible = [item for item in corpora if _claim_eligible(item)]
    synthetic = [item for item in corpora if not _claim_eligible(item)]
    total_ir_functions = sum(_int(item.get("ir_total_function_count"), 0) for item in claim_eligible)
    covered_ir_functions = sum(_int(item.get("ir_evidence_function_count"), 0) for item in claim_eligible)
    ir_coverage = 0.0
    if total_ir_functions > 0:
        ir_coverage = covered_ir_functions / total_ir_functions
    external_baselines = sorted(
        {
            str(value)
            for item in claim_eligible
            for value in item.get("external_baselines", []) or []
            if str(value)
        }
    )
    qualified_external_baselines = sorted(
        {
            str(value.get("name", "") or "")
            for item in claim_eligible
            for value in item.get("qualified_external_baselines", []) or []
            if isinstance(value, dict) and str(value.get("name", "") or "")
        }
    )
    qualified_analyst_audits = sorted(
        {
            str(value.get("id", "") or value.get("reference", "") or "")
            for item in claim_eligible
            for value in item.get("analyst_audits", []) or []
            if isinstance(value, dict) and str(value.get("id", "") or value.get("reference", "") or "")
        }
    )
    return {
        "schema": CORPUS_EVIDENCE_SCHEMA,
        "manifest_count": len(manifests),
        "corpus_count": len(corpora),
        "real_corpus_count": len(claim_eligible),
        "synthetic_or_unqualified_corpus_count": len(synthetic),
        "real_corpus_function_count": sum(_int(item.get("function_count"), 0) for item in claim_eligible),
        "ground_truth_pair_count": sum(_int(item.get("ground_truth_pair_count"), 0) for item in claim_eligible),
        "qualified_ground_truth_pair_count": sum(
            len(item.get("ground_truth_pairs", []) or []) for item in claim_eligible
        ),
        "ir_evidence_function_count": covered_ir_functions,
        "ir_total_function_count": total_ir_functions,
        "ir_evidence_coverage": ir_coverage,
        "cross_function_contract_count": sum(
            _int(item.get("cross_function_contract_count"), 0) for item in claim_eligible
        ),
        "qualified_cross_function_contract_count": sum(
            len(item.get("cross_function_contracts", []) or []) for item in claim_eligible
        ),
        "external_baseline_count": len(external_baselines),
        "external_baselines": external_baselines,
        "qualified_external_baseline_count": len(qualified_external_baselines),
        "qualified_external_baselines": qualified_external_baselines,
        "analyst_audit_count": sum(_int(item.get("analyst_audit_count"), 0) for item in claim_eligible),
        "qualified_analyst_audit_count": len(qualified_analyst_audits),
        "qualified_analyst_audits": qualified_analyst_audits,
        "target_families": sorted(
            {
                str(item.get("target_family", "") or "")
                for item in claim_eligible
                if str(item.get("target_family", "") or "")
            }
        ),
        "manifests": [
            {
                "source_path": str(manifest.get("source_path", "") or ""),
                "corpus_count": len(manifest.get("corpora", []) or []),
            }
            for manifest in manifests
        ],
    }


def _normalize_corpus(item: object, path: Path, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("corpus manifest corpora[%d] must be an object in %s" % (index, path))
    name = _required_string(item, "name", path, index)
    target_family = _required_string(item, "target_family", path, index)
    origin = _required_string(item, "origin", path, index)
    external_baselines = item.get("external_baselines", [])
    if external_baselines is None:
        external_baselines = []
    if not isinstance(external_baselines, list):
        raise ValueError("corpus manifest corpora[%d].external_baselines must be a list in %s" % (index, path))
    qualified_external_baselines = _qualified_external_baselines(external_baselines, path, index)
    function_count = _nonnegative_int(item.get("function_count"), "function_count", path, index)
    ir_covered = _nonnegative_int(item.get("ir_evidence_function_count"), "ir_evidence_function_count", path, index)
    ir_total = _nonnegative_int(item.get("ir_total_function_count"), "ir_total_function_count", path, index)
    _check_count_bounds(function_count, ir_covered, ir_total, path, index)
    ground_truth_pairs = _qualified_objects(
        item.get("ground_truth_pairs", []),
        "ground_truth_pairs",
        ("id", "reference", "expectation"),
        path,
        index,
    )
    analyst_audits = _qualified_objects(
        item.get("analyst_audits", []),
        "analyst_audits",
        ("id", "reviewer", "reference"),
        path,
        index,
    )
    cross_function_contracts = _qualified_objects(
        item.get("cross_function_contracts", []),
        "cross_function_contracts",
        ("id", "reference", "source_function", "sink_function", "contract"),
        path,
        index,
    )
    return {
        "name": name,
        "target_family": target_family,
        "origin": origin,
        "claim_eligible": bool(item.get("claim_eligible", False)),
        "source_reference": _source_reference(item, path, index, origin),
        "function_count": function_count,
        "ground_truth_pair_count": _nonnegative_int(
            item.get("ground_truth_pair_count"),
            "ground_truth_pair_count",
            path,
            index,
        ),
        "ground_truth_pairs": ground_truth_pairs,
        "ir_evidence_function_count": ir_covered,
        "ir_total_function_count": ir_total,
        "cross_function_contract_count": _nonnegative_int(
            item.get("cross_function_contract_count"),
            "cross_function_contract_count",
            path,
            index,
        ),
        "cross_function_contracts": cross_function_contracts,
        "external_baselines": _external_baseline_names(external_baselines),
        "qualified_external_baselines": qualified_external_baselines,
        "analyst_audit_count": _nonnegative_int(
            item.get("analyst_audit_count"),
            "analyst_audit_count",
            path,
            index,
        ),
        "analyst_audits": analyst_audits,
    }


def _claim_eligible(item: dict[str, Any]) -> bool:
    if not bool(item.get("claim_eligible", False)):
        return False
    origin = str(item.get("origin", "") or "").lower()
    if origin in SYNTHETIC_ORIGINS:
        return False
    if not str(item.get("source_reference", "") or ""):
        return False
    return _int(item.get("function_count"), 0) > 0


def _source_reference(item: dict[str, Any], path: Path, index: int, origin: str) -> str:
    value = str(item.get("source_reference", "") or "").strip()
    if bool(item.get("claim_eligible", False)) and origin.lower() not in SYNTHETIC_ORIGINS and not value:
        raise ValueError(
            "corpus manifest corpora[%d].source_reference is required for claim-eligible real corpora in %s"
            % (index, path)
        )
    return value


def _check_count_bounds(function_count: int, ir_covered: int, ir_total: int, path: Path, index: int) -> None:
    if ir_covered > ir_total:
        raise ValueError(
            "corpus manifest corpora[%d].ir_evidence_function_count exceeds ir_total_function_count in %s"
            % (index, path)
        )
    if function_count > 0 and ir_total > function_count:
        raise ValueError(
            "corpus manifest corpora[%d].ir_total_function_count exceeds function_count in %s"
            % (index, path)
        )


def _external_baseline_names(values: list[object]) -> list[str]:
    names: set[str] = set()
    for value in values:
        if isinstance(value, dict):
            name = str(value.get("name", "") or "").strip()
            if name:
                names.add(name)
        else:
            name = str(value or "").strip()
            if name:
                names.add(name)
    return sorted(names)


def _qualified_external_baselines(values: list[object], path: Path, index: int) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for value_index, value in enumerate(values):
        if not isinstance(value, dict):
            continue
        result.append(
            _qualified_object(
                value,
                "external_baselines",
                ("name", "reference", "metric"),
                path,
                index,
                value_index,
            )
        )
    return result


def _qualified_objects(
    value: object,
    field_name: str,
    required_fields: tuple[str, ...],
    path: Path,
    index: int,
) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("corpus manifest corpora[%d].%s must be a list in %s" % (index, field_name, path))
    return [
        _qualified_object(item, field_name, required_fields, path, index, value_index)
        for value_index, item in enumerate(value)
    ]


def _qualified_object(
    value: object,
    field_name: str,
    required_fields: tuple[str, ...],
    path: Path,
    index: int,
    value_index: int,
) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(
            "corpus manifest corpora[%d].%s[%d] must be an object in %s"
            % (index, field_name, value_index, path)
        )
    result = {str(key): str(item).strip() for key, item in value.items() if str(item).strip()}
    for required in required_fields:
        if not result.get(required):
            raise ValueError(
                "corpus manifest corpora[%d].%s[%d].%s is required in %s"
                % (index, field_name, value_index, required, path)
            )
    return result


def _required_string(payload: dict[str, Any], key: str, path: Path, index: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("corpus manifest corpora[%d].%s is required in %s" % (index, key, path))
    return value.strip()


def _nonnegative_int(value: object, field_name: str, path: Path, index: int) -> int:
    if value is None or value == "":
        result = 0
    elif isinstance(value, bool):
        raise ValueError(
            "corpus manifest corpora[%d].%s must be an integer in %s"
            % (index, field_name, path)
        )
    else:
        try:
            result = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "corpus manifest corpora[%d].%s must be an integer in %s"
                % (index, field_name, path)
            ) from exc
    if result < 0:
        raise ValueError(
            "corpus manifest corpora[%d].%s must be non-negative in %s"
            % (index, field_name, path)
        )
    return result


def _int(value: object, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)

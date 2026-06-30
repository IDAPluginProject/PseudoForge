from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any


EXTERNAL_BASELINE_LEDGER_SCHEMA = "pseudoforge_external_baseline_ledger_v1"
ANALYST_AUDIT_LEDGER_SCHEMA = "pseudoforge_analyst_audit_ledger_v1"
CROSS_FUNCTION_CONTRACT_LEDGER_SCHEMA = "pseudoforge_cross_function_contract_ledger_v1"

QUALIFYING_BASELINE_STATUS = {"passed"}
QUALIFYING_AUDIT_STATUS = {"accepted", "accepted_with_notes"}
QUALIFYING_CONTRACT_STATUS = {"validated"}


def load_external_baseline_ledgers(paths: list[str | Path]) -> list[dict[str, Any]]:
    return [load_external_baseline_ledger(path) for path in paths]


def load_analyst_audit_ledgers(paths: list[str | Path]) -> list[dict[str, Any]]:
    return [load_analyst_audit_ledger(path) for path in paths]


def load_cross_function_contract_ledgers(paths: list[str | Path]) -> list[dict[str, Any]]:
    return [load_cross_function_contract_ledger(path) for path in paths]


def load_external_baseline_ledger(path: str | Path) -> dict[str, Any]:
    payload = _json_object(path, "external baseline ledger")
    schema = str(payload.get("schema", EXTERNAL_BASELINE_LEDGER_SCHEMA) or EXTERNAL_BASELINE_LEDGER_SCHEMA)
    if schema != EXTERNAL_BASELINE_LEDGER_SCHEMA:
        raise ValueError("unsupported external baseline ledger schema in %s: %s" % (path, schema))
    baselines = payload.get("baselines", [])
    if not isinstance(baselines, list):
        raise ValueError("external baseline ledger baselines must be a list in %s" % path)
    return {
        "schema": EXTERNAL_BASELINE_LEDGER_SCHEMA,
        "source_path": str(path),
        "baselines": [
            _baseline_entry(item, Path(path), index)
            for index, item in enumerate(baselines)
        ],
    }


def load_analyst_audit_ledger(path: str | Path) -> dict[str, Any]:
    payload = _json_object(path, "analyst audit ledger")
    schema = str(payload.get("schema", ANALYST_AUDIT_LEDGER_SCHEMA) or ANALYST_AUDIT_LEDGER_SCHEMA)
    if schema != ANALYST_AUDIT_LEDGER_SCHEMA:
        raise ValueError("unsupported analyst audit ledger schema in %s: %s" % (path, schema))
    audits = payload.get("audits", [])
    if not isinstance(audits, list):
        raise ValueError("analyst audit ledger audits must be a list in %s" % path)
    return {
        "schema": ANALYST_AUDIT_LEDGER_SCHEMA,
        "source_path": str(path),
        "audits": [
            _audit_entry(item, Path(path), index)
            for index, item in enumerate(audits)
        ],
    }


def load_cross_function_contract_ledger(path: str | Path) -> dict[str, Any]:
    payload = _json_object(path, "cross-function contract ledger")
    schema = str(payload.get("schema", CROSS_FUNCTION_CONTRACT_LEDGER_SCHEMA) or CROSS_FUNCTION_CONTRACT_LEDGER_SCHEMA)
    if schema != CROSS_FUNCTION_CONTRACT_LEDGER_SCHEMA:
        raise ValueError("unsupported cross-function contract ledger schema in %s: %s" % (path, schema))
    contracts = payload.get("contracts", [])
    if not isinstance(contracts, list):
        raise ValueError("cross-function contract ledger contracts must be a list in %s" % path)
    return {
        "schema": CROSS_FUNCTION_CONTRACT_LEDGER_SCHEMA,
        "source_path": str(path),
        "contracts": [
            _contract_entry(item, Path(path), index)
            for index, item in enumerate(contracts)
        ],
    }


def apply_evidence_ledgers(
    manifest: dict[str, Any],
    external_baseline_ledgers: list[dict[str, Any]] | None = None,
    analyst_audit_ledgers: list[dict[str, Any]] | None = None,
    cross_function_contract_ledgers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result = deepcopy(manifest)
    corpora = result.get("corpora", [])
    if not isinstance(corpora, list):
        raise ValueError("corpus manifest corpora must be a list")
    baseline_entries = [
        entry
        for ledger in external_baseline_ledgers or []
        for entry in ledger.get("baselines", []) or []
        if isinstance(entry, dict)
    ]
    audit_entries = [
        entry
        for ledger in analyst_audit_ledgers or []
        for entry in ledger.get("audits", []) or []
        if isinstance(entry, dict)
    ]
    contract_entries = [
        entry
        for ledger in cross_function_contract_ledgers or []
        for entry in ledger.get("contracts", []) or []
        if isinstance(entry, dict)
    ]
    for corpus in corpora:
        if not isinstance(corpus, dict):
            continue
        _attach_baselines(corpus, baseline_entries)
        _attach_audits(corpus, audit_entries)
        _attach_contracts(corpus, contract_entries)
    return result


def apply_evidence_ledgers_to_manifests(
    manifests: list[dict[str, Any]],
    external_baseline_ledgers: list[dict[str, Any]] | None = None,
    analyst_audit_ledgers: list[dict[str, Any]] | None = None,
    cross_function_contract_ledgers: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    return [
        apply_evidence_ledgers(
            manifest,
            external_baseline_ledgers,
            analyst_audit_ledgers,
            cross_function_contract_ledgers,
        )
        for manifest in manifests
    ]


def _attach_baselines(corpus: dict[str, Any], entries: list[dict[str, Any]]) -> None:
    matched = [
        _baseline_manifest_record(entry)
        for entry in entries
        if _same_corpus(corpus, entry)
        and str(entry.get("status", "") or "") in QUALIFYING_BASELINE_STATUS
    ]
    if not matched:
        return
    current = list(corpus.get("external_baselines", []) or [])
    current.extend(matched)
    corpus["external_baselines"] = _dedupe_records(current, ("name", "reference", "metric"))
    qualified = list(corpus.get("qualified_external_baselines", []) or [])
    qualified.extend(matched)
    corpus["qualified_external_baselines"] = _dedupe_records(qualified, ("name", "reference", "metric"))


def _attach_audits(corpus: dict[str, Any], entries: list[dict[str, Any]]) -> None:
    matched = [
        _audit_manifest_record(entry)
        for entry in entries
        if _same_corpus(corpus, entry)
        and str(entry.get("status", "") or "") in QUALIFYING_AUDIT_STATUS
    ]
    if not matched:
        return
    current = list(corpus.get("analyst_audits", []) or [])
    current.extend(matched)
    corpus["analyst_audits"] = _dedupe_records(current, ("id", "reviewer", "reference"))
    corpus["analyst_audit_count"] = len(corpus["analyst_audits"])


def _attach_contracts(corpus: dict[str, Any], entries: list[dict[str, Any]]) -> None:
    matched = [
        _contract_manifest_record(entry)
        for entry in entries
        if _same_corpus(corpus, entry)
        and str(entry.get("status", "") or "") in QUALIFYING_CONTRACT_STATUS
    ]
    if not matched:
        return
    current = list(corpus.get("cross_function_contracts", []) or [])
    current.extend(matched)
    corpus["cross_function_contracts"] = _dedupe_records(current, ("id", "reference", "contract"))
    corpus["cross_function_contract_count"] = len(corpus["cross_function_contracts"])


def _same_corpus(corpus: dict[str, Any], entry: dict[str, Any]) -> bool:
    return (
        str(corpus.get("name", "") or "") == str(entry.get("corpus_name", "") or "")
        and str(corpus.get("target_family", "") or "") == str(entry.get("target_family", "") or "")
    )


def _baseline_manifest_record(entry: dict[str, Any]) -> dict[str, str]:
    return {
        "name": str(entry.get("name", "") or ""),
        "reference": str(entry.get("reference", "") or ""),
        "metric": str(entry.get("metric", "") or ""),
    }


def _audit_manifest_record(entry: dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(entry.get("id", "") or ""),
        "reviewer": str(entry.get("reviewer", "") or ""),
        "reference": str(entry.get("reference", "") or ""),
    }


def _contract_manifest_record(entry: dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(entry.get("id", "") or ""),
        "reference": str(entry.get("reference", "") or ""),
        "source_function": str(entry.get("source_function", "") or ""),
        "sink_function": str(entry.get("sink_function", "") or ""),
        "contract": str(entry.get("contract", "") or ""),
    }


def _dedupe_records(values: list[object], key_fields: tuple[str, ...]) -> list[object]:
    seen: set[tuple[str, ...]] = set()
    result: list[object] = []
    for value in values:
        if isinstance(value, dict):
            key = tuple(str(value.get(field, "") or "") for field in key_fields)
        else:
            key = (str(value or ""),)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _baseline_entry(item: object, path: Path, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("external baseline ledger baselines[%d] must be an object in %s" % (index, path))
    status = _required_string(item, "status", path, index, "baselines")
    if status not in QUALIFYING_BASELINE_STATUS and status not in {"failed", "blocked", "degraded"}:
        raise ValueError("external baseline ledger baselines[%d].status is unsupported in %s" % (index, path))
    return {
        "name": _required_string(item, "name", path, index, "baselines"),
        "corpus_name": _required_string(item, "corpus_name", path, index, "baselines"),
        "target_family": _required_string(item, "target_family", path, index, "baselines"),
        "reference": _required_string(item, "reference", path, index, "baselines"),
        "metric": _required_string(item, "metric", path, index, "baselines"),
        "status": status,
    }


def _audit_entry(item: object, path: Path, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("analyst audit ledger audits[%d] must be an object in %s" % (index, path))
    status = _required_string(item, "status", path, index, "audits")
    if status not in QUALIFYING_AUDIT_STATUS and status not in {"rejected", "blocked"}:
        raise ValueError("analyst audit ledger audits[%d].status is unsupported in %s" % (index, path))
    return {
        "id": _required_string(item, "id", path, index, "audits"),
        "corpus_name": _required_string(item, "corpus_name", path, index, "audits"),
        "target_family": _required_string(item, "target_family", path, index, "audits"),
        "reviewer": _required_string(item, "reviewer", path, index, "audits"),
        "reference": _required_string(item, "reference", path, index, "audits"),
        "status": status,
    }


def _contract_entry(item: object, path: Path, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("cross-function contract ledger contracts[%d] must be an object in %s" % (index, path))
    status = _required_string(item, "status", path, index, "contracts")
    if status not in QUALIFYING_CONTRACT_STATUS and status not in {"rejected", "blocked"}:
        raise ValueError("cross-function contract ledger contracts[%d].status is unsupported in %s" % (index, path))
    return {
        "id": _required_string(item, "id", path, index, "contracts"),
        "corpus_name": _required_string(item, "corpus_name", path, index, "contracts"),
        "target_family": _required_string(item, "target_family", path, index, "contracts"),
        "reference": _required_string(item, "reference", path, index, "contracts"),
        "source_function": _required_string(item, "source_function", path, index, "contracts"),
        "sink_function": _required_string(item, "sink_function", path, index, "contracts"),
        "contract": _required_string(item, "contract", path, index, "contracts"),
        "status": status,
    }


def _json_object(path: str | Path, description: str) -> dict[str, Any]:
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("%s file not found: %s" % (description, target)) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid %s JSON at line %d column %d: %s"
            % (description, exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("%s root must be an object" % description)
    return payload


def _required_string(
    payload: dict[str, Any],
    key: str,
    path: Path,
    index: int,
    collection: str,
) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("%s[%d].%s is required in %s" % (collection, index, key, path))
    return value.strip()

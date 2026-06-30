from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from ida_pseudoforge.core.corpus_evidence import CORPUS_MANIFEST_SCHEMA


DEFAULT_IDA_BATCH_REPLAY_ORIGIN = "ida_batch_replay_summary"


def load_ida_batch_summaries(paths: list[str | Path]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for path in paths:
        source_path = Path(path)
        if source_path.is_dir():
            summaries.extend(_load_summary_path(item) for item in _summary_files(source_path))
            continue
        summaries.append(_load_summary_path(source_path))
    return summaries


def corpus_manifest_from_ida_batch_summaries(
    summaries: list[dict[str, Any]],
    name_prefix: str = "ida_batch_replay",
    source_reference: str = "",
    claim_eligible: bool = False,
    include_symbol_ground_truth: bool = False,
    include_contract_call_evidence: bool = False,
) -> dict[str, Any]:
    if claim_eligible and not str(source_reference or "").strip():
        raise ValueError("claim-eligible IDA batch replay requires --source-reference")
    if claim_eligible and not summaries:
        raise ValueError("claim-eligible IDA batch replay requires at least one summary")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for summary in summaries:
        if not isinstance(summary, dict):
            continue
        family = _target_family(summary)
        grouped[family].append(summary)
    if claim_eligible and "unknown" in grouped:
        raise ValueError("claim-eligible IDA batch replay requires known target families")
    if claim_eligible and sum(1 for summary in summaries if _ir_available(summary)) <= 0:
        raise ValueError("claim-eligible IDA batch replay requires nonzero IR evidence coverage")
    corpora: list[dict[str, Any]] = []
    for family in sorted(grouped):
        family_summaries = grouped[family]
        ground_truth_pairs = (
            _symbol_ground_truth_pairs(family_summaries, family, source_reference)
            if include_symbol_ground_truth
            else []
        )
        cross_function_contracts = (
            _contract_call_evidence(family_summaries, family, source_reference)
            if include_contract_call_evidence
            else []
        )
        real_replay_targets = _real_replay_targets(
            family_summaries,
            family,
            source_reference,
            claim_eligible=bool(claim_eligible),
        )
        corpora.append(
            {
                "name": "%s_%s_0" % (_slug(name_prefix), _slug(family)),
                "target_family": family,
                "origin": DEFAULT_IDA_BATCH_REPLAY_ORIGIN,
                "claim_eligible": bool(claim_eligible),
                "source_reference": source_reference or "ida-batch-replay://local",
                "function_count": len(family_summaries),
                "ground_truth_pair_count": len(ground_truth_pairs),
                "ground_truth_pairs": ground_truth_pairs,
                "ir_evidence_function_count": sum(1 for item in family_summaries if _ir_available(item)),
                "ir_total_function_count": len(family_summaries),
                "cross_function_contract_count": len(cross_function_contracts),
                "cross_function_contracts": cross_function_contracts,
                "external_baselines": [],
                "analyst_audit_count": 0,
                "real_replay_target_count": len(real_replay_targets),
                "real_replay_targets": real_replay_targets,
            }
        )
    return {
        "schema": CORPUS_MANIFEST_SCHEMA,
        "corpora": corpora,
    }


def _summary_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.ida-batch-summary.json"))


def _load_summary_path(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("IDA batch summary file not found: %s" % path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid IDA batch summary JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("IDA batch summary root must be an object: %s" % path)
    return payload


def _target_family(summary: dict[str, Any]) -> str:
    context = summary.get("target_context", {})
    if isinstance(context, dict):
        family = str(context.get("target_family", "") or "").strip()
        if family:
            return family
    family = str(summary.get("target_family", "") or "").strip()
    return family or "unknown"


def _ir_available(summary: dict[str, Any]) -> bool:
    ir_summary = summary.get("ir_evidence_summary", {})
    return isinstance(ir_summary, dict) and bool(ir_summary.get("available", False))


def _symbol_ground_truth_pairs(
    summaries: list[dict[str, Any]],
    family: str,
    source_reference: str,
) -> list[dict[str, str]]:
    pairs: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for summary in summaries:
        function = _stable_function_symbol(summary)
        if not function:
            continue
        ea = _function_ea(summary)
        fingerprint = _input_fingerprint(summary)
        key = (fingerprint, ea, function)
        if key in seen:
            continue
        seen.add(key)
        pairs.append(
            {
                "id": "ida-symbol-gt-%s-%s-%s" % (_slug(family), _slug(ea), _slug(function)[:72]),
                "reference": _summary_reference(source_reference, fingerprint, ea, function),
                "expectation": (
                    "IDA preserved symbol identity '%s' at %s for target family %s with Hex-Rays IR evidence."
                    % (function, ea, family)
                ),
            }
        )
    return pairs


def _contract_call_evidence(
    summaries: list[dict[str, Any]],
    family: str,
    source_reference: str,
) -> list[dict[str, str]]:
    contracts: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for summary in summaries:
        if not _ir_available(summary):
            continue
        source_function = _stable_function_symbol(summary)
        if not source_function:
            continue
        fingerprint = _input_fingerprint(summary)
        ea = _function_ea(summary)
        for sink_function in _matched_contract_symbols(summary):
            key = (fingerprint, ea, source_function, sink_function)
            if key in seen:
                continue
            seen.add(key)
            contracts.append(
                {
                    "id": "ida-contract-%s-%s-%s-%s"
                    % (_slug(family), _slug(ea), _slug(source_function)[:36], _slug(sink_function)[:36]),
                    "reference": _summary_reference(source_reference, fingerprint, ea, source_function),
                    "source_function": source_function,
                    "sink_function": sink_function,
                    "contract": (
                        "IDA Hex-Rays replay matched contract symbol '%s' in '%s' using active domain-pack evidence."
                        % (sink_function, source_function)
                    ),
                }
            )
    return contracts


def _matched_contract_symbols(summary: dict[str, Any]) -> list[str]:
    contract_summary = summary.get("contract_pack_summary", {})
    if not isinstance(contract_summary, dict):
        return []
    symbols = contract_summary.get("matched_symbols", [])
    if not isinstance(symbols, list):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for symbol in symbols:
        text = str(symbol or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _real_replay_targets(
    summaries: list[dict[str, Any]],
    family: str,
    source_reference: str,
    claim_eligible: bool,
) -> list[dict[str, Any]]:
    if not summaries:
        return []
    return [
        {
            "family": family,
            "tool": "ida_hexrays",
            "reference": "%s#ida-replay=%s" % (source_reference or "ida-batch-replay://local", _slug(family)),
            "function_count": len(summaries),
            "status": "passed" if claim_eligible else "blocked",
        }
    ]


def _stable_function_symbol(summary: dict[str, Any]) -> str:
    if not _ir_available(summary):
        return ""
    function = str(summary.get("function", "") or "").strip()
    if not function:
        return ""
    lowered = function.lower()
    blocked_prefixes = (
        "sub_",
        "j_sub_",
        "j__sub_",
        "nullsub_",
        "j_nullsub_",
        "loc_",
        "unknown",
    )
    if lowered.startswith(blocked_prefixes):
        return ""
    if not _function_ea(summary):
        return ""
    return function


def _function_ea(summary: dict[str, Any]) -> str:
    return str(summary.get("function_ea", "") or "").strip()


def _input_fingerprint(summary: dict[str, Any]) -> str:
    return str(summary.get("input_fingerprint", "") or "").strip() or "unknown-input"


def _summary_reference(
    source_reference: str,
    fingerprint: str,
    ea: str,
    function: str,
) -> str:
    prefix = source_reference or "ida-batch-replay://local"
    return "%s#sha256=%s&ea=%s&function=%s" % (
        prefix,
        fingerprint,
        ea,
        _slug(function),
    )


def _slug(value: object) -> str:
    text = str(value or "").strip().lower()
    chars = [char if char.isalnum() else "_" for char in text]
    slug = "_".join(part for part in "".join(chars).split("_") if part)
    return slug or "unknown"

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ida_pseudoforge.core.evidence_pack import CROSS_FUNCTION_CONTRACT_LEDGER_SCHEMA


DEFAULT_RESOURCE_PAIR_RULES: tuple[tuple[str, str, str], ...] = (
    (
        "memory_lifetime",
        r"(?:malloc|calloc|realloc|strdup|cmalloc|ccalloc|cstrdup|contextmalloc|straccumfinishrealloc|decimalnew|decimal_new|sqlite3_win32_utf8_to_unicode|sqlite3_str_new)",
        r"(?:free|cfree|xfree|sqlite3_free|sqlite3_str_free)",
    ),
    (
        "file_lifetime",
        r"(?:fopen|win32_fopen|sqlite3_fopen|output_file_open|curlx_win32_open)",
        r"(?:fclose|_close)",
    ),
    (
        "socket_lifetime",
        r"(?:^socket$)",
        r"(?:^closesocket$)",
    ),
    (
        "certificate_store_lifetime",
        r"(?:certopenstore)",
        r"(?:certclosestore)",
    ),
    (
        "sqlite_statement_lifetime",
        r"(?:sqlite3_prepare|intckprepare|preparestmt)",
        r"(?:sqlite3_finalize)",
    ),
    (
        "entry_lifetime",
        r"(?:entry_new)",
        r"(?:entry_free)",
    ),
)


def build_cross_function_contract_ledger(
    export_roots: list[str | Path],
    *,
    corpus_name: str,
    target_family: str,
    reference_prefix: str = "ida-dataflow-contract://local",
    max_contracts: int = 0,
) -> dict[str, Any]:
    if not str(corpus_name or "").strip():
        raise ValueError("corpus_name is required")
    if not str(target_family or "").strip():
        raise ValueError("target_family is required")
    rules = _compiled_rules(DEFAULT_RESOURCE_PAIR_RULES)
    contracts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for rename_map_path in _rename_map_paths(export_roots):
        payload = _json_object(rename_map_path, "rename map")
        function_name = str(payload.get("function_name", "") or rename_map_path.parent.name)
        function_ea = _function_ea(payload)
        fingerprint = str(payload.get("input_fingerprint", "") or "unknown-input")
        ir_evidence = payload.get("ir_evidence", {})
        if not isinstance(ir_evidence, dict) or not bool(ir_evidence.get("available", False)):
            continue
        use_defs = [item for item in ir_evidence.get("use_def_chains", []) or [] if isinstance(item, dict)]
        call_sites = [item for item in ir_evidence.get("call_site_signatures", []) or [] if isinstance(item, dict)]
        for chain in use_defs:
            variable = str(chain.get("variable", "") or "")
            if not variable:
                continue
            source_names = _source_names(chain, rules)
            if not source_names:
                continue
            for source_name in source_names:
                for sink_name, rule_id in _matching_sink_calls(call_sites, variable, source_name, rules):
                    key = (fingerprint, function_ea, source_name, sink_name)
                    if key in seen:
                        continue
                    seen.add(key)
                    contracts.append(
                        _contract_record(
                            corpus_name=corpus_name,
                            target_family=target_family,
                            reference_prefix=reference_prefix,
                            function_name=function_name,
                            function_ea=function_ea,
                            fingerprint=fingerprint,
                            variable=variable,
                            source_name=source_name,
                            sink_name=sink_name,
                            rule_id=rule_id,
                        )
                    )
                    if max_contracts > 0 and len(contracts) >= max_contracts:
                        return _ledger(contracts)
    return _ledger(contracts)


def _compiled_rules(rules: tuple[tuple[str, str, str], ...]) -> list[tuple[str, re.Pattern[str], re.Pattern[str]]]:
    return [
        (rule_id, re.compile(source, re.IGNORECASE), re.compile(sink, re.IGNORECASE))
        for rule_id, source, sink in rules
    ]


def _rename_map_paths(paths: list[str | Path]) -> list[Path]:
    results: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            results.extend(path.rglob("function.rename-map.json"))
        elif path.is_file():
            results.append(path)
    return sorted(results)


def _json_object(path: Path, description: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("%s file not found: %s" % (description, path)) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid %s JSON at line %d column %d: %s"
            % (description, exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("%s root must be an object: %s" % (description, path))
    return payload


def _function_ea(payload: dict[str, Any]) -> str:
    value = payload.get("function_ea", "")
    if isinstance(value, int):
        return "0x%X" % value
    return str(value or "").strip()


def _source_names(
    chain: dict[str, Any],
    rules: list[tuple[str, re.Pattern[str], re.Pattern[str]]],
) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for definition in chain.get("definitions", []) or []:
        name = _call_name_from_definition(str(definition or ""))
        if not name or name in seen:
            continue
        normalized = _normalize_call_name(name)
        if any(source_re.search(normalized) for _, source_re, _ in rules):
            result.append(name)
            seen.add(name)
    return result


def _matching_sink_calls(
    call_sites: list[dict[str, Any]],
    variable: str,
    source_name: str,
    rules: list[tuple[str, re.Pattern[str], re.Pattern[str]]],
) -> list[tuple[str, str]]:
    source_normalized = _normalize_call_name(source_name)
    result: list[tuple[str, str]] = []
    for call_site in call_sites:
        sink_name = str(call_site.get("call_name", "") or "")
        if not sink_name:
            continue
        arguments = [str(item) for item in call_site.get("argument_names", []) or []]
        if variable not in arguments:
            continue
        sink_normalized = _normalize_call_name(sink_name)
        for rule_id, source_re, sink_re in rules:
            if source_re.search(source_normalized) and sink_re.search(sink_normalized):
                result.append((sink_name, rule_id))
                break
    return result


def _call_name_from_definition(definition: str) -> str:
    parts = definition.split(":")
    return parts[-1].strip() if parts else ""


def _normalize_call_name(name: str) -> str:
    text = str(name or "").strip()
    while text.startswith("j_"):
        text = text[2:]
    while text.startswith("_"):
        text = text[1:]
    return text.lower()


def _contract_record(
    *,
    corpus_name: str,
    target_family: str,
    reference_prefix: str,
    function_name: str,
    function_ea: str,
    fingerprint: str,
    variable: str,
    source_name: str,
    sink_name: str,
    rule_id: str,
) -> dict[str, str]:
    slug = _slug("%s-%s-%s-%s" % (function_ea, source_name, sink_name, variable))
    reference = "%s/%s#sha256=%s&ea=%s&var=%s" % (
        reference_prefix.rstrip("/"),
        _slug(function_name),
        fingerprint,
        function_ea,
        _slug(variable),
    )
    return {
        "id": "ida-dataflow-contract-%s" % slug,
        "corpus_name": corpus_name,
        "target_family": target_family,
        "reference": reference,
        "source_function": source_name,
        "sink_function": sink_name,
        "contract": "%s result reaches %s through %s in %s" % (
            source_name,
            sink_name,
            variable,
            function_name,
        ),
        "proof": "IR use-def variable '%s' is defined by %s and consumed by %s." % (
            variable,
            source_name,
            sink_name,
        ),
        "rule": rule_id,
        "status": "validated",
    }


def _ledger(contracts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": CROSS_FUNCTION_CONTRACT_LEDGER_SCHEMA,
        "contracts": contracts,
    }


def _slug(value: object) -> str:
    text = str(value or "").strip().lower()
    chars = [char if char.isalnum() else "_" for char in text]
    return "_".join(part for part in "".join(chars).split("_") if part) or "unknown"

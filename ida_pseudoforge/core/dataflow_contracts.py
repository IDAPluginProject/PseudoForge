from __future__ import annotations

from typing import Any

from ida_pseudoforge.core.ir_evidence import ir_evidence_summary
from ida_pseudoforge.core.plan_schema import IrEvidence


DATAFLOW_CONTRACT_SCHEMA = "pseudoforge_dataflow_contracts_v1"


def dataflow_contracts_from_ir_evidence(
    function_name: str,
    ir_evidence: IrEvidence | dict[str, Any],
    source_calls: list[str],
    sink_calls: list[str],
    reference_prefix: str = "dataflow://local",
) -> dict[str, Any]:
    payload = _evidence_payload(ir_evidence)
    use_defs = [item for item in payload.get("use_def_chains", []) or [] if isinstance(item, dict)]
    call_sites = [item for item in payload.get("call_site_signatures", []) or [] if isinstance(item, dict)]
    contracts: list[dict[str, str]] = []
    for chain in use_defs:
        variable = str(chain.get("variable", "") or "")
        source = _definition_source(chain, source_calls)
        if not variable or not source:
            continue
        for sink in _sink_calls_using_variable(call_sites, variable, sink_calls):
            contract_id = "dataflow-%s-%s-%s" % (_slug(function_name), _slug(source), _slug(sink))
            contracts.append(
                {
                    "id": contract_id,
                    "reference": "%s/%s/%s-to-%s" % (reference_prefix, _slug(function_name), _slug(source), _slug(sink)),
                    "source_function": source,
                    "sink_function": sink,
                    "contract": "%s result reaches %s in %s" % (source, sink, function_name),
                    "proof": "IR use-def variable '%s' is defined by %s and consumed by %s." % (variable, source, sink),
                    "status": "validated",
                }
            )
    deduped = _dedupe_contracts(contracts)
    return {
        "schema": DATAFLOW_CONTRACT_SCHEMA,
        "function": function_name,
        "ir_evidence_summary": ir_evidence_summary(ir_evidence),
        "contract_count": len(deduped),
        "contracts": deduped,
    }


def _evidence_payload(ir_evidence: IrEvidence | dict[str, Any]) -> dict[str, Any]:
    if isinstance(ir_evidence, IrEvidence):
        return ir_evidence.to_dict()
    if isinstance(ir_evidence, dict):
        return dict(ir_evidence)
    to_dict = getattr(ir_evidence, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        if isinstance(payload, dict):
            return dict(payload)
    return {}


def _definition_source(chain: dict[str, Any], source_calls: list[str]) -> str:
    allowed = {str(item) for item in source_calls if str(item)}
    for definition in chain.get("definitions", []) or []:
        parts = str(definition or "").split(":")
        if parts:
            call = parts[-1]
            if call in allowed:
                return call
    return ""


def _sink_calls_using_variable(call_sites: list[dict[str, Any]], variable: str, sink_calls: list[str]) -> list[str]:
    allowed = {str(item) for item in sink_calls if str(item)}
    result: list[str] = []
    for call in call_sites:
        call_name = str(call.get("call_name", "") or "")
        if call_name not in allowed:
            continue
        arguments = [str(item) for item in call.get("argument_names", []) or []]
        if variable in arguments:
            result.append(call_name)
    return result


def _dedupe_contracts(contracts: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, str]] = []
    for contract in contracts:
        key = (
            contract.get("source_function", ""),
            contract.get("sink_function", ""),
            contract.get("reference", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(contract)
    return result


def _slug(value: object) -> str:
    text = str(value or "").strip().lower()
    chars = [char if char.isalnum() else "_" for char in text]
    slug = "_".join(part for part in "".join(chars).split("_") if part)
    return slug or "unknown"

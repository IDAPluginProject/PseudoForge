from __future__ import annotations

import re
from typing import Any

from ida_pseudoforge.core.plan_schema import (
    IrCallSiteSignature,
    IrEvidence,
    IrLocalTypeSnapshot,
    IrUseDefChain,
)


ZERO_LITERAL_PATTERN = r"(?:0(?:i64|I64|ll|LL|ull|ULL|u|U|l|L)?|NULL|nullptr)(?![A-Za-z0-9_])"


def text_only_ir_evidence() -> IrEvidence:
    return IrEvidence(
        adapter="text_only",
        source="pseudocode",
        available=False,
    )


def textual_flow_ir_evidence(pseudocode: str, lvars: list[Any], calls: list[str]) -> IrEvidence:
    call_sites = _call_site_signatures(pseudocode, calls)
    use_def_chains = _use_def_chains(pseudocode, calls)
    local_types = [
        IrLocalTypeSnapshot(
            name=str(getattr(item, "name", "") or ""),
            type_text=str(getattr(item, "type", "") or ""),
            source="pseudocode_declaration",
            confidence=0.65,
            evidence="declared local variable in pseudocode",
        )
        for item in lvars
        if str(getattr(item, "name", "") or "") and str(getattr(item, "type", "") or "")
    ]
    diagnostics = _return_check_diagnostics(pseudocode, calls)
    available = bool(call_sites or use_def_chains or local_types or diagnostics)
    return IrEvidence(
        adapter="textual_flow_v1",
        source="pseudocode",
        available=available,
        use_def_chains=use_def_chains,
        local_type_snapshots=local_types,
        call_site_signatures=call_sites,
        diagnostics=diagnostics,
    )


def ir_evidence_summary(evidence: IrEvidence | dict[str, Any] | None) -> dict[str, object]:
    payload = _evidence_payload(evidence)
    use_def_chains = _list_value(payload.get("use_def_chains"))
    value_ranges = _list_value(payload.get("value_ranges"))
    local_type_snapshots = _list_value(payload.get("local_type_snapshots"))
    constant_origins = _list_value(payload.get("constant_origins"))
    call_site_signatures = _list_value(payload.get("call_site_signatures"))
    diagnostics = _list_value(payload.get("diagnostics"))
    return {
        "schema": str(payload.get("schema", "pseudoforge_ir_evidence_v1") or "pseudoforge_ir_evidence_v1"),
        "adapter": str(payload.get("adapter", "text_only") or "text_only"),
        "source": str(payload.get("source", "pseudocode") or "pseudocode"),
        "available": bool(payload.get("available", False)),
        "use_def_chains": len(use_def_chains),
        "value_ranges": len(value_ranges),
        "local_type_snapshots": len(local_type_snapshots),
        "constant_origins": len(constant_origins),
        "call_site_signatures": len(call_site_signatures),
        "diagnostics": len(diagnostics),
    }


def _evidence_payload(evidence: IrEvidence | dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(evidence, IrEvidence):
        return evidence.to_dict()
    if isinstance(evidence, dict):
        return dict(evidence)
    to_dict = getattr(evidence, "to_dict", None)
    if callable(to_dict):
        try:
            payload = to_dict()
            if isinstance(payload, dict):
                return dict(payload)
        except Exception:
            pass
    return text_only_ir_evidence().to_dict()


def _list_value(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return []


def _call_site_signatures(pseudocode: str, calls: list[str]) -> list[IrCallSiteSignature]:
    result: list[IrCallSiteSignature] = []
    for call_name in _unique_calls(calls):
        for args in _call_arguments(pseudocode, call_name):
            result.append(
                IrCallSiteSignature(
                    call_name=call_name,
                    argument_names=args,
                    confidence=0.6,
                    evidence="textual call expression",
                )
            )
    return result


def _use_def_chains(pseudocode: str, calls: list[str]) -> list[IrUseDefChain]:
    lines = (pseudocode or "").splitlines()
    result: list[IrUseDefChain] = []
    for line_index, line in enumerate(lines):
        for call_name in _unique_calls(calls):
            pattern = r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*\(" % re.escape(call_name)
            match = re.search(pattern, line)
            if not match:
                continue
            variable = match.group("var")
            uses = [
                "line:%d" % (index + 1)
                for index, candidate in enumerate(lines[line_index + 1 :], start=line_index + 1)
                if re.search(r"\b%s\b" % re.escape(variable), candidate)
            ]
            result.append(
                IrUseDefChain(
                    variable=variable,
                    definitions=["line:%d:%s" % (line_index + 1, call_name)],
                    uses=uses[:8],
                    confidence=0.55,
                    evidence="textual assignment from call",
                )
            )
    return result


def _return_check_diagnostics(pseudocode: str, calls: list[str]) -> list[str]:
    diagnostics: list[str] = []
    lines = (pseudocode or "").splitlines()
    for line_index, line in enumerate(lines):
        for call_name in _unique_calls(calls):
            pattern = r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*\(" % re.escape(call_name)
            match = re.search(pattern, line)
            if not match:
                continue
            variable = match.group("var")
            window = "\n".join(lines[line_index + 1 : line_index + 5])
            polarity = _return_check_polarity(variable, window)
            if polarity:
                diagnostics.append("return_check:%s:%s:%s" % (call_name, variable, polarity))
    return sorted(set(diagnostics))


def _return_check_polarity(variable: str, text: str) -> str:
    escaped = re.escape(variable)
    if re.search(r"\b%s\s*!=\s*%s" % (escaped, ZERO_LITERAL_PATTERN), text):
        return "nonzero_success"
    if re.search(r"\b%s\s*==\s*%s" % (escaped, ZERO_LITERAL_PATTERN), text):
        return "zero_or_null_failure"
    if re.search(r"!\s*%s\b" % escaped, text):
        return "false_failure"
    if re.search(r"\b%s\s*<\s*0" % escaped, text):
        return "negative_failure"
    if re.search(r"\b%s\s*>=\s*0" % escaped, text):
        return "nonnegative_success"
    return ""


def _call_arguments(pseudocode: str, call_name: str) -> list[list[str]]:
    pattern = r"\b%s\s*\((?P<args>[^;\n()]*(?:\([^;\n()]*\)[^;\n()]*)*)\)" % re.escape(call_name)
    return [
        _split_arguments(match.group("args"))
        for match in re.finditer(pattern, pseudocode or "")
    ]


def _split_arguments(text: str) -> list[str]:
    result: list[str] = []
    current: list[str] = []
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")" and depth > 0:
            depth -= 1
        if char == "," and depth == 0:
            result.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        result.append(tail)
    return result


def _unique_calls(calls: list[str]) -> list[str]:
    return sorted({str(item) for item in calls if str(item)})

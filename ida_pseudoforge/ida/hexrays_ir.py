from __future__ import annotations

from typing import Any

from ida_pseudoforge.core.ir_evidence import textual_flow_ir_evidence
from ida_pseudoforge.core.plan_schema import (
    FunctionCapture,
    IrCallSiteSignature,
    IrEvidence,
    IrLocalTypeSnapshot,
    IrUseDefChain,
    LocalVariable,
)


def hexrays_cfunc_ir_evidence(cfunc: Any, capture: FunctionCapture | None = None) -> IrEvidence:
    pseudocode = str(getattr(capture, "pseudocode", "") or "") if capture is not None else ""
    if not pseudocode:
        pseudocode = _cfunc_text(cfunc)

    lvars = list(getattr(capture, "lvars", []) or []) if capture is not None else []
    local_types = _local_type_snapshots(cfunc)
    if not lvars:
        lvars = [
            LocalVariable(name=item.name, type=item.type_text)
            for item in local_types
            if item.name
        ]

    calls = list(getattr(capture, "calls", []) or []) if capture is not None else []
    if not calls:
        calls = _explicit_call_names(cfunc)

    text_evidence = textual_flow_ir_evidence(pseudocode, lvars, calls)
    call_sites = _explicit_call_site_signatures(cfunc)
    if not call_sites:
        call_sites = list(text_evidence.call_site_signatures)

    use_def_chains = _explicit_use_def_chains(cfunc)
    if not use_def_chains:
        use_def_chains = list(text_evidence.use_def_chains)

    local_types = _merge_local_types(local_types, list(text_evidence.local_type_snapshots))
    semantic_diagnostics = list(text_evidence.diagnostics)
    diagnostics = sorted(
        set(
            semantic_diagnostics
            + _adapter_diagnostics(cfunc, local_types, call_sites, use_def_chains, pseudocode)
        )
    )
    available = bool(local_types or call_sites or use_def_chains or semantic_diagnostics)
    return IrEvidence(
        adapter="hexrays_cfunc_v1",
        source="hexrays_cfunc",
        available=available,
        use_def_chains=use_def_chains,
        local_type_snapshots=local_types,
        call_site_signatures=call_sites,
        diagnostics=diagnostics,
    )


def _local_type_snapshots(cfunc: Any) -> list[IrLocalTypeSnapshot]:
    result: list[IrLocalTypeSnapshot] = []
    for index, lvar in enumerate(_safe_list(_read_member(cfunc, "lvars"))):
        name = str(_read_member(lvar, "name") or "")
        if not name:
            continue
        type_text = _lvar_type_text(lvar)
        if not type_text:
            continue
        source = "hexrays_lvar_arg" if _bool_member(lvar, "is_arg_var") else "hexrays_lvar_local"
        result.append(
            IrLocalTypeSnapshot(
                name=name,
                type_text=type_text,
                source=source,
                confidence=0.9,
                evidence="Hex-Rays cfunc.lvars[%d]" % index,
            )
        )
    return result


def _lvar_type_text(lvar: Any) -> str:
    for attr in ("type", "tif"):
        value = _read_member(lvar, attr)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _explicit_call_site_signatures(cfunc: Any) -> list[IrCallSiteSignature]:
    result: list[IrCallSiteSignature] = []
    for item in _safe_list(_read_member(cfunc, "call_site_signatures")):
        call_name = _field_text(item, "call_name", "name", "callee", "function")
        if not call_name:
            continue
        result.append(
            IrCallSiteSignature(
                call_name=call_name,
                return_type=_field_text(item, "return_type"),
                argument_types=_field_text_list(item, "argument_types", "arg_types"),
                argument_names=_field_text_list(item, "argument_names", "args", "arg_names"),
                confidence=_field_float(item, "confidence", default=0.85),
                evidence=_field_text(item, "evidence") or "Hex-Rays call site",
            )
        )
    return result


def _explicit_use_def_chains(cfunc: Any) -> list[IrUseDefChain]:
    result: list[IrUseDefChain] = []
    for item in _safe_list(_read_member(cfunc, "use_def_chains")):
        variable = _field_text(item, "variable", "name")
        if not variable:
            continue
        result.append(
            IrUseDefChain(
                variable=variable,
                definitions=_field_text_list(item, "definitions", "defs"),
                uses=_field_text_list(item, "uses"),
                confidence=_field_float(item, "confidence", default=0.82),
                evidence=_field_text(item, "evidence") or "Hex-Rays use-def chain",
            )
        )
    return result


def _explicit_call_names(cfunc: Any) -> list[str]:
    names: list[str] = []
    for item in _safe_list(_read_member(cfunc, "calls")):
        if isinstance(item, str):
            text = item.strip()
        else:
            text = _field_text(item, "call_name", "name", "callee", "function")
        if text:
            names.append(text)
    for item in _explicit_call_site_signatures(cfunc):
        if item.call_name:
            names.append(item.call_name)
    return sorted(set(names))


def _merge_local_types(
    primary: list[IrLocalTypeSnapshot],
    fallback: list[IrLocalTypeSnapshot],
) -> list[IrLocalTypeSnapshot]:
    result: list[IrLocalTypeSnapshot] = []
    seen: set[str] = set()
    for item in primary + fallback:
        key = "%s\x00%s" % (item.name, item.type_text)
        if not item.name or key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _adapter_diagnostics(
    cfunc: Any,
    local_types: list[IrLocalTypeSnapshot],
    call_sites: list[IrCallSiteSignature],
    use_def_chains: list[IrUseDefChain],
    pseudocode: str,
) -> list[str]:
    diagnostics: list[str] = []
    if cfunc is not None:
        diagnostics.append("hexrays_cfunc:present")
    if local_types:
        diagnostics.append("hexrays_cfunc:lvars:%d" % len(local_types))
    if call_sites:
        diagnostics.append("hexrays_cfunc:call_sites:%d" % len(call_sites))
    if use_def_chains:
        diagnostics.append("hexrays_cfunc:use_def:%d" % len(use_def_chains))
    if pseudocode:
        diagnostics.append("hexrays_cfunc:pseudocode")
    return diagnostics


def _cfunc_text(cfunc: Any) -> str:
    lines: list[str] = []
    try:
        pseudocode = cfunc.get_pseudocode()
    except Exception:
        pseudocode = []
    for line in _safe_list(pseudocode):
        raw = _read_member(line, "line")
        if raw is None:
            raw = line
        lines.append(str(raw))
    return "\n".join(lines)


def _read_member(owner: Any, member: str) -> Any:
    if owner is None:
        return None
    if isinstance(owner, dict):
        return owner.get(member)
    try:
        value = getattr(owner, member, None)
    except Exception:
        return None
    if not callable(value):
        return value
    try:
        return value()
    except Exception:
        return None


def _field_text(owner: Any, *members: str) -> str:
    for member in members:
        value = _read_member(owner, member)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _field_text_list(owner: Any, *members: str) -> list[str]:
    for member in members:
        value = _read_member(owner, member)
        items = _safe_list(value)
        result = [str(item).strip() for item in items if str(item).strip()]
        if result:
            return result
    return []


def _field_float(owner: Any, member: str, *, default: float) -> float:
    value = _read_member(owner, member)
    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def _bool_member(owner: Any, member: str) -> bool:
    try:
        return bool(_read_member(owner, member))
    except Exception:
        return False


def _safe_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    try:
        return list(value)
    except Exception:
        return []

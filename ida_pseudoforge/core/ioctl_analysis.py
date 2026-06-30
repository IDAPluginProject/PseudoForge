from __future__ import annotations

from ida_pseudoforge.core.buffer_contracts import (
    render_buffer_struct_header,
    render_case_context_report,
)
from ida_pseudoforge.core.ioctl import decode_ioctl_code, format_ctl_code
from ida_pseudoforge.core.plan_schema import (
    BufferContract,
    BufferSizeConstraint,
    CleanPlan,
    CommandBufferContract,
    FieldAccess,
    FieldConstraint,
    FunctionCapture,
    HelperContractEdge,
)


def render_ioctl_deep_analysis_report(
    capture: FunctionCapture,
    plan: CleanPlan,
    command_value: int,
) -> str:
    contracts = [
        contract
        for contract in plan.buffer_contracts
        if contract.command_value == command_value and contract.dispatcher_kind == "ioctl"
    ]
    decoded = decode_ioctl_code(command_value)
    context_report = render_case_context_report(capture, plan, command_value)
    lines = [
        "# PseudoForge IOCTL Deep Analysis",
        "",
        "- Function: `%s`" % (capture.name or "function"),
        "- EA: `0x%X`" % capture.ea,
        "- IOCTL: `0x%08X`" % (command_value & 0xFFFFFFFF),
    ]
    if decoded is None:
        lines.append("- Decode: not a Windows IOCTL-shaped value")
    else:
        lines.extend(
            [
                "- Decode: `%s`" % format_ctl_code(command_value),
                "- Method: `%s`" % decoded.method_name,
                "- Access: `%s`" % decoded.access_name,
                "- Device type: `0x%X`" % decoded.device_type,
                "- IOCTL function: `0x%X`" % decoded.function,
            ]
        )
    lines.extend(
        [
            "- IOCTL contracts: `%d`" % len(contracts),
            "",
        ]
    )

    lines.extend(_render_transfer_model(decoded, contracts))
    lines.extend(_render_schema_hypotheses(contracts))
    lines.extend(_render_meaningful_path_requirements(contracts))
    lines.extend(_render_helper_propagation(contracts))
    if context_report:
        lines.append("# Selected Case Context")
        lines.append("")
        lines.append(_strip_heading(context_report.rstrip(), "# Selected Case Context").rstrip())
        lines.append("")
    lines.append("# C++ IOCTL Struct Sketch")
    lines.append("")
    lines.append(render_buffer_struct_header(capture, contracts).rstrip())
    lines.append("")
    return "\n".join(lines)


def _render_transfer_model(
    decoded: object | None,
    contracts: list[CommandBufferContract],
) -> list[str]:
    lines = ["# IOCTL Transfer Model", ""]
    if decoded is None:
        lines.append("- Transfer model unavailable because the selected value did not decode as CTL_CODE.")
        lines.append("")
        return lines
    method_name = str(getattr(decoded, "method_name", "") or "")
    if method_name == "METHOD_BUFFERED":
        lines.append(
            "- METHOD_BUFFERED uses `AssociatedIrp.SystemBuffer`; input and output can share one structure."
        )
    elif method_name in {"METHOD_IN_DIRECT", "METHOD_OUT_DIRECT"}:
        lines.append(
            "- Direct I/O uses the system buffer for input/control data and an MDL-backed user buffer for transfer data."
        )
    elif method_name == "METHOD_NEITHER":
        lines.append(
            "- METHOD_NEITHER exposes user pointers directly; pointer probing and capture evidence should be reviewed."
        )
    else:
        lines.append("- Transfer method is unknown; review recovered buffers manually.")
    if not contracts:
        lines.append("- No buffer contract was recovered for this IOCTL case.")
    lines.append("")
    return lines


def _render_schema_hypotheses(contracts: list[CommandBufferContract]) -> list[str]:
    lines = ["# Input And Output Structure Hypotheses", ""]
    if not contracts:
        lines.append("No IOCTL buffer structures were inferred for this case.")
        lines.append("")
        return lines
    for contract in contracts:
        title = contract.command_name or ("0x%X" % contract.command_value)
        lines.append("## %s" % title)
        lines.append("")
        if not contract.buffers:
            lines.append("- No concrete input/output buffer root was recovered.")
            lines.append("")
            continue
        for buffer in contract.buffers:
            direction = _direction_text(buffer.role)
            accesses = _all_field_accesses(contract, buffer)
            constraints = _all_field_constraints(contract, buffer)
            sizes = _all_size_constraints(contract, buffer)
            lines.extend(
                [
                    "- `%s`: `%s` buffer `%s`" % (
                        buffer.structure_name,
                        direction,
                        buffer.variable,
                    ),
                    "  - source: `%s`" % (buffer.source or "unknown"),
                    "  - length: `%s`" % (buffer.length_variable or "unknown"),
                    "  - field accesses: `%d`" % len(accesses),
                    "  - field predicates: `%d`" % len(constraints),
                    "  - size predicates: `%d`" % len(sizes),
                ]
            )
        lines.append("")
    return lines


def _render_meaningful_path_requirements(contracts: list[CommandBufferContract]) -> list[str]:
    lines = ["# Meaningful Path Requirements", ""]
    if not contracts:
        lines.append("No rejection guard-derived requirements were recovered.")
        lines.append("")
        return lines

    size_rows: list[str] = []
    field_rows: list[str] = []
    for contract in contracts:
        for buffer in contract.buffers:
            for item in _all_size_constraints(contract, buffer):
                row = _format_size_requirement(item)
                if row:
                    size_rows.append(row)
            for item in _all_field_constraints(contract, buffer):
                row = _format_field_requirement(buffer, item)
                if row:
                    field_rows.append(row)

    size_rows = _dedupe(size_rows)
    field_rows = _dedupe(field_rows)
    if size_rows:
        lines.append("Length requirements:")
        lines.append("")
        for row in size_rows:
            lines.append("- %s" % row)
        lines.append("")
    else:
        lines.append("Length requirements: none recovered from local rejection guards.")
        lines.append("")
    if field_rows:
        lines.append("Field requirements:")
        lines.append("")
        for row in field_rows:
            lines.append("- %s" % row)
        lines.append("")
    else:
        lines.append("Field requirements: none recovered from local rejection guards.")
        lines.append("")
    lines.append(
        "These are necessary local predicates derived from observed error branches, not a full path satisfiability proof."
    )
    lines.append("")
    return lines


def _render_helper_propagation(contracts: list[CommandBufferContract]) -> list[str]:
    lines = ["# Helper Propagation", ""]
    edges = [edge for contract in contracts for edge in _iter_helper_edges(contract.helper_edges)]
    if not edges:
        lines.append("No helper buffer propagation was recovered for this case.")
        lines.append("")
        return lines
    for edge in edges:
        status = "resolved" if edge.resolved else "unresolved"
        lines.append(
            "- `%s(%s)`: `%s`, buffers=%s"
            % (
                edge.callee,
                ", ".join(edge.arguments),
                status,
                ", ".join(edge.passed_buffers) or "none",
            )
        )
        for warning in edge.warnings:
            lines.append("  - warning: %s" % warning)
    lines.append("")
    return lines


def _all_size_constraints(
    contract: CommandBufferContract,
    buffer: BufferContract,
) -> list[BufferSizeConstraint]:
    result = list(buffer.size_constraints)
    for edge in _iter_helper_edges(contract.helper_edges):
        for item in edge.propagated_size_constraints:
            if item.buffer == buffer.variable:
                result.append(item)
    return result


def _all_field_accesses(
    contract: CommandBufferContract,
    buffer: BufferContract,
) -> list[FieldAccess]:
    result = list(buffer.field_accesses)
    for edge in _iter_helper_edges(contract.helper_edges):
        for item in edge.propagated_field_accesses:
            if item.buffer == buffer.variable:
                result.append(item)
    return result


def _all_field_constraints(
    contract: CommandBufferContract,
    buffer: BufferContract,
) -> list[FieldConstraint]:
    result = list(buffer.field_constraints)
    for edge in _iter_helper_edges(contract.helper_edges):
        for item in edge.propagated_field_constraints:
            if item.buffer == buffer.variable:
                result.append(item)
    return result


def _iter_helper_edges(edges: list[HelperContractEdge]) -> list[HelperContractEdge]:
    result: list[HelperContractEdge] = []
    for edge in edges:
        result.append(edge)
        result.extend(_iter_helper_edges(edge.nested_edges))
    return result


def _format_size_requirement(item: BufferSizeConstraint) -> str:
    relation = item.valid_relation
    value = item.valid_value
    if not relation or not value:
        return ""
    return "`%s %s %s` from `%s` [%s]" % (
        item.length or item.buffer or "length",
        relation,
        value,
        item.evidence,
        item.source,
    )


def _format_field_requirement(buffer: BufferContract, item: FieldConstraint) -> str:
    relation = item.valid_relation
    value = item.valid_value
    if not relation or not value:
        return ""
    field_ref = "%s.%s" % (buffer.structure_name, item.field)
    if relation.startswith("mask_"):
        op = relation[len("mask_"):]
        expression = "(%s & %s) %s %s" % (
            field_ref,
            item.mask or "mask",
            op,
            value,
        )
    else:
        expression = "%s %s %s" % (field_ref, relation, value)
    return "`%s` from `%s` [%s]" % (expression, item.evidence, item.source)


def _direction_text(role: str) -> str:
    if role == "input":
        return "input"
    if role == "output":
        return "output"
    if role == "inout":
        return "input/output"
    return role or "unknown"


def _strip_heading(text: str, heading: str) -> str:
    stripped = text.strip()
    if stripped.startswith(heading):
        return stripped[len(heading):].lstrip()
    return text


def _dedupe(rows: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not row or row in seen:
            continue
        seen.add(row)
        result.append(row)
    return result

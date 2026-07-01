from __future__ import annotations

from ida_pseudoforge.core.buffer_contracts import (
    render_buffer_struct_header,
    render_case_context_report,
)
from ida_pseudoforge.core.helper_depth import DEFAULT_HELPER_DEPTH, normalize_helper_depth
from ida_pseudoforge.core.helper_edge_audit import (
    helper_edge_audit_records,
    helper_edge_class_counts,
    helper_path_family_records,
    unresolved_helper_edge_records,
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
from ida_pseudoforge.profiles.loader import (
    get_process_information_class_name,
    get_system_information_class_name,
    get_thread_information_class_name,
)


def render_ioctl_deep_analysis_report(
    capture: FunctionCapture,
    plan: CleanPlan,
    command_value: int,
    helper_depth: int = DEFAULT_HELPER_DEPTH,
) -> str:
    return render_selector_path_analysis_report(capture, plan, command_value, helper_depth=helper_depth)


def render_selector_path_analysis_report(
    capture: FunctionCapture,
    plan: CleanPlan,
    command_value: int,
    helper_depth: int = DEFAULT_HELPER_DEPTH,
) -> str:
    contracts = [
        contract
        for contract in plan.buffer_contracts
        if contract.command_value == command_value
    ]
    decoded = decode_ioctl_code(command_value)
    context_report = render_case_context_report(capture, plan, command_value)
    selector_kind = _selector_kind(capture, contracts)
    lines = [
        "# PseudoForge Selector Path Analysis",
        "",
        "- Function: `%s`" % (capture.name or "function"),
        "- EA: `0x%X`" % capture.ea,
        "- Selector: `0x%X` (`%d`)" % (command_value, command_value),
        "- Selector domain: `%s`" % _selector_domain_label(selector_kind),
        "- Helper depth: `%d`" % normalize_helper_depth(helper_depth),
    ]
    selector_name = _selector_name(selector_kind, command_value, contracts)
    if selector_name:
        lines.append("- Selector name: `%s`" % selector_name)
    if selector_kind == "ioctl" and decoded is not None:
        lines.extend(
            [
                "- CTL_CODE decode: `%s`" % format_ctl_code(command_value),
                "- IOCTL method: `%s`" % decoded.method_name,
                "- IOCTL access: `%s`" % decoded.access_name,
                "- IOCTL device type: `0x%X`" % decoded.device_type,
                "- IOCTL function: `0x%X`" % decoded.function,
            ]
        )
    elif selector_kind == "ioctl":
        lines.append("- CTL_CODE decode: not a Windows IOCTL-shaped value")
    lines.extend(
        [
            "- Matching contracts: `%d`" % len(contracts),
            "",
        ]
    )

    lines.extend(_render_selector_model(selector_kind, decoded, contracts))
    lines.extend(_render_schema_hypotheses(contracts))
    lines.extend(_render_meaningful_path_requirements(contracts))
    lines.extend(_render_helper_propagation(contracts))
    lines.extend(_render_helper_edge_audit(contracts))
    lines.extend(_render_helper_path_families(contracts))
    if context_report:
        lines.append("# Selected Case Context")
        lines.append("")
        lines.append(_strip_heading(context_report.rstrip(), "# Selected Case Context").rstrip())
        lines.append("")
    lines.append("# C++ Selector Struct Sketch")
    lines.append("")
    lines.append(render_buffer_struct_header(capture, contracts).rstrip())
    lines.append("")
    return "\n".join(lines)


def _render_selector_model(
    selector_kind: str,
    decoded: object | None,
    contracts: list[CommandBufferContract],
) -> list[str]:
    lines = ["# Selector Data Model", ""]
    if selector_kind == "ntset_system":
        lines.append(
            "- `NtSetSystemInformation` uses `SystemInformationClass` as the selector and "
            "`SystemInformation`/`SystemInformationLength` as the focused input buffer contract."
        )
        lines.append(
            "- Output evidence is reported only when the selected case writes back into `SystemInformation`."
        )
        if not contracts:
            lines.append("- No buffer contract was recovered for this SystemInformationClass case.")
        lines.append("")
        return lines
    if selector_kind == "ntset_process":
        lines.append(
            "- `NtSetInformationProcess` uses `PROCESSINFOCLASS` as the selector and "
            "`ProcessInformation`/`ProcessInformationLength` as the focused buffer contract."
        )
        if not contracts:
            lines.append("- No buffer contract was recovered for this ProcessInformationClass case.")
        lines.append("")
        return lines
    if selector_kind == "ntset_thread":
        lines.append(
            "- `NtSetInformationThread` uses `THREADINFOCLASS` as the selector and "
            "`ThreadInformation`/`ThreadInformationLength` as the focused buffer contract."
        )
        if not contracts:
            lines.append("- No buffer contract was recovered for this ThreadInformationClass case.")
        lines.append("")
        return lines
    if selector_kind != "ioctl":
        lines.append("- No CTL_CODE transfer model is used for this selector domain.")
        if not contracts:
            lines.append("- No buffer contract was recovered for this selector case.")
        lines.append("")
        return lines
    if decoded is None:
        lines.append("- No CTL_CODE transfer model is available for this selector value.")
        if not contracts:
            lines.append("- No buffer contract was recovered for this selector case.")
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
        lines.append("No selector buffer structures were inferred for this case.")
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

    hard_size_rows: list[str] = []
    hard_field_rows: list[str] = []
    likely_size_rows: list[str] = []
    likely_field_rows: list[str] = []
    context_rows: list[str] = []
    for contract in contracts:
        for buffer in contract.buffers:
            for item in _all_size_constraints(contract, buffer):
                hard_row = _format_size_requirement(item)
                if hard_row:
                    hard_size_rows.append(hard_row)
                    continue
                likely_row = _format_likely_size_requirement(item)
                if likely_row:
                    likely_size_rows.append(likely_row)
            for item in _all_field_constraints(contract, buffer):
                hard_row = _format_field_requirement(buffer, item)
                if hard_row:
                    hard_field_rows.append(hard_row)
                    continue
                likely_row = _format_likely_field_requirement(buffer, item)
                if likely_row:
                    likely_field_rows.append(likely_row)
            context_rows.extend(_field_access_context_rows(contract, buffer))

    hard_size_rows = _dedupe(hard_size_rows)
    hard_field_rows = _dedupe(hard_field_rows)
    likely_size_rows = _dedupe(likely_size_rows)
    likely_field_rows = _dedupe(likely_field_rows)
    context_rows = _dedupe(context_rows)

    lines.append("Hard requirements:")
    lines.append("")
    if hard_size_rows:
        lines.append("Length requirements:")
        lines.append("")
        for row in hard_size_rows:
            lines.append("- %s" % row)
        lines.append("")
    else:
        lines.append("Length requirements: none recovered from local rejection guards.")
        lines.append("")
    if hard_field_rows:
        lines.append("Field requirements:")
        lines.append("")
        for row in hard_field_rows:
            lines.append("- %s" % row)
        lines.append("")
    else:
        lines.append("Field requirements: none recovered from local rejection guards.")
        lines.append("")
    lines.append("Likely requirements:")
    lines.append("")
    if likely_size_rows or likely_field_rows:
        for row in likely_size_rows:
            lines.append("- %s" % row)
        for row in likely_field_rows:
            lines.append("- %s" % row)
    else:
        lines.append("- none")
    lines.append("")
    lines.append("Context observations:")
    lines.append("")
    if context_rows:
        for row in context_rows[:24]:
            lines.append("- %s" % row)
        if len(context_rows) > 24:
            lines.append("- ... %d more observation(s)" % (len(context_rows) - 24))
    else:
        lines.append("- none")
    lines.append("")
    lines.append(
        "Hard rows are derived from observed rejection guards. Likely rows are predicates without a confirmed "
        "reject outcome. Context rows are access evidence, not requirements. This is not a full path "
        "satisfiability proof."
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


def _render_helper_edge_audit(contracts: list[CommandBufferContract]) -> list[str]:
    lines = ["# Helper Edge Audit", ""]
    records = helper_edge_audit_records(contracts)
    if not records:
        lines.append("No helper edge audit records were produced for this case.")
        lines.append("")
        return lines

    counts = helper_edge_class_counts(records)
    lines.append("Classification counts:")
    lines.append("")
    for classification, count in counts.items():
        lines.append("- `%s`: `%d`" % (classification, count))
    lines.append("")

    unresolved = unresolved_helper_edge_records(records)
    if not unresolved:
        lines.append("Unresolved helper edges: none")
        lines.append("")
        return lines

    lines.append("Unresolved helper edges:")
    lines.append("")
    for record in unresolved:
        lines.append(
            "- `%s`: `%s` severity=`%s`, depth=`%s`, buffers=%s"
            % (
                record.get("callee", ""),
                record.get("classification", ""),
                record.get("severity", ""),
                record.get("depth", ""),
                ", ".join(record.get("passed_buffers", []) or []) or "none",
            )
        )
        lines.append("  - reason: %s" % record.get("reason", ""))
        lines.append("  - next: %s" % record.get("next_action", ""))
        if record.get("evidence"):
            lines.append("  - evidence: `%s`" % record.get("evidence", ""))
    lines.append("")
    return lines


def _render_helper_path_families(contracts: list[CommandBufferContract]) -> list[str]:
    lines = ["# Helper Path Families", ""]
    families = helper_path_family_records(contracts)
    if not families:
        lines.append("No helper path families were recovered for this case.")
        lines.append("")
        return lines
    for family in families:
        lines.append(
            "- `%s`: root=`%s`, class=`%s`, edges=`%s`, unresolved=`%s`, fields=`%s`, predicates=`%s`"
            % (
                family.get("family_id", ""),
                family.get("root_callee", ""),
                family.get("root_classification", ""),
                family.get("edge_count", 0),
                family.get("unresolved_edges", 0),
                family.get("field_accesses", 0),
                family.get("field_constraints", 0),
            )
        )
    lines.append("")
    lines.append(
        "Path families are top-level helper evidence groups. They are a partitioning aid, not a complete "
        "symbolic execution proof."
    )
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


def _format_likely_size_requirement(item: BufferSizeConstraint) -> str:
    if not item.length or not item.relation or not item.value:
        return ""
    return "`%s %s %s` from `%s` [%s]" % (
        item.length,
        item.relation,
        item.value,
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


def _format_likely_field_requirement(buffer: BufferContract, item: FieldConstraint) -> str:
    if not item.relation or not item.value:
        return ""
    field_ref = "%s.%s" % (buffer.structure_name, item.field)
    if item.relation.startswith("mask_"):
        op = item.relation[len("mask_"):]
        expression = "(%s & %s) %s %s" % (
            field_ref,
            item.mask or "mask",
            op,
            item.value,
        )
    else:
        expression = "%s %s %s" % (field_ref, item.relation, item.value)
    return "`%s` from `%s` [%s]" % (expression, item.evidence, item.source)


def _field_access_context_rows(contract: CommandBufferContract, buffer: BufferContract) -> list[str]:
    constrained_offsets = {item.offset for item in _all_field_constraints(contract, buffer)}
    rows: list[str] = []
    for item in _all_field_accesses(contract, buffer):
        if item.offset in constrained_offsets:
            continue
        rows.append(
            "`%s.%s` accessed as `%s` `%s` from `%s` [%s]"
            % (
                buffer.structure_name,
                item.field,
                item.type or "unknown",
                item.access or "access",
                item.evidence,
                item.source,
            )
        )
    return rows


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


def _selector_kind(capture: FunctionCapture, contracts: list[CommandBufferContract]) -> str:
    for contract in contracts:
        if contract.dispatcher_kind:
            return contract.dispatcher_kind
    name = (capture.name or "").lower()
    prototype = capture.prototype or ""
    if name == "ntsetsysteminformation" or "SYSTEM_INFORMATION_CLASS" in prototype:
        return "ntset_system"
    if name == "ntsetinformationprocess" or "PROCESSINFOCLASS" in prototype:
        return "ntset_process"
    if name == "ntsetinformationthread" or "THREADINFOCLASS" in prototype:
        return "ntset_thread"
    return "generic"


def _selector_domain_label(selector_kind: str) -> str:
    if selector_kind == "ioctl":
        return "IOCTL"
    if selector_kind == "ntset_system":
        return "SYSTEM_INFORMATION_CLASS"
    if selector_kind == "ntset_process":
        return "PROCESSINFOCLASS"
    if selector_kind == "ntset_thread":
        return "THREADINFOCLASS"
    return selector_kind or "generic"


def _selector_name(
    selector_kind: str,
    command_value: int,
    contracts: list[CommandBufferContract],
) -> str:
    for contract in contracts:
        if contract.command_name:
            return contract.command_name
    if selector_kind == "ntset_system":
        return get_system_information_class_name(command_value)
    if selector_kind == "ntset_process":
        return get_process_information_class_name(command_value)
    if selector_kind == "ntset_thread":
        return get_thread_information_class_name(command_value)
    if selector_kind == "ioctl" and decode_ioctl_code(command_value) is not None:
        return format_ctl_code(command_value)
    return ""

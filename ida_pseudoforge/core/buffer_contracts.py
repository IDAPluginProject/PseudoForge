from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from functools import lru_cache
from typing import Iterable

from ida_pseudoforge.core.ioctl import decode_ioctl_code, format_ctl_code, parse_c_integer_literal
from ida_pseudoforge.core.disasm_contracts import (
    DisasmCaseContractEvidence,
    DisasmCaseSlice,
    normalize_disasm_slices,
    recover_disasm_case_evidence,
)
from ida_pseudoforge.core.normalize import (
    extract_function_signature,
    extract_function_name,
    extract_parameters_from_signature,
    find_matching_paren,
    safe_identifier_replace,
    split_parameters,
)
from ida_pseudoforge.core.plan_schema import (
    BufferContract,
    BufferSizeConstraint,
    CleanPlan,
    CommandBufferContract,
    FieldAccess,
    FieldConstraint,
    FlowRewrite,
    FunctionCapture,
    HelperContractEdge,
)
from ida_pseudoforge.core.render_comments import sanitize_generated_comment_text
from ida_pseudoforge.profiles.loader import (
    get_process_information_class_name,
    get_process_information_class_value,
    get_system_information_class_name,
    get_system_information_class_value,
    get_thread_information_class_name,
    get_thread_information_class_value,
    load_kernel_api_family,
)


_CASE_INTEGER_SUFFIX = r"(?i:ui64|i64|u?ll|llu|ul|lu|u|l)"
_CASE_LABEL_RE = re.compile(r"case\s+(?P<value>[^:]+?)\s*:")
_C_VALUE_RE = r"(?:sizeof\s*\([^)]+\)|0x[0-9A-Fa-f]+|\d+)(?:%s)?" % _CASE_INTEGER_SUFFIX
_C_INTEGER_LITERAL_VALUE_RE = r"-?(?:0x[0-9A-Fa-f]+|\d+)(?:%s)?" % _CASE_INTEGER_SUFFIX
_IDENT_RE = r"[A-Za-z_][A-Za-z0-9_]*"
_LENGTH_COMPARE_RE = re.compile(
    r"(?P<left>%s|%s)\s*(?P<op>==|!=|<=|>=|<|>)\s*(?P<right>%s|%s)"
    % (_IDENT_RE, _C_VALUE_RE, _IDENT_RE, _C_VALUE_RE)
)
_LENGTH_TRUTHY_IF_RE = re.compile(
    r"^if\s*\(\s*(?P<negate>!)?\s*"
    r"(?:\(\s*(?:_DWORD|unsigned\s+int|int|ULONG|SIZE_T|DWORD)\s*\)\s*)?"
    r"(?P<length>%s)\s*\)" % _IDENT_RE
)
_ARROW_FIELD_RE = re.compile(r"\b(?P<buffer>%s)\s*->\s*(?P<field>%s)\b" % (_IDENT_RE, _IDENT_RE))
_DEREF_OFFSET_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[_A-Za-z][A-Za-z0-9_\s]*?)\s*\*+\s*\)\s*"
    r"\(\s*(?P<buffer>%s)\s*(?:\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:LL|i64|L)?)?\s*\)"
    % _IDENT_RE
)
_DEREF_PLAIN_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[_A-Za-z][A-Za-z0-9_\s]*?)\s*\*+\s*\)\s*(?P<buffer>%s)\b(?!\s*\+)" % _IDENT_RE
)
_CAST_INDEX_RE = re.compile(
    r"\*\s*\(\s*\(\s*(?P<type>[_A-Za-z][A-Za-z0-9_\s]*?)\s*\*+\s*\)\s*"
    r"(?P<buffer>%s)\s*\+\s*(?P<index>\d+)\s*\)" % _IDENT_RE
)
_INDEXED_MEMBER_RE = re.compile(
    r"\b(?P<buffer>%s)\s*\[\s*(?P<index>\d+)\s*\]\s*\.\s*"
    r"(?P<member>%s)\s*\[\s*(?P<member_index>\d+)\s*\]" % (_IDENT_RE, _IDENT_RE)
)
_POINTER_INDEX_RE = re.compile(
    r"\b(?P<buffer>%s)\s*\[\s*(?P<index>\d+)\s*\](?!\s*\.)" % _IDENT_RE
)
_PLAIN_POINTER_DEREF_RE = re.compile(r"\*\s*(?P<buffer>%s)\b" % _IDENT_RE)
_ASSIGNMENT_RE = re.compile(r"(?P<left>[^=<>!]+?)\s*=\s*(?!=)(?P<right>.+?);")
_BUFFER_COPY_ASSIGN_RE = re.compile(
    r"^\s*(?P<local>%s)\s*=\s*(?P<expr>\*\s*(?P<plain>%s)|(?P<indexed>%s)\s*\[\s*(?P<index>\d+)\s*\])\s*;"
    % (_IDENT_RE, _IDENT_RE, _IDENT_RE)
)
_LOCAL_ACCESSOR_RE = re.compile(
    r"\b(?P<accessor>(?:LO|HI)(?:BYTE|WORD|DWORD)|(?:BYTE|WORD|DWORD|QWORD)\d+)\s*"
    r"\(\s*(?P<local>%s)\s*\)" % _IDENT_RE
)
_LOCAL_CAST_RE = re.compile(
    r"\(\s*(?P<type>_?BYTE|_?WORD|_?DWORD|_?QWORD|unsigned\s+int|int|ULONG|LONG|__int64|unsigned\s+__int64)\s*\)"
    r"\s*(?P<local>%s)\b" % _IDENT_RE
)
_LOCAL_ADDRESS_DEREF_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[_A-Za-z][A-Za-z0-9_\s]*?)\s*\*+\s*\)\s*&\s*(?P<local>%s)\b" % _IDENT_RE
)
_LOCAL_MEMBER_RE = re.compile(
    r"\b(?P<local>%s)\s*\.\s*(?P<member>m128i_[iu](?:8|16|32|64))\s*\[\s*(?P<member_index>\d+)\s*\]"
    % _IDENT_RE
)
_CALL_NAME_RE = re.compile(r"\b(?P<name>%s)\s*\(" % _IDENT_RE)
_INDIRECT_CALL_TARGET_RE = re.compile(r"\)\s*(?P<name>%s)\s*\)\s*\(" % _IDENT_RE)
_CAST_OFFSET_ACCESS_RE = re.compile(
    r"\(\s*(?P<type>[_A-Za-z][A-Za-z0-9_\s]*?(?:\s*\*+)*)\s*\)\s*"
    r"\(\s*(?P<base>%s)\s*\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:LL|i64|L)?\s*\)"
    % _IDENT_RE
)
_GOTO_LABEL_RE = re.compile(r"\bgoto\s+(?P<label>[A-Za-z_][A-Za-z0-9_]*)\s*;")
_RETURN_STATUS_LITERAL_RE = re.compile(r"\breturn\s+(?P<value>%s)\s*;" % _C_INTEGER_LITERAL_VALUE_RE)
_ASSIGN_STATUS_LITERAL_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?P<value>%s)\s*;" % _C_INTEGER_LITERAL_VALUE_RE)
_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "do", "else"}
_DECOMPILER_ACCESSOR_CALL_RE = re.compile(
    r"^(?:(?:LO|HI)(?:BYTE|WORD|DWORD)|(?:BYTE|WORD|DWORD|QWORD)\d+)$"
)
_CALLING_CONVENTION_TOKENS = {"__cdecl", "__fastcall", "__stdcall", "__thiscall", "__vectorcall"}
_TYPE_LIKE_CALL_TOKENS = {
    "void",
    "char",
    "short",
    "int",
    "long",
    "float",
    "double",
    "bool",
    "signed",
    "unsigned",
    "_BYTE",
    "_WORD",
    "_DWORD",
    "_QWORD",
    "_OWORD",
    "_BOOL1",
    "_BOOL2",
    "_BOOL4",
    "_BOOL8",
    "BYTE",
    "WORD",
    "DWORD",
    "QWORD",
    "BOOL",
    "BOOLEAN",
    "NTSTATUS",
    "PVOID",
    "PCHAR",
    "PWCHAR",
    "HANDLE",
    "ULONG",
    "LONG",
    "ULONGLONG",
    "LONGLONG",
    "ULONG_PTR",
    "LONG_PTR",
    "SIZE_T",
    "SSIZE_T",
    "UINT_PTR",
    "INT_PTR",
}
_TYPE_LIKE_CALL_RE = re.compile(r"^_{1,2}(?:u?int(?:8|16|32|64)|m(?:64|128i?|256i?|512i?))$")
_IRP_ASSOCIATED_IRP_OFFSET_X64 = 0x18


def clear_profile_dependent_buffer_contract_caches() -> None:
    _profile_field_layout_for_pointer_type.cache_clear()
    _profile_structure_field_layout.cache_clear()
    _profile_structure_size.cache_clear()


@dataclass(slots=True)
class CaseContextAccess:
    base: str
    offset: int
    type: str
    access: str
    predicate: str = ""
    expression: str = ""
    evidence: str = ""


@dataclass(slots=True)
class _SizePredicate:
    role: str
    length: str
    relation: str
    value: int


@dataclass(slots=True)
class _HelperCallSite:
    callee: str
    arguments: list[str]
    evidence: str
    indirect: bool = False
    offset: int = -1


def recover_buffer_contracts(
    capture: FunctionCapture,
    flow_rewrites: list[FlowRewrite],
    rename_map: dict[str, str] | None = None,
    helper_captures: dict[str, FunctionCapture] | Iterable[FunctionCapture] | None = None,
    max_depth: int = 2,
    case_values: Iterable[int] | None = None,
    disasm_case_slices: Iterable[DisasmCaseSlice] | dict[int, DisasmCaseSlice] | None = None,
) -> list[CommandBufferContract]:
    raw_text = capture.pseudocode or ""
    text = safe_identifier_replace(raw_text, rename_map or {})
    renames = rename_map or {}
    helper_map = _normalize_helper_captures(helper_captures)
    buffer_sources = _infer_buffer_sources(text, capture)
    length_aliases = _infer_length_aliases(text)
    helper_interesting_names = (
        set(buffer_sources)
        | _length_names_from_sources(buffer_sources)
        | _length_like_names(text)
    )
    case_filter = {int(value) for value in case_values} if case_values is not None else None
    disasm_evidence_by_case = _recover_disasm_evidence_by_case(
        disasm_case_slices,
        buffer_sources,
        length_aliases,
        rename_map or {},
        case_filter,
    )
    disasm_helper_slices = _disasm_helper_slices_by_name(disasm_case_slices, capture)
    result: list[CommandBufferContract] = []

    for flow in flow_rewrites:
        kind = _dispatcher_kind(capture, flow)
        if kind == "generic" and not _has_strong_generic_buffer_evidence(text):
            continue
        case_bodies = _merged_case_bodies(
            native_bodies=_native_switch_case_bodies(text, flow.dispatcher),
            flow_bodies={
                value: _renamed_case_body_lines(lines, rename_map or {})
                for value, lines in flow.case_bodies.items()
            },
        )
        if not case_bodies:
            continue

        for value in flow.recovered_cases:
            if case_filter is not None and value not in case_filter:
                continue
            body_lines = _authoritative_case_body_lines(raw_text, flow, value, renames)
            if not body_lines:
                body_lines = case_bodies.get(value, [])
            if not body_lines:
                continue
            if _is_terminal_noncontract_case_body(body_lines):
                continue
            body_lines = _body_lines_with_shared_tail_size_guards(
                text,
                flow.dispatcher,
                body_lines,
                buffer_sources,
                length_aliases,
            )
            if not _case_body_has_contract_evidence(body_lines, buffer_sources, length_aliases):
                body_lines = _body_lines_with_goto_label_tail_context(
                    text,
                    body_lines,
                    buffer_sources,
                    length_aliases,
                )
            if (
                not _case_body_has_contract_evidence(body_lines, buffer_sources, length_aliases)
                and not _case_body_has_helper_argument_evidence(body_lines, helper_interesting_names)
            ):
                body_lines = _body_lines_with_goto_label_helper_context(
                    text,
                    body_lines,
                    helper_interesting_names,
                )
            if (
                not _case_body_has_contract_evidence(body_lines, buffer_sources, length_aliases)
                and not _case_body_has_helper_argument_evidence(body_lines, helper_interesting_names)
            ):
                body_lines = _body_lines_with_dispatcher_condition_context(
                    text,
                    flow.dispatcher,
                    value,
                    flow.case_names.get(value, ""),
                    body_lines,
                )
            command_name = flow.case_names.get(value, "")
            if not command_name and kind == "ioctl":
                command_name = format_ctl_code(value)
            command = _analyze_command_case(
                kind,
                flow.dispatcher,
                value,
                command_name,
                body_lines,
                buffer_sources,
                helper_map,
                max_depth=max_depth,
                depth=0,
                visited={capture.name},
                length_aliases=length_aliases,
                disasm_evidence=disasm_evidence_by_case.get(value),
                disasm_helper_slices=disasm_helper_slices,
            )
            if command.buffers or command.helper_edges:
                result.append(command)

    if case_filter is not None:
        missing_values = [value for value in sorted(case_filter) if value not in {item.command_value for item in result}]
        if missing_values:
            result.extend(
                _recover_focused_native_switch_contracts(
                    capture,
                    text,
                    missing_values,
                    buffer_sources,
                    helper_map,
                    max_depth,
                    length_aliases,
                    helper_interesting_names,
                    disasm_evidence_by_case,
                    disasm_helper_slices,
                )
            )
        missing_values = [value for value in sorted(case_filter) if value not in {item.command_value for item in result}]
        if missing_values:
            result.extend(
                _recover_focused_disasm_contracts(
                    capture,
                    text,
                    missing_values,
                    buffer_sources,
                    helper_map,
                    max_depth,
                    length_aliases,
                    disasm_evidence_by_case,
                    disasm_helper_slices,
                )
            )

    return result


def find_case_value_near_line(pseudocode: str, line_index: int = -1, line_text: str = "") -> int | None:
    if line_text:
        if _is_default_case_line(line_text):
            return None
        value = _case_value_from_line(line_text)
        if value is not None:
            return value
    lines = (pseudocode or "").splitlines()
    if line_index < 0 or line_index >= len(lines):
        return None
    stop_index = max(-1, line_index - 200)
    for index in range(line_index, stop_index, -1):
        stripped = lines[index].strip()
        if _is_default_case_line(stripped):
            return None
        value = _case_value_from_line(stripped)
        if value is not None:
            return value
        if index != line_index and stripped.startswith("switch"):
            break
    return None


def render_buffer_contract_report(capture: FunctionCapture, contracts: list[CommandBufferContract]) -> str:
    lines = [
        "# Buffer Contract Report: %s" % (capture.name or "function"),
        "",
        "- EA: 0x%X" % capture.ea,
        "- Contracts: `%d`" % len(contracts),
        "",
    ]
    if not contracts:
        lines.append("No command buffer contracts were recovered.")
        return "\n".join(lines).rstrip() + "\n"

    for contract in contracts:
        title = contract.command_name or ("0x%X" % contract.command_value)
        lines.extend(
            [
                "## %s" % title,
                "",
                "- Dispatcher kind: `%s`" % contract.dispatcher_kind,
                "- Dispatcher: `%s`" % contract.dispatcher,
                "- Command value: `0x%X`" % contract.command_value,
                "- Confidence: `%.2f`" % contract.confidence,
                "- Evidence: %s" % contract.evidence,
                "",
            ]
        )
        if contract.buffers:
            lines.extend(["Buffers:", ""])
            for buffer in contract.buffers:
                lines.extend(
                    [
                        "- `%s` `%s` as `%s`" % (
                            buffer.role,
                            buffer.variable,
                            buffer.structure_name,
                        ),
                        "  - source: `%s`" % buffer.source,
                        "  - length: `%s`" % (buffer.length_variable or "unknown"),
                        "  - confidence: `%.2f`" % buffer.confidence,
                    ]
                )
                for size in buffer.size_constraints:
                    lines.append(
                        "  - observed size guard: `%s %s %s` (%s)"
                        % (size.length, size.relation, size.value, size.evidence)
                    )
                    if size.valid_relation and size.valid_value:
                        lines.append(
                            "  - valid size: `%s %s %s` (derived from rejection guard)"
                            % (size.length, size.valid_relation, size.valid_value)
                        )
                for access in buffer.field_accesses:
                    lines.append(
                        "  - field %s: `%s %s` `%s` at `0x%X` (%s)"
                        % (
                            access.access,
                            access.type or "unknown",
                            access.field,
                            access.buffer,
                            access.offset,
                            access.evidence,
                        )
                    )
                for field in buffer.field_constraints:
                    detail = field.value if field.value else field.mask
                    lines.append(
                        "  - observed field guard: `%s %s %s` at `0x%X` (%s)"
                        % (field.field, field.relation, detail, field.offset, field.evidence)
                    )
                    if field.valid_relation and field.valid_value:
                        lines.append(
                            "  - valid field: `%s %s %s` at `0x%X` (derived from rejection guard)"
                            % (field.field, field.valid_relation, field.valid_value, field.offset)
                        )
            lines.append("")
        if contract.helper_edges:
            lines.extend(["Helper edges:", ""])
            for edge in contract.helper_edges:
                status = "resolved" if edge.resolved else "unresolved"
                lines.append(
                    "- `%s(%s)` `%s` buffers=%s"
                    % (edge.callee, ", ".join(edge.arguments), status, ", ".join(edge.passed_buffers) or "none")
                )
                for size in edge.propagated_size_constraints:
                    lines.append(
                        "  - propagated observed size guard: `%s %s %s` (%s)"
                        % (size.length, size.relation, size.value, size.evidence)
                    )
                    if size.valid_relation and size.valid_value:
                        lines.append(
                            "  - propagated valid size: `%s %s %s`"
                            % (size.length, size.valid_relation, size.valid_value)
                        )
                for access in edge.propagated_field_accesses:
                    lines.append(
                        "  - propagated field %s: `%s %s` `%s` at `0x%X` (%s)"
                        % (
                            access.access,
                            access.type or "unknown",
                            access.field,
                            access.buffer,
                            access.offset,
                            access.evidence,
                        )
                    )
                for field in edge.propagated_field_constraints:
                    detail = field.value if field.value else field.mask
                    lines.append(
                        "  - propagated observed field guard: `%s %s %s` (%s)"
                        % (field.field, field.relation, detail, field.evidence)
                    )
                    if field.valid_relation and field.valid_value:
                        lines.append(
                            "  - propagated valid field: `%s %s %s`"
                            % (field.field, field.valid_relation, field.valid_value)
                        )
                for warning in edge.warnings:
                    lines.append("  - warning: %s" % warning)
                for nested in edge.nested_edges:
                    nested_status = "resolved" if nested.resolved else "unresolved"
                    lines.append(
                        "  - nested: `%s(%s)` `%s` buffers=%s"
                        % (
                            nested.callee,
                            ", ".join(nested.arguments),
                            nested_status,
                            ", ".join(nested.passed_buffers) or "none",
                        )
                    )
            lines.append("")
        if contract.warnings:
            lines.extend(["Warnings:", ""])
            for warning in contract.warnings:
                lines.append("- %s" % warning)
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_case_context_report(capture: FunctionCapture, plan: CleanPlan, command_value: int) -> str:
    rename_map = {item.old: item.new for item in plan.active_renames()}
    flow, body_lines = _selected_case_body(capture, plan, command_value, rename_map=rename_map)
    if flow is None and not body_lines:
        return ""

    context_accesses = _recover_case_context_accesses(capture, body_lines)
    goto_labels = _case_goto_labels(body_lines)
    cleanup_by_label = {item.label: item for item in plan.cleanup_labels}
    lines = [
        "# Selected Case Context",
        "",
    ]

    if flow is not None:
        lines.append("- Dispatcher: `%s`" % (flow.dispatcher or "unknown"))
        lines.append("- Body state: `%s`" % flow.case_body_states.get(command_value, "unknown"))
        if flow.case_anchors.get(command_value):
            lines.append("- Source line: `%d`" % flow.case_anchors[command_value])
    else:
        lines.append("- Dispatcher: `unknown`")
        lines.append("- Body state: `unknown`")

    if goto_labels:
        lines.append("- Shared exits: %s" % ", ".join("`%s`" % label for label in goto_labels))
    else:
        lines.append("- Shared exits: none")
    lines.append("- Case body lines: `%d`" % len(body_lines))
    lines.append("")

    excerpt = _case_body_excerpt(body_lines)
    if excerpt:
        lines.extend(["Case body excerpt:", ""])
        for line in excerpt:
            lines.append("- `%s`" % _cpp_comment(line))
        lines.append("")

    if goto_labels:
        lines.extend(["Shared exit details:", ""])
        for label in goto_labels:
            cleanup = cleanup_by_label.get(label)
            if cleanup is None:
                lines.append("- `%s`: no cleanup label classification available" % label)
                continue
            lines.append(
                "- `%s`: `%s` confidence=`%.2f` (%s)"
                % (label, cleanup.classification, cleanup.confidence, cleanup.evidence)
            )
        lines.append("")

    if context_accesses:
        lines.extend(["Context-like offset accesses:", ""])
        for access in context_accesses:
            lines.append(
                "- `%s + 0x%X` as `%s` `%s` (%s)"
                % (access.base, access.offset, access.type or "unknown", access.access, access.evidence)
            )
            if access.predicate:
                lines.append("  - valid predicate: `%s`" % access.predicate)
        lines.append("")
        lines.append(
            "ABI note: these context-like fields are reported separately from command input/output buffers."
        )
    else:
        lines.append("Context-like offset accesses: none")
    return "\n".join(lines).rstrip() + "\n"


def helper_names_for_selected_case(capture: FunctionCapture, plan: CleanPlan, command_value: int) -> list[str]:
    rename_map = {item.old: item.new for item in plan.active_renames()}
    raw_text = capture.pseudocode or ""
    renamed_text = safe_identifier_replace(raw_text, rename_map)
    _raw_flow, raw_body_lines = _selected_case_body(capture, plan, command_value)
    _renamed_flow, renamed_body_lines = _selected_case_body(
        capture,
        plan,
        command_value,
        rename_map=rename_map,
    )

    raw_sources = _infer_buffer_sources(raw_text, capture)
    renamed_sources = _infer_buffer_sources(renamed_text, capture)
    raw_interesting_names = set(raw_sources) | _length_names_from_sources(raw_sources) | _length_like_names(raw_text)
    renamed_interesting_names = (
        set(renamed_sources)
        | _length_names_from_sources(renamed_sources)
        | _length_like_names(renamed_text)
    )

    result: list[str] = []
    seen: set[str] = set()
    variants = [
        (raw_text, raw_body_lines, raw_interesting_names),
        (renamed_text, renamed_body_lines, renamed_interesting_names),
    ]
    for full_text, body_lines, interesting_names in variants:
        if not body_lines or not interesting_names:
            continue
        candidate_lines = _body_lines_with_goto_label_helper_context(
            full_text,
            body_lines,
            interesting_names,
        )
        for site in _iter_helper_call_sites("\n".join(candidate_lines)):
            callee = site.callee
            if callee in seen:
                continue
            if not _arguments_reference_names(site.arguments, interesting_names):
                continue
            seen.add(callee)
            result.append(callee)
    return result


def _iter_helper_call_sites(text: str) -> list[_HelperCallSite]:
    result: list[_HelperCallSite] = []
    seen: set[tuple[str, tuple[str, ...], bool]] = set()
    for site in _direct_helper_call_sites(text):
        key = (site.callee, tuple(site.arguments), site.indirect)
        if key in seen:
            continue
        seen.add(key)
        result.append(site)
    for site in _indirect_helper_call_sites(text):
        key = (site.callee, tuple(site.arguments), site.indirect)
        if key in seen:
            continue
        seen.add(key)
        result.append(site)
    return result


def _direct_helper_call_sites(text: str) -> list[_HelperCallSite]:
    result: list[_HelperCallSite] = []
    for match in _CALL_NAME_RE.finditer(text or ""):
        callee = match.group("name")
        if _is_ignored_helper_call_name(callee):
            continue
        open_index = match.end() - 1
        close_index = find_matching_paren(text or "", open_index)
        if close_index < 0:
            continue
        arguments = split_parameters((text or "")[open_index + 1:close_index])
        result.append(
            _HelperCallSite(
                callee=callee,
                arguments=arguments,
                evidence=_call_site_evidence(callee, arguments),
                offset=match.start(),
            )
        )
    return result


def _indirect_helper_call_sites(text: str) -> list[_HelperCallSite]:
    result: list[_HelperCallSite] = []
    source = text or ""
    for match in _INDIRECT_CALL_TARGET_RE.finditer(source):
        callee = match.group("name")
        if _is_ignored_helper_call_name(callee):
            continue
        open_index = match.end() - 1
        close_index = find_matching_paren(source, open_index)
        if close_index < 0:
            continue
        arguments = split_parameters(source[open_index + 1:close_index])
        result.append(
            _HelperCallSite(
                callee=callee,
                arguments=arguments,
                evidence=_call_site_evidence(callee, arguments),
                indirect=True,
                offset=match.start(),
            )
        )
    return result


def _is_ignored_helper_call_name(name: str) -> bool:
    if name in _KEYWORDS:
        return True
    if name in _CALLING_CONVENTION_TOKENS:
        return True
    if name in _TYPE_LIKE_CALL_TOKENS:
        return True
    if _TYPE_LIKE_CALL_RE.fullmatch(name or ""):
        return True
    return bool(_DECOMPILER_ACCESSOR_CALL_RE.fullmatch(name or ""))


def _call_site_evidence(callee: str, arguments: list[str]) -> str:
    return "%s(%s)" % (callee, ", ".join(arguments))


def _arguments_reference_names(arguments: list[str], names: set[str]) -> bool:
    for argument in arguments:
        identifier = _argument_identifier(argument)
        if identifier in names:
            return True
        if _argument_references_any_name(argument, names):
            return True
    return False


def _body_lines_with_shared_tail_size_guards(
    text: str,
    dispatcher: str,
    body_lines: list[str],
    buffer_sources: dict[str, dict[str, str]],
    length_aliases: dict[str, str] | None = None,
) -> list[str]:
    assignments = _literal_assignments_from_lines(body_lines)
    if not assignments:
        return body_lines
    length_names = _length_names_from_sources(buffer_sources) | _length_like_names(text) | set(length_aliases or {})
    if not length_names:
        return body_lines
    tail_lines = _post_switch_tail_lines(text, dispatcher)
    if not tail_lines:
        return body_lines
    extra = _shared_tail_size_guard_blocks(tail_lines, assignments, length_names)
    if not extra:
        return body_lines
    return list(body_lines) + extra


def _body_lines_with_goto_label_tail_context(
    text: str,
    body_lines: list[str],
    buffer_sources: dict[str, dict[str, str]],
    length_aliases: dict[str, str] | None = None,
    max_tail_lines: int = 160,
) -> list[str]:
    labels = _case_goto_labels(body_lines)
    if not labels:
        return body_lines
    lines = (text or "").splitlines()
    for label in labels:
        tail = _goto_label_tail_context(lines, label, max_tail_lines)
        if not tail:
            continue
        merged = _merge_unique_context_lines(body_lines, tail)
        if _case_body_has_contract_evidence(merged, buffer_sources, length_aliases):
            return merged
    return body_lines


def _body_lines_with_goto_label_helper_context(
    text: str,
    body_lines: list[str],
    interesting_names: set[str],
    max_tail_lines: int = 160,
) -> list[str]:
    labels = _case_goto_labels(body_lines)
    if not labels:
        return body_lines
    lines = (text or "").splitlines()
    for label in labels:
        tail = _goto_label_tail_context(lines, label, max_tail_lines)
        if not tail:
            continue
        if _case_body_has_helper_argument_evidence(tail, interesting_names):
            return _merge_unique_context_lines(body_lines, tail)
    return body_lines


def _merge_unique_context_lines(body_lines: list[str], context_lines: list[str]) -> list[str]:
    merged = list(body_lines)
    seen = {line.strip() for line in merged if line.strip()}
    for line in context_lines:
        stripped = line.strip()
        if not stripped or stripped in seen:
            continue
        merged.append(stripped)
        seen.add(stripped)
    return merged


def _literal_assignments_from_lines(lines: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in lines:
        match = re.search(
            r"^\s*(?P<name>%s)\s*=\s*(?P<value>%s)\s*;"
            % (_IDENT_RE, _C_INTEGER_LITERAL_VALUE_RE),
            line or "",
        )
        if not match:
            continue
        result[match.group("name")] = match.group("value")
    return result


def _post_switch_tail_lines(text: str, dispatcher: str, max_lines: int = 120) -> list[str]:
    if not dispatcher:
        return []
    switch_re = re.compile(r"\bswitch\s*\(\s*(?:\(\s*[^()]+\s*\)\s*)*%s\s*\)" % re.escape(dispatcher))
    lines = (text or "").splitlines()
    switch_index = -1
    for index, line in enumerate(lines):
        if switch_re.search(line):
            switch_index = index
            break
    if switch_index < 0:
        return []
    depth = 0
    seen_open = False
    for index in range(switch_index, len(lines)):
        stripped = lines[index].strip()
        opens = stripped.count("{")
        closes = stripped.count("}")
        if opens:
            seen_open = True
        if seen_open:
            depth += opens - closes
            if depth <= 0:
                return lines[index + 1:index + 1 + max_lines]
    return []


def _shared_tail_size_guard_blocks(
    tail_lines: list[str],
    assignments: dict[str, str],
    length_names: set[str],
) -> list[str]:
    result: list[str] = []
    seen: set[tuple[str, ...]] = set()
    assignment_names = set(assignments)
    for index, line in enumerate(tail_lines):
        stripped = line.strip()
        if not stripped.startswith("if"):
            continue
        if not _line_mentions_any_identifier(stripped, length_names):
            continue
        if not _line_mentions_any_identifier(stripped, assignment_names):
            continue
        block = _control_block_lines(tail_lines, index)
        replaced = [_replace_literal_assignments(item, assignments) for item in block]
        key = tuple(replaced)
        if key in seen:
            continue
        seen.add(key)
        result.extend(replaced)
    return result


def _control_block_lines(lines: list[str], index: int, max_lines: int = 16) -> list[str]:
    if index < 0 or index >= len(lines):
        return []
    result = [lines[index]]
    depth = 0
    saw_open = False
    for offset, line in enumerate(lines[index:]):
        stripped = line.strip()
        opens = stripped.count("{")
        closes = stripped.count("}")
        if opens:
            saw_open = True
        depth += opens - closes
        if len(result) >= max_lines:
            break
        if offset == 0:
            if not saw_open and stripped.endswith(";"):
                break
            continue
        result.append(line)
        if saw_open and depth <= 0:
            break
        if not saw_open and stripped.endswith(";"):
            break
    return result


def _replace_literal_assignments(line: str, assignments: dict[str, str]) -> str:
    result = line
    for name, value in sorted(assignments.items(), key=lambda item: len(item[0]), reverse=True):
        result = re.sub(r"\b%s\b" % re.escape(name), value, result)
    return result


def _line_mentions_any_identifier(line: str, names: set[str]) -> bool:
    if not line or not names:
        return False
    identifiers = set(re.findall(r"\b%s\b" % _IDENT_RE, line))
    return bool(identifiers & names)


def _case_body_has_contract_evidence(
    body_lines: list[str],
    buffer_sources: dict[str, dict[str, str]],
    length_aliases: dict[str, str] | None,
) -> bool:
    return bool(
        _recover_size_constraints(
            body_lines,
            length_aliases=length_aliases,
            known_lengths=_length_names_from_sources(buffer_sources),
        )
        or _recover_field_accesses(body_lines, buffer_sources)
    )


def _case_body_has_helper_argument_evidence(body_lines: list[str], interesting_names: set[str]) -> bool:
    if not body_lines or not interesting_names:
        return False
    for site in _iter_helper_call_sites("\n".join(body_lines)):
        if _arguments_reference_names(site.arguments, interesting_names):
            return True
    return False


def _body_lines_with_dispatcher_condition_context(
    text: str,
    dispatcher: str,
    command_value: int,
    command_name: str,
    body_lines: list[str],
) -> list[str]:
    context = _dispatcher_condition_context_lines(text, dispatcher, command_value, command_name)
    if not context:
        return body_lines
    return _merge_unique_context_lines(body_lines, context)


def _dispatcher_condition_context_lines(
    text: str,
    dispatcher: str,
    command_value: int,
    command_name: str,
) -> list[str]:
    if not text or not dispatcher:
        return []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not _is_simple_dispatcher_case_condition(line, dispatcher, command_value, command_name):
            continue
        prefix = _preceding_guard_context(lines, index)
        branch = _true_branch_and_join_context(lines, index)
        context = prefix + branch
        if _case_context_has_buffer_evidence(context):
            return context
    return []


def _is_simple_dispatcher_case_condition(
    line: str,
    dispatcher: str,
    command_value: int,
    command_name: str,
) -> bool:
    match = re.match(r"^\s*if\s*\(\s*(?P<left>.+?)\s*==\s*(?P<right>.+?)\s*\)\s*$", line or "")
    if not match:
        return False
    left = _clean_dispatcher_case_operand(match.group("left"))
    right = _clean_dispatcher_case_operand(match.group("right"))
    return (
        _operand_matches_dispatcher(left, dispatcher)
        and _operand_matches_case(right, command_value, command_name)
    ) or (
        _operand_matches_dispatcher(right, dispatcher)
        and _operand_matches_case(left, command_value, command_name)
    )


def _clean_dispatcher_case_operand(value: str) -> str:
    token = (value or "").strip()
    while True:
        stripped = re.sub(r"^\(\s*[_A-Za-z][A-Za-z0-9_\s]*\s*\)\s*", "", token).strip()
        if stripped == token:
            break
        token = stripped
    if token.startswith("(") and token.endswith(")"):
        token = token[1:-1].strip()
    return token


def _operand_matches_dispatcher(value: str, dispatcher: str) -> bool:
    return (value or "").strip() == dispatcher


def _operand_matches_case(value: str, command_value: int, command_name: str) -> bool:
    token = (value or "").strip()
    if command_name and token == command_name:
        return True
    parsed = _parse_case_label_value(token)
    return parsed == command_value


def _preceding_guard_context(lines: list[str], condition_index: int, max_lines: int = 24) -> list[str]:
    start = condition_index
    scanned = 0
    index = condition_index - 1
    while index >= 0:
        stripped = lines[index].strip()
        if not stripped:
            break
        if stripped == "}":
            block_start = _matching_braced_block_start(lines, index)
            header_index = _previous_non_empty_index(lines, block_start - 1)
            if (
                block_start >= 0
                and header_index is not None
                and lines[header_index].strip().startswith("if")
            ):
                start = header_index
                scanned += index - header_index + 1
                index = header_index - 1
                if scanned >= max_lines:
                    break
                continue
            break
        start = index
        scanned += 1
        if stripped.endswith(":"):
            break
        if stripped in {"{", "}"}:
            break
        if scanned >= max_lines:
            break
        index -= 1
    return [line.strip() for line in lines[start:condition_index] if line.strip()]


def _true_branch_and_join_context(
    lines: list[str],
    condition_index: int,
    max_join_lines: int = 96,
) -> list[str]:
    result = [lines[condition_index].strip()]
    then_start = _next_non_empty_index(lines, condition_index + 1)
    if then_start is None:
        return result
    then_end = _statement_end_index(lines, then_start)
    then_lines = _statement_lines(lines, then_start, then_end)
    result.extend(then_lines)
    tail_label = _single_goto_label(then_lines)
    if tail_label:
        result.extend(_label_tail_context(lines, tail_label, max_join_lines))
        return result

    join_start = then_end
    else_index = _next_non_empty_index(lines, then_end)
    if else_index is not None and lines[else_index].strip().startswith("else"):
        else_body_start = _next_non_empty_index(lines, else_index + 1)
        if else_body_start is not None:
            join_start = _statement_end_index(lines, else_body_start)
        else:
            join_start = else_index + 1

    result.extend(_join_context_lines(lines, join_start, max_join_lines))
    return result


def _next_non_empty_index(lines: list[str], start: int) -> int | None:
    for index in range(start, len(lines)):
        if lines[index].strip():
            return index
    return None


def _previous_non_empty_index(lines: list[str], start: int) -> int | None:
    for index in range(start, -1, -1):
        if lines[index].strip():
            return index
    return None


def _statement_end_index(lines: list[str], start: int) -> int:
    if start < 0 or start >= len(lines):
        return start
    stripped = lines[start].strip()
    if stripped.startswith("{"):
        return _braced_statement_end_index(lines, start)
    if stripped.startswith("else"):
        body_start = _next_non_empty_index(lines, start + 1)
        return _statement_end_index(lines, body_start) if body_start is not None else start + 1
    return start + 1


def _braced_statement_end_index(lines: list[str], start: int) -> int:
    depth = 0
    saw_open = False
    for index in range(start, len(lines)):
        stripped = lines[index].strip()
        opens = stripped.count("{")
        closes = stripped.count("}")
        if opens:
            depth += opens
            saw_open = True
        if closes:
            depth -= closes
            if saw_open and depth <= 0:
                return index + 1
    return len(lines)


def _matching_braced_block_start(lines: list[str], end_index: int) -> int:
    depth = 0
    for index in range(end_index, -1, -1):
        stripped = lines[index].strip()
        depth += stripped.count("}")
        depth -= stripped.count("{")
        if depth <= 0 and "{" in stripped:
            return index
    return -1


def _statement_lines(lines: list[str], start: int, end: int) -> list[str]:
    result: list[str] = []
    for line in lines[start:end]:
        stripped = line.strip()
        if stripped in {"{", "}"}:
            continue
        if stripped:
            result.append(stripped)
    return result


def _single_goto_label(lines: list[str]) -> str:
    statements = [line.strip() for line in lines if line.strip() and line.strip() not in {"{", "}"}]
    if len(statements) != 1:
        return ""
    match = _GOTO_LABEL_RE.search(statements[0])
    return match.group("label") if match else ""


def _label_tail_context(lines: list[str], label: str, max_lines: int) -> list[str]:
    label_re = re.compile(r"^\s*%s\s*:" % re.escape(label))
    for index, line in enumerate(lines):
        if not label_re.match(line):
            continue
        return _join_context_lines(lines, index, max_lines)
    return []


def _goto_label_tail_context(lines: list[str], label: str, max_lines: int) -> list[str]:
    label_re = re.compile(r"^\s*%s\s*:" % re.escape(label))
    for index, line in enumerate(lines):
        if not label_re.match(line):
            continue
        return _join_goto_tail_lines(lines, index, max_lines)
    return []


def _join_goto_tail_lines(lines: list[str], start: int, max_lines: int) -> list[str]:
    result: list[str] = []
    depth = 0
    previous = ""
    label_re = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:")
    for index in range(start, min(len(lines), start + max_lines)):
        stripped = lines[index].strip()
        if not stripped:
            continue
        if index > start and depth <= 0 and label_re.match(stripped):
            break
        result.append(stripped)
        opens = stripped.count("{")
        closes = stripped.count("}")
        depth += opens - closes
        if depth <= 0 and _is_terminal_return_line(stripped, previous):
            break
        previous = stripped
    return result


def _is_terminal_return_line(line: str, previous: str) -> bool:
    stripped = (line or "").strip()
    if not (stripped.startswith("return ") or stripped == "return;"):
        return False
    if (previous or "").strip().startswith("if"):
        return False
    return stripped.endswith(";")


def _join_context_lines(lines: list[str], start: int, max_lines: int) -> list[str]:
    result: list[str] = []
    depth = 0
    saw_open = False
    terminal_started = False
    for index in range(start, min(len(lines), start + max_lines)):
        stripped = lines[index].strip()
        if not stripped:
            continue
        if stripped in {"{", "}"} and not result:
            continue
        result.append(stripped)
        opens = stripped.count("{")
        closes = stripped.count("}")
        if opens:
            depth += opens
            saw_open = True
        if closes:
            depth -= closes
            if saw_open and depth <= 0 and stripped == "}":
                break
        if stripped.startswith("return ") or stripped == "return;":
            terminal_started = True
        if terminal_started and stripped.endswith(";"):
            break
    return result


def _case_context_has_buffer_evidence(lines: list[str]) -> bool:
    for line in lines:
        lowered = line.lower()
        if "length" in lowered or "buffer" in lowered or "information" in lowered:
            return True
        if "*" in line or "->" in line:
            return True
    return False


def _selected_case_body(
    capture: FunctionCapture,
    plan: CleanPlan,
    command_value: int,
    rename_map: dict[str, str] | None = None,
) -> tuple[FlowRewrite | None, list[str]]:
    text = capture.pseudocode or ""
    for flow in plan.flow_rewrites:
        if command_value not in set(flow.recovered_cases) and command_value not in flow.case_bodies:
            continue
        body_lines = _authoritative_case_body_lines(text, flow, command_value, rename_map or {})
        return flow, list(body_lines)
    return None, []


def _authoritative_case_body_lines(
    text: str,
    flow: FlowRewrite,
    command_value: int,
    rename_map: dict[str, str] | None = None,
) -> list[str]:
    renames = rename_map or {}
    source_variants = _case_body_source_variants(text, renames)
    for source in source_variants:
        body = _native_switch_case_bodies(source, flow.dispatcher).get(command_value)
        if body is not None:
            return _renamed_case_body_lines(body, renames)
    for source in source_variants:
        body = _case_body_from_anchor(source, command_value, flow.case_anchors.get(command_value, 0))
        if body is not None:
            return _renamed_case_body_lines(body, renames)
    return _renamed_case_body_lines(flow.case_bodies.get(command_value, []), renames)


def _case_body_source_variants(text: str, rename_map: dict[str, str]) -> list[str]:
    raw_text = text or ""
    if not rename_map:
        return [raw_text]
    renamed_text = safe_identifier_replace(raw_text, rename_map)
    if renamed_text == raw_text:
        return [raw_text]
    return [raw_text, renamed_text]


def _merged_case_bodies(
    native_bodies: dict[int, list[str]],
    flow_bodies: dict[int, list[str]],
) -> dict[int, list[str]]:
    merged = {value: list(lines) for value, lines in flow_bodies.items() if lines}
    for value, body in native_bodies.items():
        current = merged.get(value)
        if (
            _is_terminal_noncontract_case_body(body)
            or current is None
            or _native_case_body_score(body) > _native_case_body_score(current)
        ):
            merged[value] = list(body)
    return merged


def _is_terminal_noncontract_case_body(lines: list[str]) -> bool:
    significant = [
        line.strip()
        for line in lines
        if line.strip() and line.strip() not in {"{", "}"}
    ]
    if len(significant) != 1:
        return False
    line = significant[0]
    if "(" in line or ")" in line:
        return False
    if re.fullmatch(r"return\s+(?:0x[0-9A-Fa-f]+|\d+)(?:LL|i64|L|u|U)?\s*;", line):
        return True
    return bool(re.fullmatch(r"return\s+STATUS_[A-Za-z0-9_]+\s*;", line))


def _renamed_case_body_lines(lines: list[str], rename_map: dict[str, str]) -> list[str]:
    if not lines:
        return []
    if not rename_map:
        return list(lines)
    return safe_identifier_replace("\n".join(lines), rename_map).splitlines()


def _case_body_excerpt(lines: list[str], max_lines: int = 8) -> list[str]:
    result: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped in {"{", "}"}:
            continue
        result.append(stripped)
        if len(result) >= max_lines:
            break
    return result


def _case_body_from_anchor(text: str, command_value: int, anchor_line: int = 0) -> list[str] | None:
    lines = (text or "").splitlines()
    if not lines:
        return None
    candidate_indices = _case_anchor_candidate_indices(lines, command_value, anchor_line)
    for index in candidate_indices:
        body = _slice_case_body_from_label(lines, index)
        if body:
            return body
    return None


def _case_anchor_candidate_indices(lines: list[str], command_value: int, anchor_line: int) -> list[int]:
    result: list[int] = []
    if anchor_line > 0:
        start = max(0, anchor_line - 4)
        end = min(len(lines), anchor_line + 3)
        for index in range(start, end):
            if _line_matches_case_value(lines[index], command_value):
                result.append(index)
    for index, line in enumerate(lines):
        if _line_matches_case_value(line, command_value) and index not in result:
            result.append(index)
    return result


def _line_matches_case_value(line: str, command_value: int) -> bool:
    value = _case_value_from_line((line or "").strip())
    return value == command_value


def _slice_case_body_from_label(lines: list[str], case_index: int) -> list[str]:
    if case_index < 0 or case_index >= len(lines):
        return []
    result: list[str] = []
    first = lines[case_index].strip()
    first_match = _CASE_LABEL_RE.match(first)
    if first_match:
        remainder = first[first_match.end():].strip()
        if remainder and remainder not in {"{", "}"}:
            result.append(remainder)

    local_depth = 0
    for line in lines[case_index + 1:]:
        stripped = line.strip()
        if local_depth <= 0 and (_CASE_LABEL_RE.match(stripped) or _is_default_case_line(stripped)):
            break
        if local_depth <= 0 and stripped == "}":
            break
        if stripped:
            result.append(line.rstrip())
        local_depth += stripped.count("{") - stripped.count("}")
    return _trim_case_lines(result)


def _length_names_from_sources(sources: dict[str, dict[str, str]]) -> set[str]:
    result: set[str] = set()
    for info in sources.values():
        for name in str(info.get("length", "")).split(","):
            name = name.strip()
            if name:
                result.add(name)
    return result


def _length_like_names(text: str) -> set[str]:
    return {
        name
        for name in set(re.findall(r"\b%s\b" % _IDENT_RE, text or ""))
        if _looks_like_length_name(name)
    }


def _argument_references_any_name(argument: str, names: set[str]) -> bool:
    if not argument or not names:
        return False
    identifiers = set(re.findall(r"\b%s\b" % _IDENT_RE, argument))
    return bool(identifiers & names)


def _case_goto_labels(lines: list[str]) -> list[str]:
    result: list[str] = []
    for line in lines:
        match = _GOTO_LABEL_RE.search(line or "")
        if not match:
            continue
        label = match.group("label")
        if label not in result:
            result.append(label)
    return result


def _recover_case_context_accesses(capture: FunctionCapture, lines: list[str]) -> list[CaseContextAccess]:
    known_buffer_names = set(_infer_buffer_sources(capture.pseudocode or "", capture))
    result: list[CaseContextAccess] = []
    seen: set[tuple[str, int, str, str, str, str]] = set()
    for index, line in enumerate(lines):
        stripped = line.strip()
        left_expr = _assignment_left(stripped)
        reject_guard = _line_has_reject_or_case_exit_outcome(lines, index)
        for match in _CAST_OFFSET_ACCESS_RE.finditer(stripped):
            base = match.group("base")
            if base in known_buffer_names or _looks_like_buffer_name(base):
                continue
            offset = _parse_offset(match.group("offset") or "0")
            expression = match.group(0)
            access = _context_access_kind(stripped, left_expr, match.start(), expression)
            predicate = _context_valid_predicate(stripped, expression, reject_guard)
            item = CaseContextAccess(
                base=base,
                offset=offset,
                type=_normalize_context_type(match.group("type")),
                access=access,
                predicate=predicate,
                expression=expression,
                evidence=stripped,
            )
            key = (item.base, item.offset, item.type, item.access, item.predicate, item.evidence)
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
    return result


def _context_access_kind(line: str, left_expr: str, expression_start: int, expression: str) -> str:
    prefix = line[:expression_start].rstrip()
    is_deref = prefix.endswith("*")
    if is_deref and left_expr and expression in left_expr:
        return "write"
    if is_deref:
        return "read"
    if left_expr and expression in left_expr:
        return "write_address"
    return "address"


def _context_valid_predicate(line: str, expression: str, reject_guard: bool) -> str:
    if not reject_guard:
        return ""
    condition = _if_condition(line)
    if not condition:
        return ""
    deref_expression = "*%s" % expression
    if re.search(r"!\s*%s" % re.escape(deref_expression), condition):
        return "%s != 0" % deref_expression
    comparison = _comparison_valid_predicate(condition, deref_expression)
    if comparison:
        return comparison
    if expression in condition:
        return "guard expression evaluates to 0: %s" % condition
    return ""


def _comparison_valid_predicate(condition: str, expression: str) -> str:
    escaped = re.escape(expression)
    right_match = re.search(r"%s\s*(?P<op>==|!=|<=|>=|<|>)\s*(?P<value>%s)" % (escaped, _C_VALUE_RE), condition)
    if right_match:
        relation = _valid_relation_for_reject_guard(right_match.group("op"))
        return "%s %s %s" % (expression, relation, right_match.group("value")) if relation else ""
    left_match = re.search(r"(?P<value>%s)\s*(?P<op>==|!=|<=|>=|<|>)\s*%s" % (_C_VALUE_RE, escaped), condition)
    if left_match:
        relation = _valid_relation_for_reject_guard(_invert_relation(left_match.group("op")))
        return "%s %s %s" % (expression, relation, left_match.group("value")) if relation else ""
    return ""


def _if_condition(line: str) -> str:
    match = re.search(r"\bif\s*\(", line or "")
    if not match:
        return ""
    start = match.end()
    depth = 1
    for index in range(start, len(line)):
        char = line[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return line[start:index].strip()
    return ""


def _line_has_reject_or_case_exit_outcome(lines: list[str], index: int) -> bool:
    if _line_has_reject_outcome(lines, index):
        return True
    current = (lines[index] if 0 <= index < len(lines) else "").strip()
    if not current.startswith("if"):
        return False
    outcome_text = current + "\n" + _guard_outcome_window(lines, index) + "\n" + _linear_guard_outcome_window(lines, index)
    if not re.search(r"\b(?:goto|break|return)\b", outcome_text):
        return False
    return bool(
        re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:-\d+|0x[4C][0-9A-Fa-f]{7,})\s*;", outcome_text)
        or re.search(r"\breturn\s+(?:-\d+|0x[4C][0-9A-Fa-f]{7,})\s*;", outcome_text)
    )


def _linear_guard_outcome_window(lines: list[str], index: int, max_lines: int = 6) -> str:
    result: list[str] = []
    for line in lines[index + 1:index + 1 + max_lines]:
        stripped = line.strip()
        if not stripped or stripped in {"{", "}"}:
            continue
        if stripped.startswith(("case ", "default:", "if ", "else", "switch ")):
            break
        result.append(stripped)
        if re.search(r"\b(?:goto|break|return)\b", stripped):
            break
    return "\n".join(result)


def _normalize_context_type(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", (value or "").strip())
    if not cleaned:
        return "unknown"
    pointer_suffix = "*" * cleaned.count("*")
    base = cleaned.replace("*", " ")
    base = re.sub(r"\b(?:const|volatile)\b", "", base)
    base = re.sub(r"\s+", " ", base).strip()
    normalized = _normalize_c_type(base)
    if pointer_suffix:
        return "%s %s" % (normalized, pointer_suffix)
    return normalized


def render_buffer_struct_header(capture: FunctionCapture, contracts: list[CommandBufferContract]) -> str:
    lines = [
        "#pragma once",
        "",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "// Generated by PseudoForge buffer contract recovery.",
        "// Review inferred padding, direction, and predicates before using as ABI.",
        "",
        "#pragma pack(push, 1)",
        "",
    ]
    if not contracts:
        lines.extend(
            [
                "// No command buffer contracts were recovered for %s." % _cpp_comment(capture.name or "function"),
                "",
                "#pragma pack(pop)",
                "",
            ]
        )
        return "\n".join(lines)

    emitted: set[str] = set()
    for contract in contracts:
        for buffer in contract.buffers:
            if buffer.structure_name in emitted:
                continue
            emitted.add(buffer.structure_name)
            lines.extend(_render_single_buffer_struct(contract, buffer))

    if not emitted:
        lines.append("// No concrete buffer structures were inferred.")
        lines.append("")
    lines.append("#pragma pack(pop)")
    lines.append("")
    return "\n".join(lines)


def buffer_contracts_json_payload(contracts: list[CommandBufferContract]) -> list[dict[str, object]]:
    return json.loads(json.dumps([asdict(contract) for contract in contracts], ensure_ascii=True))


def _render_single_buffer_struct(contract: CommandBufferContract, buffer: BufferContract) -> list[str]:
    helper_sizes = _helper_size_constraints_for_buffer(contract.helper_edges, buffer.variable)
    helper_accesses = _helper_field_accesses_for_buffer(contract.helper_edges, buffer.variable)
    helper_fields = _helper_field_constraints_for_buffer(contract.helper_edges, buffer.variable)
    all_size_constraints = buffer.size_constraints + helper_sizes
    all_field_accesses = buffer.field_accesses + helper_accesses
    all_field_constraints = buffer.field_constraints + helper_fields
    fields = _build_cpp_fields(all_field_accesses, all_field_constraints)
    size_hint = _struct_size_hint(fields, all_size_constraints)
    exact_hint = _struct_exact_size_hint(all_size_constraints)
    size_predicates = _size_predicates_for_constraints(all_size_constraints)
    command_label = contract.command_name or ("0x%X" % contract.command_value)
    lines = [
        "// Command: %s (0x%X)" % (_cpp_comment(command_label), contract.command_value),
        "// Dispatcher: %s, buffer: %s, role: %s" % (
            _cpp_comment(contract.dispatcher),
            _cpp_comment(buffer.variable),
            _cpp_comment(buffer.role),
        ),
    ]
    if all_size_constraints:
        lines.append("// Size predicates:")
        for item in all_size_constraints:
            valid_text = ""
            if item.valid_relation and item.valid_value:
                valid_text = "; valid %s %s %s" % (
                    item.length or buffer.length_variable or "length",
                    item.valid_relation,
                    item.valid_value,
                )
            lines.append(
                "// - observed %s %s %s%s [%s]" % (
                    _cpp_comment(item.length or buffer.length_variable or "length"),
                    _cpp_comment(item.relation),
                    _cpp_comment(item.value),
                    _cpp_comment(valid_text),
                    _cpp_comment(item.source),
                )
            )
    named_unknowns = _named_unknown_field_notes(all_field_accesses)
    if named_unknowns:
        lines.append("// Named fields with unknown offsets:")
        for note in named_unknowns:
            lines.append("// - %s" % _cpp_comment(note))
    if size_predicates:
        lines.extend(_render_cpp_size_constants(buffer.structure_name, size_predicates))
    lines.append("struct %s" % buffer.structure_name)
    lines.append("{")
    lines.extend(_render_cpp_field_layout(fields, size_hint, size_predicates))
    lines.append("};")
    for field in fields:
        lines.append(
            "static_assert(offsetof(%s, %s) == 0x%X, \"%s.%s offset mismatch\");"
            % (
                buffer.structure_name,
                field["name"],
                field["offset"],
                buffer.structure_name,
                field["name"],
            )
        )
    lines.extend(_render_ioctl_role_aliases(contract, buffer))
    struct_size = max(size_hint, _fields_end_offset(fields))
    if exact_hint == 0 and struct_size == 0:
        lines.append("// Exact-size predicate is 0; C++ empty structs have non-zero sizeof.")
    elif exact_hint is not None and exact_hint == struct_size:
        lines.append(
            "static_assert(sizeof(%s) == 0x%X, \"%s size mismatch\");"
            % (buffer.structure_name, exact_hint, buffer.structure_name)
        )
    else:
        minimum_struct_size = max(struct_size, 1)
        lines.append(
            "static_assert(sizeof(%s) >= 0x%X, \"%s minimum size mismatch\");"
            % (buffer.structure_name, minimum_struct_size, buffer.structure_name)
        )
        if exact_hint is not None:
            lines.append(
                "// Exact-size predicate observed for 0x%X, but inferred fields require 0x%X bytes."
                % (exact_hint, struct_size)
            )
    if size_predicates:
        lines.append("")
        lines.extend(_render_cpp_size_validator(buffer.structure_name, size_predicates))
    lines.append("")
    return lines


def _render_ioctl_role_aliases(contract: CommandBufferContract, buffer: BufferContract) -> list[str]:
    if contract.dispatcher_kind != "ioctl":
        return []
    prefix = "PF_IOCTL_%08X" % (contract.command_value & 0xFFFFFFFF)
    aliases: list[str] = []
    if buffer.role in {"input", "inout"}:
        aliases.append("using %s_REQUEST = %s;" % (prefix, buffer.structure_name))
    if buffer.role in {"output", "inout"}:
        aliases.append("using %s_RESPONSE = %s;" % (prefix, buffer.structure_name))
    return aliases


def _case_value_from_line(line: str) -> int | None:
    match = _CASE_LABEL_RE.search((line or "").strip())
    if not match:
        return None
    return _parse_case_label_value(match.group("value"))


def _parse_case_label_value(value: str) -> int | None:
    token = (value or "").strip()
    if not token:
        return None
    if "|" in token:
        result = 0
        for term in token.split("|"):
            parsed = _parse_case_label_value(term)
            if parsed is None:
                return None
            result |= parsed
        return result
    parsed = parse_c_integer_literal(token)
    if parsed is not None:
        return parsed
    for resolver in (
        get_process_information_class_value,
        get_system_information_class_value,
        get_thread_information_class_value,
    ):
        parsed = resolver(token)
        if parsed is not None:
            return parsed
    return None


def _is_default_case_line(line: str) -> bool:
    return bool(re.match(r"^\s*default\s*:", line or ""))


def _build_cpp_fields(
    accesses: list[FieldAccess],
    constraints: list[FieldConstraint],
) -> list[dict[str, object]]:
    fields: dict[int, dict[str, object]] = {}
    for access in accesses:
        if not _access_has_layout_offset(access):
            continue
        item = fields.setdefault(access.offset, _new_cpp_field(access.offset))
        item["name"] = _cpp_field_name(access.field, access.offset)
        candidate_type = _cpp_type(access.type)
        if not item["accesses"] and not item["constraints"] and not item["sources"]:
            item["type"] = candidate_type
            item["size"] = _cpp_type_size(candidate_type)
        else:
            item["type"] = _preferred_cpp_type(str(item["type"]), access.type)
            item["size"] = max(int(item["size"]), _cpp_type_size(str(item["type"])))
        _append_unique(item["accesses"], access.access)
        _append_unique(item["sources"], access.source)
        if access.evidence:
            _append_unique(item["evidence"], access.evidence)
    for constraint in constraints:
        if constraint.offset < 0:
            continue
        item = fields.setdefault(constraint.offset, _new_cpp_field(constraint.offset))
        item["name"] = _cpp_field_name(constraint.field, constraint.offset)
        _append_unique(
            item["constraints"],
            _constraint_comment(constraint),
        )
        _append_unique(item["sources"], constraint.source)
        if constraint.evidence:
            _append_unique(item["evidence"], constraint.evidence)
    return [fields[offset] for offset in sorted(fields)]


def _new_cpp_field(offset: int) -> dict[str, object]:
    return {
        "offset": offset,
        "name": _field_name(offset),
        "type": "std::uint32_t",
        "size": 4,
        "accesses": [],
        "constraints": [],
        "sources": [],
        "evidence": [],
    }


def _render_cpp_field_layout(
    fields: list[dict[str, object]],
    size_hint: int,
    size_predicates: list[_SizePredicate] | None = None,
) -> list[str]:
    if not fields:
        size_only = _render_size_only_byte_layout(size_hint, size_predicates or [])
        if size_only:
            return size_only

    lines: list[str] = []
    cursor = 0
    reserved_index = 0
    for field in fields:
        offset = int(field["offset"])
        size = int(field["size"])
        if offset < cursor:
            lines.append("    // Overlapping field skipped at 0x%X: %s" % (offset, _cpp_comment(str(field["name"]))))
            continue
        if offset > cursor:
            lines.append(
                "    std::uint8_t reserved_0x%02X[%d];"
                % (cursor, offset - cursor)
            )
            reserved_index += 1
        _extend_field_comments(lines, field)
        lines.append("    %s %s;" % (field["type"], field["name"]))
        cursor = offset + size
    target_size = max(size_hint, cursor)
    if target_size > cursor:
        lines.append(
            "    std::uint8_t reserved_0x%02X[%d];"
            % (cursor, target_size - cursor)
        )
        reserved_index += 1
    if not fields and target_size <= 0 and _has_exact_zero_size_predicate(size_predicates or []):
        lines.append("    // No bytes are accepted for this buffer role.")
    elif not fields and target_size <= 0:
        lines.append("    // Layout was not recovered for this buffer role.")
    elif not fields and reserved_index == 0:
        lines.append("    std::uint8_t reserved_0x00[%d];" % target_size)
    return lines


def _render_size_only_byte_layout(size_hint: int, size_predicates: list[_SizePredicate]) -> list[str]:
    bounds = _lower_size_bounds_by_role(size_predicates)
    input_size = bounds.get("input", 0)
    output_size = bounds.get("output", 0)
    target_size = max(size_hint, input_size, output_size)
    lines: list[str] = []
    if input_size and output_size:
        common_size = min(input_size, output_size)
        if common_size:
            lines.append("    // Size-only byte range; no field offsets were recovered.")
            lines.append("    std::uint8_t inout_bytes_0x00[%s];" % _format_cpp_size_literal(common_size))
        cursor = common_size
        if input_size > cursor:
            lines.append(
                "    std::uint8_t input_extension_0x%02X[%s];"
                % (cursor, _format_cpp_size_literal(input_size - cursor))
            )
            cursor = input_size
        if output_size > cursor:
            lines.append(
                "    std::uint8_t output_extension_0x%02X[%s];"
                % (cursor, _format_cpp_size_literal(output_size - cursor))
            )
            cursor = output_size
        if target_size > cursor:
            lines.append(
                "    std::uint8_t reserved_0x%02X[%s];"
                % (cursor, _format_cpp_size_literal(target_size - cursor))
            )
        return lines
    if input_size:
        lines.append("    // Size-only input byte range; no field offsets were recovered.")
        lines.append("    std::uint8_t input_bytes_0x00[%s];" % _format_cpp_size_literal(input_size))
        if target_size > input_size:
            lines.append(
                "    std::uint8_t reserved_0x%02X[%s];"
                % (input_size, _format_cpp_size_literal(target_size - input_size))
            )
        return lines
    if output_size:
        lines.append("    // Size-only output byte range; no field offsets were recovered.")
        lines.append("    std::uint8_t output_bytes_0x00[%s];" % _format_cpp_size_literal(output_size))
        if target_size > output_size:
            lines.append(
                "    std::uint8_t reserved_0x%02X[%s];"
                % (output_size, _format_cpp_size_literal(target_size - output_size))
            )
        return lines
    return []


def _lower_size_bounds_by_role(size_predicates: list[_SizePredicate]) -> dict[str, int]:
    result: dict[str, int] = {}
    for predicate in size_predicates:
        if predicate.relation == "==":
            result[predicate.role] = max(result.get(predicate.role, 0), predicate.value)
        elif predicate.relation == ">=":
            result[predicate.role] = max(result.get(predicate.role, 0), predicate.value)
    return result


def _has_exact_zero_size_predicate(size_predicates: list[_SizePredicate]) -> bool:
    return any(predicate.relation == "==" and predicate.value == 0 for predicate in size_predicates)


def _extend_field_comments(lines: list[str], field: dict[str, object]) -> None:
    comments = []
    accesses = ", ".join(str(item) for item in field["accesses"])
    if accesses:
        comments.append("access: %s" % accesses)
    constraints = "; ".join(str(item) for item in field["constraints"])
    if constraints:
        comments.append("predicates: %s" % constraints)
    sources = ", ".join(str(item) for item in field["sources"])
    if sources:
        comments.append("source: %s" % sources)
    evidence = "; ".join(str(item) for item in list(field["evidence"])[:2])
    if evidence:
        comments.append("evidence: %s" % evidence)
    if comments:
        lines.append("    // %s" % _cpp_comment(" | ".join(comments)))


def _helper_size_constraints_for_buffer(edges: list[HelperContractEdge], buffer: str) -> list[BufferSizeConstraint]:
    result: list[BufferSizeConstraint] = []
    for edge in edges:
        for item in edge.propagated_size_constraints:
            if item.buffer == buffer:
                result.append(item)
        result.extend(_helper_size_constraints_for_buffer(edge.nested_edges, buffer))
    return result


def _helper_field_accesses_for_buffer(edges: list[HelperContractEdge], buffer: str) -> list[FieldAccess]:
    result: list[FieldAccess] = []
    for edge in edges:
        for item in edge.propagated_field_accesses:
            if item.buffer == buffer:
                result.append(item)
        result.extend(_helper_field_accesses_for_buffer(edge.nested_edges, buffer))
    return result


def _helper_field_constraints_for_buffer(edges: list[HelperContractEdge], buffer: str) -> list[FieldConstraint]:
    result: list[FieldConstraint] = []
    for edge in edges:
        for item in edge.propagated_field_constraints:
            if item.buffer == buffer:
                result.append(item)
        result.extend(_helper_field_constraints_for_buffer(edge.nested_edges, buffer))
    return result


def _struct_size_hint(fields: list[dict[str, object]], constraints: list[BufferSizeConstraint]) -> int:
    result = _fields_end_offset(fields)
    for constraint in constraints:
        value = _parse_constraint_integer(constraint.value)
        if value is not None:
            result = max(result, value)
    return result


def _struct_exact_size_hint(constraints: list[BufferSizeConstraint]) -> int | None:
    hints = []
    for constraint in constraints:
        if constraint.relation not in {"==", "!="}:
            continue
        value = _parse_constraint_integer(constraint.value)
        if value is not None:
            hints.append(value)
    return hints[0] if hints and len(set(hints)) == 1 else None


def _size_predicates_for_constraints(constraints: list[BufferSizeConstraint]) -> list[_SizePredicate]:
    exact_by_role: dict[str, list[_SizePredicate]] = {}
    min_by_role: dict[str, _SizePredicate] = {}
    max_by_role: dict[str, _SizePredicate] = {}
    for constraint in constraints:
        predicate = _size_predicate_from_constraint(constraint)
        if predicate is None:
            continue
        if predicate.relation == "==":
            exact_by_role.setdefault(predicate.role, []).append(predicate)
        elif predicate.relation == ">=":
            current = min_by_role.get(predicate.role)
            if current is None or predicate.value > current.value:
                min_by_role[predicate.role] = predicate
        elif predicate.relation == "<=":
            current = max_by_role.get(predicate.role)
            if current is None or predicate.value < current.value:
                max_by_role[predicate.role] = predicate

    result: list[_SizePredicate] = []
    for role in sorted(set(exact_by_role) | set(min_by_role) | set(max_by_role), key=_size_role_sort_key):
        exacts = exact_by_role.get(role, [])
        if exacts:
            seen_exact_values: set[int] = set()
            for item in sorted(exacts, key=lambda predicate: predicate.value):
                if item.value in seen_exact_values:
                    continue
                seen_exact_values.add(item.value)
                result.append(item)
            continue
        if role in min_by_role:
            result.append(min_by_role[role])
        if role in max_by_role:
            result.append(max_by_role[role])
    return result


def _size_predicate_from_constraint(constraint: BufferSizeConstraint) -> _SizePredicate | None:
    relation = constraint.valid_relation
    value_text = constraint.valid_value
    if not relation and constraint.relation == "==":
        relation = constraint.relation
        value_text = constraint.value
    if not relation or not value_text:
        return None
    value = _parse_constraint_integer(value_text)
    if value is None:
        return None
    normalized_relation = relation
    normalized_value = value
    if relation == ">":
        normalized_relation = ">="
        normalized_value = value + 1
    elif relation == "<":
        if value <= 0:
            return None
        normalized_relation = "<="
        normalized_value = value - 1
    if normalized_relation not in {"==", ">=", "<="}:
        return None
    role = constraint.role or _role_from_length(constraint.length)
    if role not in {"input", "output"}:
        role = _role_from_length(constraint.length)
    return _SizePredicate(
        role=role,
        length=constraint.length,
        relation=normalized_relation,
        value=normalized_value,
    )


def _size_role_sort_key(role: str) -> tuple[int, str]:
    return ({"input": 0, "output": 1}.get(role, 9), role)


def _fields_end_offset(fields: list[dict[str, object]]) -> int:
    result = 0
    for field in fields:
        result = max(result, int(field["offset"]) + int(field["size"]))
    return result


def _parse_constraint_integer(value: str) -> int | None:
    if not value or value.startswith("sizeof"):
        return None
    return parse_c_integer_literal(value)


def _access_has_layout_offset(access: FieldAccess) -> bool:
    if access.field.startswith("field_0x"):
        return True
    if "profile:" in (access.source or "") and access.type and access.type != "unknown":
        return True
    return bool("*" in access.evidence and access.type and access.type != "unknown")


def _named_unknown_field_notes(accesses: list[FieldAccess]) -> list[str]:
    result = []
    for access in accesses:
        if _access_has_layout_offset(access):
            continue
        result.append("%s %s (%s)" % (access.access, access.field, access.evidence))
    return result


def _preferred_cpp_type(current: str, candidate: str) -> str:
    candidate_cpp = _cpp_type(candidate)
    if current == "std::uint32_t":
        return candidate_cpp
    if _cpp_type_size(candidate_cpp) > _cpp_type_size(current):
        return candidate_cpp
    return current


def _cpp_type(type_text: str) -> str:
    normalized = _normalize_c_type(type_text)
    aliases = {
        "UCHAR": "std::uint8_t",
        "CHAR": "std::int8_t",
        "BOOLEAN": "std::uint8_t",
        "USHORT": "std::uint16_t",
        "SHORT": "std::int16_t",
        "ULONG": "std::uint32_t",
        "LONG": "std::int32_t",
        "int": "std::int32_t",
        "unsigned int": "std::uint32_t",
        "ULONGLONG": "std::uint64_t",
        "LONGLONG": "std::int64_t",
        "SIZE_T": "std::uintptr_t",
        "ULONG_PTR": "std::uintptr_t",
        "PVOID": "void *",
        "HANDLE": "void *",
        "void": "void *",
        "unknown": "std::uint32_t",
        "": "std::uint32_t",
    }
    return aliases.get(normalized, normalized)


def _cpp_type_size(type_text: str) -> int:
    if type_text in {"std::uint8_t", "std::int8_t"}:
        return 1
    if type_text in {"std::uint16_t", "std::int16_t"}:
        return 2
    if type_text in {"std::uint32_t", "std::int32_t"}:
        return 4
    return 8


def _cpp_field_name(field: str, offset: int) -> str:
    candidate = field if field else _field_name(offset)
    candidate = re.sub(r"[^A-Za-z0-9_]", "_", candidate).strip("_")
    if not candidate or candidate[0].isdigit():
        candidate = _field_name(offset)
    return candidate


def _constraint_comment(constraint: FieldConstraint) -> str:
    detail = constraint.value if constraint.value else constraint.mask
    if constraint.mask and constraint.value:
        detail = "%s, value %s" % (constraint.mask, constraint.value)
    observed = "observed %s %s %s" % (constraint.field, constraint.relation, detail)
    if constraint.valid_relation and constraint.valid_value:
        return "%s; valid %s %s %s" % (
            observed,
            constraint.field,
            constraint.valid_relation,
            constraint.valid_value,
        )
    return observed


def _append_unique(items: object, value: str) -> None:
    if not value:
        return
    values = items
    if not isinstance(values, list):
        return
    if value not in values:
        values.append(value)


def _cpp_comment(value: str) -> str:
    return re.sub(r"\s+", " ", sanitize_generated_comment_text(value)).strip()


def _render_cpp_size_constants(structure_name: str, predicates: list[_SizePredicate]) -> list[str]:
    lines = ["// Size contract constants:"]
    for predicate in predicates:
        lines.append(
            "static constexpr std::size_t %s = %s;"
            % (
                _size_constant_name(structure_name, predicate, predicates),
                _format_cpp_size_literal(predicate.value),
            )
        )
    lines.append("")
    return lines


def _render_cpp_size_validator(structure_name: str, predicates: list[_SizePredicate]) -> list[str]:
    parameters: list[str] = []
    used_parameter_names: set[str] = set()
    parameter_by_key: dict[tuple[str, str], str] = {}
    exact_conditions: dict[str, list[str]] = {}
    range_conditions: list[str] = []
    for predicate in predicates:
        parameter_key = (predicate.role, predicate.length)
        parameter_name = parameter_by_key.get(parameter_key, "")
        if not parameter_name:
            parameter_name = _size_parameter_name(predicate, used_parameter_names)
            parameter_by_key[parameter_key] = parameter_name
            parameters.append("std::size_t %s" % parameter_name)
        condition = (
            "%s %s %s"
            % (
                parameter_name,
                predicate.relation,
                _size_constant_name(structure_name, predicate, predicates),
            )
        )
        if predicate.relation == "==":
            exact_conditions.setdefault(parameter_name, []).append(condition)
        else:
            range_conditions.append(condition)
    conditions: list[str] = []
    for parameter_name in parameter_by_key.values():
        alternatives = exact_conditions.get(parameter_name, [])
        if len(alternatives) > 1:
            conditions.append("(%s)" % " || ".join(alternatives))
        elif alternatives:
            conditions.append(alternatives[0])
    conditions.extend(range_conditions)
    lines = [
        "inline bool IsValid%sSize(%s)" % (structure_name, ", ".join(parameters)),
        "{",
    ]
    if not conditions:
        lines.append("    return true;")
    elif len(conditions) == 1:
        lines.append("    return %s;" % conditions[0])
    else:
        lines.append("    return %s" % conditions[0])
        for condition in conditions[1:-1]:
            lines.append("        && %s" % condition)
        lines.append("        && %s;" % conditions[-1])
    lines.append("}")
    return lines


def _size_constant_name(
    structure_name: str,
    predicate: _SizePredicate,
    predicates: list[_SizePredicate] | None = None,
) -> str:
    relation_prefix = {
        "==": "",
        ">=": "MIN_",
        "<=": "MAX_",
    }.get(predicate.relation, "")
    if predicate.relation == "==" and _has_multiple_exact_sizes_for_role(predicates or [], predicate.role):
        return "%s_%s_SIZE_0x%X" % (structure_name, predicate.role.upper(), predicate.value)
    if predicate.relation == "==" and structure_name.upper().endswith("_%s" % predicate.role.upper()):
        return "%s_SIZE" % structure_name
    return "%s_%s%s_SIZE" % (structure_name, relation_prefix, predicate.role.upper())


def _has_multiple_exact_sizes_for_role(predicates: list[_SizePredicate], role: str) -> bool:
    values = {
        predicate.value
        for predicate in predicates
        if predicate.relation == "==" and predicate.role == role
    }
    return len(values) > 1


def _size_parameter_name(predicate: _SizePredicate, used_names: set[str]) -> str:
    fallback = "%sLength" % predicate.role
    candidate = _cpp_identifier(predicate.length, fallback)
    if candidate in used_names:
        candidate = fallback
    if candidate in used_names:
        index = 2
        while "%s%d" % (candidate, index) in used_names:
            index += 1
        candidate = "%s%d" % (candidate, index)
    used_names.add(candidate)
    return candidate


def _cpp_identifier(value: str, fallback: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_]", "_", value or "").strip("_")
    if not candidate or candidate[0].isdigit():
        candidate = fallback
    return candidate


def _format_cpp_size_literal(value: int) -> str:
    return "0x%X" % value


def _analyze_command_case(
    kind: str,
    dispatcher: str,
    command_value: int,
    command_name: str,
    body_lines: list[str],
    buffer_sources: dict[str, dict[str, str]],
    helper_map: dict[str, FunctionCapture],
    max_depth: int,
    depth: int,
    visited: set[str],
    length_aliases: dict[str, str] | None = None,
    disasm_evidence: DisasmCaseContractEvidence | None = None,
    disasm_helper_slices: dict[str, DisasmCaseSlice] | None = None,
) -> CommandBufferContract:
    body_text = "\n".join(body_lines)
    size_constraints = _recover_size_constraints(
        body_lines,
        length_aliases=length_aliases,
        known_lengths=_length_names_from_sources(buffer_sources),
    )
    field_accesses = _recover_field_accesses(body_lines, buffer_sources)
    field_constraints = _recover_field_constraints(body_lines, field_accesses)
    helper_edges = _recover_helper_edges(
        body_text,
        buffer_sources,
        helper_map,
        max_depth=max_depth,
        depth=depth,
        visited=visited,
    )
    merge_warnings: list[str] = []
    if disasm_evidence is not None:
        disasm_edges = _resolve_disasm_helper_edges(
            disasm_evidence.helper_edges,
            helper_map,
            max_depth=max_depth,
            depth=depth,
            visited=visited,
            disasm_helper_slices=disasm_helper_slices,
        )
        merge_warnings = _disasm_merge_warnings(
            size_constraints,
            disasm_evidence.size_constraints,
            field_accesses,
            disasm_evidence.field_accesses,
            field_constraints,
            disasm_evidence.field_constraints,
        )
        size_constraints = _merge_size_constraints(size_constraints, disasm_evidence.size_constraints)
        field_accesses = _merge_field_access_lists(field_accesses, disasm_evidence.field_accesses)
        field_constraints = _dedupe_field_constraints(field_constraints + disasm_evidence.field_constraints)
        helper_edges = _merge_helper_edge_lists(helper_edges, disasm_edges)
    alias_roots = _buffer_alias_roots(buffer_sources)
    helper_edges = [_canonical_helper_edge(edge, alias_roots) for edge in helper_edges]
    buffers = _build_buffer_contracts(
        kind,
        command_value,
        command_name,
        buffer_sources,
        size_constraints,
        field_accesses,
        field_constraints,
        helper_edges,
    )
    warnings = _contract_warnings(kind, command_value, buffers, size_constraints, field_accesses, helper_edges)
    warnings = _dedupe_strings(warnings + merge_warnings + (disasm_evidence.warnings if disasm_evidence else []))
    confidence = _command_confidence(buffers, helper_edges, warnings)
    if disasm_evidence is not None and _has_pseudocode_disasm_agreement(size_constraints, field_accesses):
        confidence = round(min(0.95, confidence + 0.04), 2)
    evidence = "Recovered from case body predicates and buffer field accesses"
    if disasm_evidence is not None:
        evidence = "Recovered from merged pseudocode and disassembly evidence"
    return CommandBufferContract(
        dispatcher_kind=kind,
        dispatcher=dispatcher,
        command_value=command_value,
        command_name=command_name,
        buffers=buffers,
        helper_edges=helper_edges,
        warnings=warnings,
        confidence=confidence,
        evidence=evidence,
    )


def _recover_focused_native_switch_contracts(
    capture: FunctionCapture,
    text: str,
    case_values: list[int],
    buffer_sources: dict[str, dict[str, str]],
    helper_map: dict[str, FunctionCapture],
    max_depth: int,
    length_aliases: dict[str, str],
    helper_interesting_names: set[str],
    disasm_evidence_by_case: dict[int, DisasmCaseContractEvidence] | None = None,
    disasm_helper_slices: dict[str, DisasmCaseSlice] | None = None,
) -> list[CommandBufferContract]:
    result: list[CommandBufferContract] = []
    recovered: set[int] = set()
    for dispatcher in _native_switch_dispatchers(text):
        flow = FlowRewrite(
            kind="native_switch_focused_fallback",
            dispatcher=dispatcher,
            recovered_cases=list(case_values),
            confidence=0.45,
            evidence="Focused fallback recovered native switch case body",
        )
        kind = _dispatcher_kind(capture, flow)
        if kind == "generic" and not _has_strong_generic_buffer_evidence(text):
            continue
        case_bodies = _native_switch_case_bodies(text, dispatcher)
        if not case_bodies:
            continue
        for value in case_values:
            if value in recovered:
                continue
            body_lines = case_bodies.get(value)
            if not body_lines:
                continue
            if _is_terminal_noncontract_case_body(body_lines):
                recovered.add(value)
                continue
            body_lines = _body_lines_with_shared_tail_size_guards(
                text,
                dispatcher,
                body_lines,
                buffer_sources,
                length_aliases,
            )
            if not _case_body_has_contract_evidence(body_lines, buffer_sources, length_aliases):
                body_lines = _body_lines_with_goto_label_tail_context(
                    text,
                    body_lines,
                    buffer_sources,
                    length_aliases,
                )
            if (
                not _case_body_has_contract_evidence(body_lines, buffer_sources, length_aliases)
                and not _case_body_has_helper_argument_evidence(body_lines, helper_interesting_names)
            ):
                body_lines = _body_lines_with_goto_label_helper_context(
                    text,
                    body_lines,
                    helper_interesting_names,
                )
            if (
                not _case_body_has_contract_evidence(body_lines, buffer_sources, length_aliases)
                and not _case_body_has_helper_argument_evidence(body_lines, helper_interesting_names)
            ):
                body_lines = _body_lines_with_dispatcher_condition_context(
                    text,
                    dispatcher,
                    value,
                    _command_name_for_kind(kind, value),
                    body_lines,
                )
            command_name = _command_name_for_kind(kind, value)
            if not command_name and kind == "ioctl":
                command_name = format_ctl_code(value)
            command = _analyze_command_case(
                kind,
                dispatcher,
                value,
                command_name,
                body_lines,
                buffer_sources,
                helper_map,
                max_depth=max_depth,
                depth=0,
                visited={capture.name},
                length_aliases=length_aliases,
                disasm_evidence=(disasm_evidence_by_case or {}).get(value),
                disasm_helper_slices=disasm_helper_slices,
            )
            if command.buffers or command.helper_edges:
                result.append(command)
                recovered.add(value)
    return result


def _recover_focused_disasm_contracts(
    capture: FunctionCapture,
    text: str,
    case_values: list[int],
    buffer_sources: dict[str, dict[str, str]],
    helper_map: dict[str, FunctionCapture],
    max_depth: int,
    length_aliases: dict[str, str],
    disasm_evidence_by_case: dict[int, DisasmCaseContractEvidence],
    disasm_helper_slices: dict[str, DisasmCaseSlice] | None = None,
) -> list[CommandBufferContract]:
    result: list[CommandBufferContract] = []
    native_dispatchers = _native_switch_dispatchers(text)
    for value in case_values:
        evidence = disasm_evidence_by_case.get(value)
        if evidence is None:
            continue
        dispatcher = evidence.dispatcher or (native_dispatchers[0] if native_dispatchers else "")
        flow = FlowRewrite(
            kind="disasm_focused_fallback",
            dispatcher=dispatcher,
            recovered_cases=[value],
            confidence=0.50,
            evidence=evidence.evidence or "Focused fallback recovered disassembly case evidence",
        )
        kind = _dispatcher_kind(capture, flow)
        command_name = _command_name_for_kind(kind, value)
        if not command_name and kind == "ioctl":
            command_name = format_ctl_code(value)
        command = _analyze_command_case(
            kind,
            dispatcher,
            value,
            command_name,
            [],
            buffer_sources,
            helper_map,
            max_depth=max_depth,
            depth=0,
            visited={capture.name},
            length_aliases=length_aliases,
            disasm_evidence=evidence,
            disasm_helper_slices=disasm_helper_slices,
        )
        if command.buffers or command.helper_edges:
            result.append(command)
    return result


def _recover_disasm_evidence_by_case(
    disasm_case_slices: Iterable[DisasmCaseSlice] | dict[int, DisasmCaseSlice] | None,
    buffer_sources: dict[str, dict[str, str]],
    length_aliases: dict[str, str],
    rename_map: dict[str, str],
    case_filter: set[int] | None,
) -> dict[int, DisasmCaseContractEvidence]:
    if case_filter is None:
        return {}
    slice_map = normalize_disasm_slices(disasm_case_slices)
    if not slice_map:
        return {}
    result: dict[int, DisasmCaseContractEvidence] = {}
    for value in sorted(case_filter):
        case_slice = slice_map.get(value)
        if case_slice is None:
            continue
        evidence = recover_disasm_case_evidence(
            case_slice,
            buffer_sources,
            length_aliases=length_aliases,
            rename_map=rename_map,
        )
        if (
            evidence.size_constraints
            or evidence.field_accesses
            or evidence.field_constraints
            or evidence.helper_edges
            or evidence.warnings
        ):
            result[value] = evidence
    return result


def _disasm_helper_slices_by_name(
    disasm_case_slices: Iterable[DisasmCaseSlice] | dict[int, DisasmCaseSlice] | None,
    capture: FunctionCapture,
) -> dict[str, DisasmCaseSlice]:
    result: dict[str, DisasmCaseSlice] = {}
    for item in _iter_disasm_slices(disasm_case_slices):
        name = (item.function_name or "").strip()
        if not name or name == capture.name:
            continue
        result[name] = item
    return result


def _iter_disasm_slices(
    disasm_case_slices: Iterable[DisasmCaseSlice] | dict[int, DisasmCaseSlice] | None,
) -> list[DisasmCaseSlice]:
    if disasm_case_slices is None:
        return []
    if isinstance(disasm_case_slices, dict):
        return [item for item in disasm_case_slices.values() if item is not None]
    return [item for item in disasm_case_slices if item is not None]


def _resolve_disasm_helper_edges(
    edges: list[HelperContractEdge],
    helper_map: dict[str, FunctionCapture],
    max_depth: int,
    depth: int,
    visited: set[str],
    disasm_helper_slices: dict[str, DisasmCaseSlice] | None = None,
) -> list[HelperContractEdge]:
    result: list[HelperContractEdge] = []
    for edge in edges:
        helper = helper_map.get(edge.callee)
        if helper is None and depth < max_depth:
            helper_slice = (disasm_helper_slices or {}).get(edge.callee)
            if helper_slice is not None:
                result.append(
                    _analyze_disasm_helper_edge(
                        helper_slice,
                        edge,
                        max_depth=max_depth,
                        depth=depth + 1,
                    )
                )
                continue
        if helper is None or depth >= max_depth:
            result.append(edge)
            continue
        if helper.name in visited:
            result.append(
                HelperContractEdge(
                    callee=edge.callee,
                    arguments=list(edge.arguments),
                    passed_buffers=list(edge.passed_buffers),
                    resolved=False,
                    depth=depth + 1,
                    evidence=edge.evidence,
                    warnings=["recursive helper edge skipped"],
                    confidence=0.40,
                )
            )
            continue
        resolved = _analyze_helper_edge(
            helper,
            list(edge.arguments),
            list(edge.passed_buffers),
            helper_map,
            max_depth,
            depth + 1,
            visited | {helper.name},
        )
        resolved.evidence = edge.evidence
        result.append(resolved)
    return result


def _analyze_disasm_helper_edge(
    helper_slice: DisasmCaseSlice,
    edge: HelperContractEdge,
    max_depth: int,
    depth: int,
) -> HelperContractEdge:
    helper_sources: dict[str, dict[str, str]] = {}
    for buffer in edge.passed_buffers:
        _add_buffer_source(
            helper_sources,
            buffer,
            "inout",
            "helper disasm argument",
            _length_arguments_for_buffer(edge.arguments, buffer),
        )
    initial_aliases = _x64_call_initial_aliases(edge.arguments)
    evidence = recover_disasm_case_evidence(
        helper_slice,
        helper_sources,
        initial_aliases=initial_aliases,
        max_instructions=512,
    )
    nested_edges = []
    if depth < max_depth:
        nested_edges = list(evidence.helper_edges)
    return HelperContractEdge(
        callee=edge.callee,
        arguments=list(edge.arguments),
        passed_buffers=list(edge.passed_buffers),
        resolved=True,
        depth=depth,
        evidence=edge.evidence,
        propagated_size_constraints=[
            _constraint_for_buffer(item, _constraint_buffer_from_sources(item, helper_sources))
            for item in evidence.size_constraints
            if _constraint_buffer_from_sources(item, helper_sources)
        ],
        propagated_field_accesses=list(evidence.field_accesses),
        propagated_field_constraints=list(evidence.field_constraints),
        nested_edges=nested_edges,
        warnings=list(evidence.warnings),
        confidence=0.74
        if evidence.size_constraints or evidence.field_accesses or evidence.field_constraints or evidence.helper_edges
        else 0.55,
    )


def _x64_call_initial_aliases(arguments: list[str]) -> dict[str, str]:
    registers = ("rcx", "rdx", "r8", "r9")
    result: dict[str, str] = {}
    for index, argument in enumerate(arguments[:len(registers)]):
        identifier = _argument_identifier(argument) or argument
        if identifier:
            result[registers[index]] = identifier
    for index, argument in enumerate(arguments[len(registers):]):
        identifier = _argument_identifier(argument) or argument
        if identifier:
            result["[rsp+0x%X]" % (0x20 + index * 8)] = identifier
    return result


def _merge_size_constraints(
    primary: list[BufferSizeConstraint],
    secondary: list[BufferSizeConstraint],
) -> list[BufferSizeConstraint]:
    result: list[BufferSizeConstraint] = []
    for item in primary + secondary:
        current = _find_equivalent_size_constraint(result, item)
        if current is None:
            result.append(item)
            continue
        current.source = _merge_source_text(current.source, item.source)
        current.confidence = max(current.confidence, item.confidence)
        if _source_is_disasm(item.source) and item.evidence:
            current.evidence = _merge_evidence_text(current.evidence, item.evidence)
    return result


def _find_equivalent_size_constraint(
    items: list[BufferSizeConstraint],
    candidate: BufferSizeConstraint,
) -> BufferSizeConstraint | None:
    for item in items:
        if (
            item.length == candidate.length
            and item.relation == candidate.relation
            and item.value == candidate.value
            and item.valid_relation == candidate.valid_relation
            and item.valid_value == candidate.valid_value
            and item.role == candidate.role
        ):
            return item
    return None


def _merge_field_access_lists(
    primary: list[FieldAccess],
    secondary: list[FieldAccess],
) -> list[FieldAccess]:
    result: dict[tuple[str, int, str, str], FieldAccess] = {}
    for item in primary + secondary:
        key = (item.buffer, item.offset, item.field, item.type)
        current = result.get(key)
        if current is None:
            result[key] = item
            continue
        if current.access != item.access:
            current.access = "read_write"
        current.source = _merge_source_text(current.source, item.source)
        current.confidence = max(current.confidence, item.confidence)
        if _source_is_disasm(item.source) and item.evidence:
            current.evidence = _merge_evidence_text(current.evidence, item.evidence)
    return list(result.values())


def _merge_helper_edge_lists(
    primary: list[HelperContractEdge],
    secondary: list[HelperContractEdge],
) -> list[HelperContractEdge]:
    result: list[HelperContractEdge] = []
    for item in primary + secondary:
        current = _find_equivalent_helper_edge(result, item)
        if current is None:
            result.append(item)
            continue
        if item.resolved and not current.resolved:
            current.resolved = True
            current.propagated_size_constraints = list(item.propagated_size_constraints)
            current.propagated_field_accesses = list(item.propagated_field_accesses)
            current.propagated_field_constraints = list(item.propagated_field_constraints)
            current.nested_edges = list(item.nested_edges)
            current.warnings = list(item.warnings)
        else:
            current.propagated_size_constraints = _merge_size_constraints(
                current.propagated_size_constraints,
                item.propagated_size_constraints,
            )
            current.propagated_field_accesses = _merge_field_access_lists(
                current.propagated_field_accesses,
                item.propagated_field_accesses,
            )
            current.propagated_field_constraints = _dedupe_field_constraints(
                current.propagated_field_constraints + item.propagated_field_constraints
            )
            current.nested_edges = _merge_helper_edge_lists(current.nested_edges, item.nested_edges)
            current.warnings = _dedupe_strings(current.warnings + item.warnings)
        current.confidence = max(current.confidence, item.confidence)
        current.evidence = _merge_evidence_text(current.evidence, item.evidence)
    return result


def _find_equivalent_helper_edge(
    items: list[HelperContractEdge],
    candidate: HelperContractEdge,
) -> HelperContractEdge | None:
    key = (candidate.callee, tuple(candidate.arguments), tuple(candidate.passed_buffers))
    for item in items:
        if (item.callee, tuple(item.arguments), tuple(item.passed_buffers)) == key:
            return item
    return None


def _disasm_merge_warnings(
    local_sizes: list[BufferSizeConstraint],
    disasm_sizes: list[BufferSizeConstraint],
    local_accesses: list[FieldAccess],
    disasm_accesses: list[FieldAccess],
    local_constraints: list[FieldConstraint],
    disasm_constraints: list[FieldConstraint],
) -> list[str]:
    warnings: list[str] = []
    for local in local_sizes:
        if _source_is_disasm(local.source):
            continue
        for disasm in disasm_sizes:
            if _size_constraints_conflict(local, disasm):
                warnings.append(
                    "pseudocode/disassembly size conflict for %s: %s %s versus %s %s"
                    % (local.length, local.relation, local.value, disasm.relation, disasm.value)
                )
    for local in local_accesses:
        if _source_is_disasm(local.source):
            continue
        for disasm in disasm_accesses:
            if local.buffer == disasm.buffer and local.offset == disasm.offset and local.type != disasm.type:
                warnings.append(
                    "pseudocode/disassembly field type conflict for %s+0x%X: %s versus %s"
                    % (local.buffer, local.offset, local.type or "unknown", disasm.type or "unknown")
                )
    for local in local_constraints:
        if _source_is_disasm(local.source):
            continue
        for disasm in disasm_constraints:
            if _field_constraints_conflict(local, disasm):
                warnings.append(
                    "pseudocode/disassembly field predicate conflict for %s+0x%X: %s %s versus %s %s"
                    % (
                        local.buffer,
                        local.offset,
                        local.relation,
                        local.value or local.mask,
                        disasm.relation,
                        disasm.value or disasm.mask,
                    )
                )
    return _dedupe_strings(warnings)


def _size_constraints_conflict(left: BufferSizeConstraint, right: BufferSizeConstraint) -> bool:
    if left.length != right.length:
        return False
    left_relation, left_value = _effective_size_constraint(left)
    right_relation, right_value = _effective_size_constraint(right)
    if not left_relation or not right_relation:
        return False
    return left_relation == right_relation and left_value != right_value


def _effective_size_constraint(item: BufferSizeConstraint) -> tuple[str, str]:
    if item.valid_relation and item.valid_value:
        return item.valid_relation, item.valid_value
    return item.relation, item.value


def _field_constraints_conflict(left: FieldConstraint, right: FieldConstraint) -> bool:
    if left.buffer != right.buffer or left.offset != right.offset:
        return False
    left_relation, left_value = _effective_field_constraint(left)
    right_relation, right_value = _effective_field_constraint(right)
    if not left_relation or not right_relation:
        return False
    return left_relation == right_relation and left_value != right_value


def _effective_field_constraint(item: FieldConstraint) -> tuple[str, str]:
    if item.valid_relation and item.valid_value:
        return item.valid_relation, item.valid_value
    return item.relation, item.value or item.mask


def _has_pseudocode_disasm_agreement(
    size_constraints: list[BufferSizeConstraint],
    field_accesses: list[FieldAccess],
) -> bool:
    for item in size_constraints:
        if _source_has_merged_disasm(item.source):
            return True
    for item in field_accesses:
        if _source_has_merged_disasm(item.source):
            return True
    return False


def _source_is_disasm(source: str) -> bool:
    return str(source or "").startswith("disasm")


def _source_has_merged_disasm(source: str) -> bool:
    parts = [part.strip() for part in str(source or "").split(",") if part.strip()]
    return any(_source_is_disasm(part) for part in parts) and any(not _source_is_disasm(part) for part in parts)


def _merge_source_text(left: str, right: str) -> str:
    values: list[str] = []
    for value in (left, right):
        for item in str(value or "").split(","):
            item = item.strip()
            if item and item not in values:
                values.append(item)
    return ", ".join(values)


def _merge_evidence_text(left: str, right: str) -> str:
    if not left:
        return right
    if not right or right in left:
        return left
    return "%s | %s" % (left, right)


def _dedupe_strings(items: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _native_switch_dispatchers(text: str) -> list[str]:
    result: list[str] = []
    source = text or ""
    for match in re.finditer(r"\bswitch\s*\(", source):
        open_index = match.end() - 1
        close_index = find_matching_paren(source, open_index)
        if close_index < 0:
            continue
        dispatcher = _switch_dispatcher_identifier(source[open_index + 1:close_index])
        if dispatcher and dispatcher not in result:
            result.append(dispatcher)
    return result


def _switch_dispatcher_identifier(expression: str) -> str:
    identifier = _argument_identifier(expression or "")
    if identifier:
        return identifier
    return ""


def _command_name_for_kind(kind: str, value: int) -> str:
    if kind == "ntset_system":
        return get_system_information_class_name(value)
    if kind == "ntset_process":
        return get_process_information_class_name(value)
    if kind == "ntset_thread":
        return get_thread_information_class_name(value)
    return ""


def _infer_buffer_sources(text: str, capture: FunctionCapture) -> dict[str, dict[str, str]]:
    sources: dict[str, dict[str, str]] = {}
    signature = extract_function_signature(text) or safe_identifier_replace(capture.prototype, {})
    parameters = extract_parameters_from_signature(signature)
    function_name = capture.name or extract_function_name(signature) or extract_function_name(capture.prototype)
    for name, type_text in parameters:
        lowered = name.lower()
        if _looks_like_dispatcher_parameter_name(name):
            continue
        if lowered in {"processinformation", "systeminformation", "threadinformation"}:
            _add_buffer_source(sources, name, "input", "parameter", _matching_length_variable(text, name))
        elif "buffer" in lowered or ("information" in lowered and _looks_like_pointer_type(type_text)):
            _add_buffer_source(sources, name, "input", "parameter", _matching_length_variable(text, name))
    _add_ntset_parameter_buffer_source(sources, function_name, parameters)

    for match in re.finditer(
        r"\b(?P<var>%s)\s*=\s*(?P<irp>%s)->AssociatedIrp\.(?:MasterIrp|SystemBuffer)\s*;"
        % (_IDENT_RE, _IDENT_RE),
        text,
    ):
        _add_buffer_source(sources, match.group("var"), "inout", "AssociatedIrp.SystemBuffer", _known_length_names(text))

    for match in re.finditer(
        r"\b(?P<var>%s)\s*=\s*\*\s*\([^;\n]*\*+\s*\)\s*\(\s*(?P<irp>%s)\s*\+\s*(?:%d|0x%X)(?:LL|i64|L)?\s*\)\s*;"
        % (_IDENT_RE, _IDENT_RE, _IRP_ASSOCIATED_IRP_OFFSET_X64, _IRP_ASSOCIATED_IRP_OFFSET_X64),
        text,
    ):
        _add_buffer_source(
            sources,
            match.group("var"),
            "inout",
            "IRP offset 0x%X" % _IRP_ASSOCIATED_IRP_OFFSET_X64,
            _known_length_names(text),
        )

    for name in sorted(set(re.findall(r"\b%s\b" % _IDENT_RE, text or ""))):
        if _looks_like_length_name(name):
            continue
        if _identifier_is_called(text, name):
            continue
        if not _identifier_has_value_use(text, name):
            continue
        lowered = name.lower()
        if any(marker in lowered for marker in ("systembuffer", "inputbuffer", "outputbuffer", "type3inputbuffer", "userbuffer")):
            role = "output" if "output" in lowered or "userbuffer" in lowered else "input"
            if "systembuffer" in lowered:
                role = "inout"
            _add_buffer_source(sources, name, role, "name", _matching_length_variable(text, name))
    _propagate_buffer_source_aliases(text, sources)
    return sources


def _add_ntset_parameter_buffer_source(
    sources: dict[str, dict[str, str]],
    function_name: str,
    parameters: list[tuple[str, str]],
) -> None:
    compact = re.sub(r"[^A-Za-z0-9]", "", function_name or "").lower()
    if compact == "ntsetsysteminformation":
        buffer_index = 1
        length_index = 2
    elif compact in {"ntsetinformationprocess", "ntsetinformationthread"}:
        buffer_index = 2
        length_index = 3
    else:
        return
    if len(parameters) <= buffer_index:
        return
    buffer_name = parameters[buffer_index][0]
    length_name = parameters[length_index][0] if len(parameters) > length_index else ""
    _add_buffer_source(
        sources,
        buffer_name,
        "input",
        "NtSetInformation parameter position",
        length_name,
    )


def _looks_like_dispatcher_parameter_name(name: str) -> bool:
    compact = re.sub(r"[^A-Za-z0-9]", "", name or "").lower()
    if compact in {
        "class",
        "infoclass",
        "informationclass",
        "iocontrolcode",
        "ioctlcode",
        "processinformationclass",
        "systeminformationclass",
        "threadinformationclass",
    }:
        return True
    return compact.endswith("informationclass") or compact.endswith("infoclass")


def _looks_like_pointer_type(type_text: str) -> bool:
    compact = re.sub(r"\s+", "", type_text or "").upper()
    if "*" in compact:
        return True
    return compact in {
        "PVOID",
        "PCVOID",
        "PCHAR",
        "PUCHAR",
        "PBYTE",
        "PULONG",
        "PULONG_PTR",
        "PULONGLONG",
        "PSIZE_T",
    }


def _propagate_buffer_source_aliases(text: str, sources: dict[str, dict[str, str]]) -> None:
    assignment_re = re.compile(
        r"\b(?P<dst>%s)\s*=\s*(?:\(\s*[^()]+\s*\)\s*)*(?P<src>%s)\s*;"
        % (_IDENT_RE, _IDENT_RE)
    )
    for _ in range(4):
        changed = False
        for match in assignment_re.finditer(text or ""):
            dst = match.group("dst")
            src = match.group("src")
            if dst == src or src not in sources or _looks_like_length_name(dst):
                continue
            info = sources[src]
            before = dict(sources.get(dst, {}))
            _add_buffer_source(
                sources,
                dst,
                info.get("role", "input"),
                "alias:%s" % src,
                info.get("length", ""),
            )
            if sources.get(dst, {}) != before:
                changed = True
        if not changed:
            break


def _identifier_has_value_use(text: str, name: str) -> bool:
    if not text or not name:
        return False
    for match in re.finditer(r"\b%s\b" % re.escape(name), text):
        prefix = text[max(0, match.start() - 2):match.start()]
        if prefix.endswith(".") or prefix.endswith("->"):
            continue
        return True
    return False


def _identifier_is_called(text: str, name: str) -> bool:
    if not text or not name:
        return False
    return bool(re.search(r"\b%s\s*\(" % re.escape(name), text))


def _add_buffer_source(
    sources: dict[str, dict[str, str]],
    variable: str,
    role: str,
    source: str,
    length: str,
) -> None:
    if not variable:
        return
    current = sources.get(variable, {})
    if current:
        if current.get("role") != role and "inout" in {current.get("role"), role}:
            role = "inout"
        length = current.get("length", "") or length
        source = current.get("source", "") or source
    sources[variable] = {"role": role, "source": source, "length": length}


def _known_length_names(text: str) -> str:
    names = set(re.findall(r"\b%s\b" % _IDENT_RE, text or ""))
    return ", ".join(sorted(name for name in names if _looks_like_length_name(name)))


def _infer_length_aliases(text: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    assignment_re = re.compile(
        r"\b(?P<dst>%s)\s*=\s*(?:\(\s*[^()]+\s*\)\s*)*(?P<src>%s)\s*;"
        % (_IDENT_RE, _IDENT_RE)
    )
    canonical_names = _length_like_names(text)
    for _ in range(4):
        changed = False
        for match in assignment_re.finditer(text or ""):
            dst = match.group("dst")
            src = match.group("src")
            if dst == src:
                continue
            canonical = ""
            if src in canonical_names:
                canonical = src
            elif src in aliases:
                canonical = aliases[src]
            if not canonical:
                continue
            if aliases.get(dst) == canonical:
                continue
            aliases[dst] = canonical
            changed = True
        if not changed:
            break
    return aliases


def _matching_length_variable(text: str, buffer_name: str) -> str:
    names = set(re.findall(r"\b%s\b" % _IDENT_RE, text or ""))
    generic = sorted(name for name in names if _looks_like_length_name(name))
    matched = _ranked_length_names_for_buffer(generic, buffer_name)
    if matched:
        return ", ".join(matched)
    return generic[0] if len(generic) == 1 else ""


def _ranked_length_names_for_buffer(length_names: list[str], buffer_name: str) -> list[str]:
    buffer_tokens = _semantic_name_tokens(buffer_name)
    if not buffer_tokens:
        return []
    exact: list[str] = []
    related: list[str] = []
    for length_name in length_names:
        length_tokens = _semantic_name_tokens(length_name)
        if not length_tokens:
            continue
        if length_tokens[:len(buffer_tokens)] == buffer_tokens:
            exact.append(length_name)
            continue
        shared = set(buffer_tokens) & set(length_tokens)
        if shared and shared - {"buffer", "information", "length", "size", "bytes"}:
            related.append(length_name)
    return exact or related


def _semantic_name_tokens(name: str) -> list[str]:
    if not name:
        return []
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    spaced = re.sub(r"[^A-Za-z0-9]+", " ", spaced)
    return [part.lower() for part in spaced.split() if part]


def _recover_size_constraints(
    lines: list[str],
    source: str = "local",
    length_aliases: dict[str, str] | None = None,
    known_lengths: set[str] | None = None,
) -> list[BufferSizeConstraint]:
    result: list[BufferSizeConstraint] = []
    seen = set()
    known_lengths = known_lengths or set()
    literal_aliases = _literal_assignments_from_lines(lines)
    for index, line in enumerate(lines):
        stripped = line.strip()
        valid_from_reject = _line_has_reject_outcome(lines, index)
        for match in _LENGTH_COMPARE_RE.finditer(stripped):
            left = _canonical_length_operand(_clean_operand(match.group("left")), length_aliases)
            right = _canonical_length_operand(_clean_operand(match.group("right")), length_aliases)
            left = _literal_alias_value(left, literal_aliases)
            right = _literal_alias_value(right, literal_aliases)
            op = match.group("op")
            if _is_known_length_operand(left, known_lengths) and _looks_like_constraint_value(right):
                length, relation, value = left, op, right
            elif _is_known_length_operand(right, known_lengths) and _looks_like_constraint_value(left):
                length, relation, value = right, _invert_relation(op), left
            else:
                continue
            key = (length, relation, value, stripped, source)
            if key in seen:
                continue
            seen.add(key)
            valid_relation = _valid_relation_for_reject_guard(relation) if valid_from_reject else ""
            result.append(
                BufferSizeConstraint(
                    buffer="",
                    length=length,
                    relation=relation,
                    value=value,
                    valid_relation=valid_relation,
                    valid_value=value if valid_relation else "",
                    role=_role_from_length(length),
                    evidence=stripped,
                    source=source,
                    confidence=0.82,
                )
            )
        truthy_constraint = _truthy_length_constraint(stripped, valid_from_reject, length_aliases, source, known_lengths)
        if truthy_constraint is not None:
            key = (
                truthy_constraint.length,
                truthy_constraint.relation,
                truthy_constraint.value,
                truthy_constraint.evidence,
                truthy_constraint.source,
            )
            if key not in seen:
                seen.add(key)
                result.append(truthy_constraint)
    return result


def _truthy_length_constraint(
    line: str,
    valid_from_reject: bool,
    length_aliases: dict[str, str] | None,
    source: str,
    known_lengths: set[str] | None = None,
) -> BufferSizeConstraint | None:
    if not valid_from_reject:
        return None
    match = _LENGTH_TRUTHY_IF_RE.search(line or "")
    if not match:
        return None
    length = _canonical_length_operand(match.group("length"), length_aliases)
    if not _is_known_length_operand(length, known_lengths or set()):
        return None
    relation = "==" if match.group("negate") else "!="
    valid_relation = _valid_relation_for_reject_guard(relation)
    return BufferSizeConstraint(
        buffer="",
        length=length,
        relation=relation,
        value="0",
        valid_relation=valid_relation,
        valid_value="0" if valid_relation else "",
        role=_role_from_length(length),
        evidence=line,
        source=source,
        confidence=0.78,
    )


def _is_known_length_operand(name: str, known_lengths: set[str]) -> bool:
    return _looks_like_length_name(name) or name in known_lengths


def _canonical_length_operand(value: str, aliases: dict[str, str] | None) -> str:
    operand = (value or "").strip()
    if not aliases:
        return operand
    seen: set[str] = set()
    while operand in aliases and operand not in seen:
        seen.add(operand)
        operand = aliases[operand]
    return operand


def _literal_alias_value(value: str, literal_aliases: dict[str, str]) -> str:
    return literal_aliases.get(value, value)


def _line_has_reject_outcome(lines: list[str], index: int) -> bool:
    current = (lines[index] if 0 <= index < len(lines) else "").strip()
    if not current.startswith("if"):
        return False
    outcome_text = current + "\n" + _guard_outcome_window(lines, index)
    lowered = outcome_text.lower()
    reject_status_markers = (
        "status_invalid",
        "status_info_length_mismatch",
        "status_buffer_too_small",
        "status_buffer_overflow",
        "status_not_supported",
        "status_invalid_info_class",
        "status_invalid_device_request",
    )
    if any(marker in lowered for marker in reject_status_markers):
        return True
    if re.search(r"\breturn\s+STATUS_(?!SUCCESS\b)[A-Z0-9_]+\s*;", outcome_text):
        return True
    if re.search(r"\breturn\s+-1\s*;", outcome_text):
        return True
    if _has_error_status_return(outcome_text):
        return True
    if re.search(r"\b(?:goto|break|return)\b", outcome_text) and _has_error_status_assignment(outcome_text):
        return True
    for match in _GOTO_LABEL_RE.finditer(outcome_text):
        if _label_has_error_outcome(lines, match.group("label")):
            return True
    return False


def _label_has_error_outcome(lines: list[str], label: str, max_lines: int = 6) -> bool:
    if not label:
        return False
    label_re = re.compile(r"^\s*%s\s*:" % re.escape(label))
    for index, line in enumerate(lines):
        if not label_re.match(line or ""):
            continue
        window = "\n".join(item.strip() for item in lines[index + 1:index + 1 + max_lines] if item.strip())
        return _has_error_status_return(window) or _has_error_status_assignment(window)
    return False


def _has_error_status_return(text: str) -> bool:
    return any(_is_error_status_literal(match.group("value")) for match in _RETURN_STATUS_LITERAL_RE.finditer(text or ""))


def _has_error_status_assignment(text: str) -> bool:
    if any(_is_error_status_literal(match.group("value")) for match in _ASSIGN_STATUS_LITERAL_RE.finditer(text or "")):
        return True
    return any(
        _is_error_status_literal(match.group("value"))
        for match in re.finditer(r"=\s*(?P<value>%s)\s*;" % _C_INTEGER_LITERAL_VALUE_RE, text or "")
    )


def _is_error_status_literal(value: str) -> bool:
    parsed = parse_c_integer_literal(value)
    if parsed is None:
        return False
    return parsed < 0 or bool(parsed & 0x80000000)


def _guard_outcome_window(lines: list[str], index: int, max_lines: int = 8) -> str:
    result: list[str] = []
    depth = 0
    saw_body = False
    for line in lines[index + 1:index + 1 + max_lines]:
        stripped = line.strip()
        if not stripped:
            continue
        result.append(stripped)
        opens = stripped.count("{")
        closes = stripped.count("}")
        if opens:
            depth += opens
            saw_body = True
        if closes:
            depth -= closes
            if saw_body and depth <= 0:
                break
        if not saw_body and stripped.endswith(";"):
            break
    return "\n".join(result)


def _valid_relation_for_reject_guard(relation: str) -> str:
    if relation.startswith("mask_"):
        suffix = relation[len("mask_"):]
        negated = _negate_relation(suffix)
        return "mask_%s" % negated if negated else ""
    return _negate_relation(relation)


def _negate_relation(relation: str) -> str:
    return {
        "<": ">=",
        ">": "<=",
        "<=": ">",
        ">=": "<",
        "==": "!=",
        "!=": "==",
    }.get(relation, "")


def _recover_field_accesses(
    lines: list[str],
    buffer_sources: dict[str, dict[str, str]],
    source: str = "local",
    typed_field_layouts: dict[str, dict[str, dict[str, object]]] | None = None,
    buffer_element_types: dict[str, tuple[str, int]] | None = None,
) -> list[FieldAccess]:
    result: list[FieldAccess] = []
    access_by_key: dict[tuple[str, int, str, str], FieldAccess] = {}
    known_buffers = set(buffer_sources)
    typed_field_layouts = typed_field_layouts or {}
    buffer_element_types = buffer_element_types or {}
    copy_aliases = _buffer_copy_aliases(lines, known_buffers, buffer_element_types)
    for line in lines:
        stripped = line.strip()
        left_expr = _assignment_left(stripped)
        for match in _ARROW_FIELD_RE.finditer(stripped):
            buffer = match.group("buffer")
            if buffer not in known_buffers and not _looks_like_buffer_name(buffer):
                continue
            field = match.group("field")
            field_layout = typed_field_layouts.get(buffer, {}).get(field, {})
            access = _access_kind(match.group(0), left_expr)
            item = FieldAccess(
                buffer=buffer,
                structure=str(field_layout.get("structure", "")),
                offset=int(field_layout.get("offset", 0)),
                type=str(field_layout.get("type", "unknown") or "unknown"),
                field=field,
                access=access,
                evidence=stripped,
                source=_merge_source_text(source, str(field_layout.get("source", ""))),
                confidence=0.86 if field_layout else 0.78,
            )
            _merge_field_access(access_by_key, item)
        for match in _DEREF_OFFSET_RE.finditer(stripped):
            buffer = match.group("buffer")
            if buffer not in known_buffers and not _looks_like_buffer_name(buffer):
                continue
            offset = _parse_offset(match.group("offset") or "0")
            field_type = _normalize_c_type(match.group("type"))
            item = FieldAccess(
                buffer=buffer,
                structure="",
                offset=offset,
                type=field_type,
                field=_field_name(offset),
                access=_access_kind(match.group(0), left_expr),
                evidence=stripped,
                source=source,
                confidence=0.74,
            )
            _merge_field_access(access_by_key, item)
        for match in _DEREF_PLAIN_RE.finditer(stripped):
            buffer = match.group("buffer")
            if buffer not in known_buffers and not _looks_like_buffer_name(buffer):
                continue
            field_type = _normalize_c_type(match.group("type"))
            item = FieldAccess(
                buffer=buffer,
                structure="",
                offset=0,
                type=field_type,
                field=_field_name(0),
                access=_access_kind(match.group(0), left_expr),
                evidence=stripped,
                source=source,
                confidence=0.74,
            )
            _merge_field_access(access_by_key, item)
        for match in _CAST_INDEX_RE.finditer(stripped):
            buffer = match.group("buffer")
            if buffer not in known_buffers and not _looks_like_buffer_name(buffer):
                continue
            field_type = _normalize_c_type(match.group("type"))
            offset = int(match.group("index")) * _sizeof_type(field_type)
            item = FieldAccess(
                buffer=buffer,
                structure="",
                offset=offset,
                type=field_type,
                field=_field_name(offset),
                access=_access_kind(match.group(0), left_expr),
                evidence=stripped,
                source=source,
                confidence=0.74,
            )
            _merge_field_access(access_by_key, item)
        for match in _INDEXED_MEMBER_RE.finditer(stripped):
            buffer = match.group("buffer")
            if buffer not in known_buffers and not _looks_like_buffer_name(buffer):
                continue
            member = match.group("member")
            member_size = _indexed_member_element_size(member)
            if member_size <= 0:
                continue
            offset = int(match.group("index")) * 16 + int(match.group("member_index")) * member_size
            item = FieldAccess(
                buffer=buffer,
                structure="",
                offset=offset,
                type=_indexed_member_element_type(member),
                field=_field_name(offset),
                access=_access_kind(match.group(0), left_expr),
                evidence=stripped,
                source=source,
                confidence=0.7,
            )
            _merge_field_access(access_by_key, item)
        for match in _POINTER_INDEX_RE.finditer(stripped):
            if ";" not in stripped:
                continue
            buffer = match.group("buffer")
            if buffer not in known_buffers and not _looks_like_buffer_name(buffer):
                continue
            element_type, element_size = _buffer_element_type_and_size(buffer, buffer_element_types)
            offset = int(match.group("index")) * element_size
            item = FieldAccess(
                buffer=buffer,
                structure="",
                offset=offset,
                type=_normalize_c_type(element_type),
                field=_field_name(offset),
                access=_access_kind(match.group(0), left_expr),
                evidence=stripped,
                source=source,
                confidence=0.70,
            )
            _merge_field_access(access_by_key, item)
        for match in _PLAIN_POINTER_DEREF_RE.finditer(stripped):
            if ";" not in stripped:
                continue
            buffer = match.group("buffer")
            if buffer not in known_buffers and not _looks_like_buffer_name(buffer):
                continue
            element_type, _element_size = _buffer_element_type_and_size(buffer, buffer_element_types)
            item = FieldAccess(
                buffer=buffer,
                structure="",
                offset=0,
                type=_normalize_c_type(element_type),
                field=_field_name(0),
                access=_access_kind(match.group(0), left_expr),
                evidence=stripped,
                source=source,
                confidence=0.70,
            )
            _merge_field_access(access_by_key, item)
        for item in _alias_field_accesses(stripped, left_expr, copy_aliases, source):
            _merge_field_access(access_by_key, item)
    return list(access_by_key.values())


def _buffer_copy_aliases(
    lines: list[str],
    known_buffers: set[str],
    buffer_element_types: dict[str, tuple[str, int]],
) -> dict[str, tuple[str, int, str, int]]:
    result: dict[str, tuple[str, int, str, int]] = {}
    for line in lines:
        match = _BUFFER_COPY_ASSIGN_RE.match(line or "")
        if not match:
            continue
        local = match.group("local")
        plain = match.group("plain")
        indexed = match.group("indexed")
        buffer = plain or indexed
        if buffer not in known_buffers:
            continue
        element_type, element_size = _buffer_element_type_and_size(buffer, buffer_element_types)
        index = int(match.group("index") or "0")
        result[local] = (buffer, index * element_size, element_type, element_size)
    return result


def _buffer_element_type_and_size(
    buffer: str,
    buffer_element_types: dict[str, tuple[str, int]],
) -> tuple[str, int]:
    element_type, element_size = buffer_element_types.get(buffer, ("_BYTE", 1))
    return element_type or "_BYTE", max(1, int(element_size or 1))


def _alias_field_accesses(
    line: str,
    left_expr: str,
    copy_aliases: dict[str, tuple[str, int, str, int]],
    source: str,
) -> list[FieldAccess]:
    result: list[FieldAccess] = []
    for match in _LOCAL_ACCESSOR_RE.finditer(line):
        item = _alias_field_access(
            match.group("local"),
            _accessor_offset_type(match.group("accessor")),
            match.group(0),
            line,
            left_expr,
            copy_aliases,
            source,
        )
        if item is not None:
            result.append(item)
    for match in _LOCAL_CAST_RE.finditer(line):
        item = _alias_field_access(
            match.group("local"),
            (0, _normalize_c_type(match.group("type")), _sizeof_type(match.group("type"))),
            match.group(0),
            line,
            left_expr,
            copy_aliases,
            source,
        )
        if item is not None:
            result.append(item)
    for match in _LOCAL_ADDRESS_DEREF_RE.finditer(line):
        item = _alias_field_access(
            match.group("local"),
            (0, _normalize_c_type(match.group("type")), _sizeof_type(match.group("type"))),
            match.group(0),
            line,
            left_expr,
            copy_aliases,
            source,
        )
        if item is not None:
            result.append(item)
    for match in _LOCAL_MEMBER_RE.finditer(line):
        local = match.group("local")
        member = match.group("member")
        member_size = _indexed_member_element_size(member)
        if member_size <= 0:
            continue
        item = _alias_field_access(
            local,
            (
                int(match.group("member_index")) * member_size,
                _indexed_member_element_type(member),
                member_size,
            ),
            match.group(0),
            line,
            left_expr,
            copy_aliases,
            source,
        )
        if item is not None:
            result.append(item)
    return result


def _alias_field_access(
    local: str,
    access_info: tuple[int, str, int] | None,
    expression: str,
    line: str,
    left_expr: str,
    copy_aliases: dict[str, tuple[str, int, str, int]],
    source: str,
) -> FieldAccess | None:
    if access_info is None or local not in copy_aliases:
        return None
    buffer, base_offset, _element_type, _element_size = copy_aliases[local]
    relative_offset, field_type, _field_size = access_info
    offset = base_offset + relative_offset
    return FieldAccess(
        buffer=buffer,
        structure="",
        offset=offset,
        type=_normalize_c_type(field_type),
        field=_field_name(offset),
        access=_access_kind(expression, left_expr),
        evidence=line,
        source=source,
        confidence=0.68,
    )


def _accessor_offset_type(accessor: str) -> tuple[int, str, int] | None:
    normalized = (accessor or "").upper()
    direct = {
        "LOBYTE": (0, "UCHAR", 1),
        "HIBYTE": (1, "UCHAR", 1),
        "LOWORD": (0, "USHORT", 2),
        "HIWORD": (2, "USHORT", 2),
        "LODWORD": (0, "ULONG", 4),
        "HIDWORD": (4, "ULONG", 4),
    }
    if normalized in direct:
        return direct[normalized]
    match = re.match(r"^(?P<kind>BYTE|WORD|DWORD|QWORD)(?P<index>\d+)$", normalized)
    if not match:
        return None
    kind = match.group("kind")
    index = int(match.group("index"))
    size_type = {
        "BYTE": (1, "UCHAR"),
        "WORD": (2, "USHORT"),
        "DWORD": (4, "ULONG"),
        "QWORD": (8, "ULONGLONG"),
    }[kind]
    size, type_text = size_type
    return index * size, type_text, size


def _indexed_member_element_size(member: str) -> int:
    return {
        "m128i_i8": 1,
        "m128i_u8": 1,
        "m128i_i16": 2,
        "m128i_u16": 2,
        "m128i_i32": 4,
        "m128i_u32": 4,
        "m128i_i64": 8,
        "m128i_u64": 8,
    }.get(member, 0)


def _indexed_member_element_type(member: str) -> str:
    return {
        "m128i_i8": "std::int8_t",
        "m128i_u8": "std::uint8_t",
        "m128i_i16": "std::int16_t",
        "m128i_u16": "std::uint16_t",
        "m128i_i32": "std::int32_t",
        "m128i_u32": "std::uint32_t",
        "m128i_i64": "std::int64_t",
        "m128i_u64": "std::uint64_t",
    }.get(member, "std::uint32_t")


def _recover_field_constraints(
    lines: list[str],
    accesses: list[FieldAccess],
    source: str = "local",
) -> list[FieldConstraint]:
    result: list[FieldConstraint] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        valid_from_reject = _line_has_reject_outcome(lines, index)
        for access in accesses:
            if access.evidence != stripped:
                continue
            expression = _field_expression_for_access(access, stripped)
            if not expression:
                generic_constraint = _generic_deref_constraint(access, stripped, source, valid_from_reject)
                if generic_constraint is not None:
                    result.append(generic_constraint)
                continue
            mask_match = re.search(
                r"\(\s*%s\s*&\s*(?P<mask>~?%s)\s*\)\s*(?P<op>==|!=)\s*(?P<value>0x[0-9A-Fa-f]+|\d+)"
                % (re.escape(expression), _C_VALUE_RE),
                stripped,
            )
            if mask_match:
                relation = "mask_%s" % mask_match.group("op")
                valid_relation = _valid_relation_for_reject_guard(relation) if valid_from_reject else ""
                result.append(
                    FieldConstraint(
                        buffer=access.buffer,
                        structure="",
                        offset=access.offset,
                        field=access.field,
                        relation=relation,
                        value=mask_match.group("value"),
                        mask=mask_match.group("mask"),
                        valid_relation=valid_relation,
                        valid_value=mask_match.group("value") if valid_relation else "",
                        evidence=stripped,
                        source=source,
                        confidence=0.78,
                    )
                )
                continue
            compare_match = re.search(
                r"%s\s*(?P<op>==|!=|<=|>=|<|>)\s*(?P<value>%s)"
                % (re.escape(expression), _C_VALUE_RE),
                stripped,
            )
            if compare_match:
                relation = compare_match.group("op")
                valid_relation = _valid_relation_for_reject_guard(relation) if valid_from_reject else ""
                result.append(
                    FieldConstraint(
                        buffer=access.buffer,
                        structure="",
                        offset=access.offset,
                        field=access.field,
                        relation=relation,
                        value=compare_match.group("value"),
                        valid_relation=valid_relation,
                        valid_value=compare_match.group("value") if valid_relation else "",
                        evidence=stripped,
                        source=source,
                        confidence=0.80,
                    )
                )
                continue
            if re.search(r"!\s*%s\b" % re.escape(expression), stripped):
                valid_relation = _valid_relation_for_reject_guard("==") if valid_from_reject else ""
                result.append(
                    FieldConstraint(
                        buffer=access.buffer,
                        structure="",
                        offset=access.offset,
                        field=access.field,
                        relation="==",
                        value="0",
                        valid_relation=valid_relation,
                        valid_value="0" if valid_relation else "",
                        evidence=stripped,
                        source=source,
                        confidence=0.70,
                    )
                )
    return _dedupe_field_constraints(result)


def _generic_deref_constraint(
    access: FieldAccess,
    line: str,
    source: str,
    valid_from_reject: bool,
) -> FieldConstraint | None:
    if not access.field.startswith("field_"):
        return None
    mask_match = re.search(
        r"&\s*(?P<mask>~?%s)\s*\)?\s*(?P<op>==|!=)\s*(?P<value>0x[0-9A-Fa-f]+|\d+)" % _C_VALUE_RE,
        line,
    )
    if mask_match:
        relation = "mask_%s" % mask_match.group("op")
        valid_relation = _valid_relation_for_reject_guard(relation) if valid_from_reject else ""
        return FieldConstraint(
            buffer=access.buffer,
            structure="",
            offset=access.offset,
            field=access.field,
            relation=relation,
            value=mask_match.group("value"),
            mask=mask_match.group("mask"),
            valid_relation=valid_relation,
            valid_value=mask_match.group("value") if valid_relation else "",
            evidence=line,
            source=source,
            confidence=0.72,
        )
    compare_match = re.search(r"(?P<op>==|!=|<=|>=|<|>)\s*(?P<value>%s)" % _C_VALUE_RE, line)
    if not compare_match:
        return None
    relation = compare_match.group("op")
    valid_relation = _valid_relation_for_reject_guard(relation) if valid_from_reject else ""
    return FieldConstraint(
        buffer=access.buffer,
        structure="",
        offset=access.offset,
        field=access.field,
        relation=relation,
        value=compare_match.group("value"),
        valid_relation=valid_relation,
        valid_value=compare_match.group("value") if valid_relation else "",
        evidence=line,
        source=source,
        confidence=0.70,
    )


def _build_buffer_contracts(
    kind: str,
    command_value: int,
    command_name: str,
    buffer_sources: dict[str, dict[str, str]],
    size_constraints: list[BufferSizeConstraint],
    field_accesses: list[FieldAccess],
    field_constraints: list[FieldConstraint],
    helper_edges: list[HelperContractEdge],
) -> list[BufferContract]:
    alias_roots = _buffer_alias_roots(buffer_sources)
    field_accesses = [_canonical_field_access(item, alias_roots) for item in field_accesses]
    field_constraints = [_canonical_field_constraint(item, alias_roots) for item in field_constraints]
    helper_edges = [_canonical_helper_edge(edge, alias_roots) for edge in helper_edges]
    buffers = _candidate_contract_buffers(
        buffer_sources,
        size_constraints,
        field_accesses,
        field_constraints,
        helper_edges,
    )
    result: list[BufferContract] = []
    for buffer in buffers:
        info = buffer_sources.get(buffer, {})
        helper_info = _helper_buffer_info(helper_edges, buffer)
        buffer_field_accesses = [item for item in field_accesses if item.buffer == buffer]
        buffer_field_constraints = [item for item in field_constraints if item.buffer == buffer]
        role = _merge_buffer_roles(
            info.get("role", ""),
            helper_info.get("role", ""),
            _role_from_field_accesses(buffer_field_accesses),
            _role_from_buffer_name(buffer),
        )
        structure_name = _structure_name(kind, command_value, command_name, role)
        for item in field_accesses:
            if item.buffer == buffer:
                item.structure = structure_name
        for item in field_constraints:
            if item.buffer == buffer:
                item.structure = structure_name
        buffer_size_constraints = [
            _constraint_for_buffer(item, buffer)
            for item in size_constraints
            if _constraint_matches_buffer(item, info, role)
        ]
        helper_size_constraints = _helper_size_constraints_for_buffer(helper_edges, buffer)
        helper_field_accesses = _helper_field_accesses_for_buffer(helper_edges, buffer)
        helper_field_constraints = _helper_field_constraints_for_buffer(helper_edges, buffer)
        if (
            not buffer_size_constraints
            and not buffer_field_accesses
            and not buffer_field_constraints
            and not helper_size_constraints
            and not helper_field_accesses
            and not helper_field_constraints
            and not helper_info.get("length", "")
            and not helper_info.get("source", "")
        ):
            continue
        result.append(
            BufferContract(
                role=role or "unknown",
                source=info.get("source", "") or helper_info.get("source", "") or "inferred",
                variable=buffer,
                length_variable=_merge_csv_values(info.get("length", ""), helper_info.get("length", "")),
                structure_name=structure_name,
                size_constraints=buffer_size_constraints,
                field_accesses=buffer_field_accesses,
                field_constraints=buffer_field_constraints,
                confidence=_buffer_confidence(
                    buffer_size_constraints,
                    buffer_field_accesses,
                    buffer_field_constraints,
                    helper_size_constraints,
                    helper_field_accesses,
                    helper_field_constraints,
                ),
                evidence="Buffer referenced by case predicates, field accesses, or helper propagation",
            )
        )
    return result


def _buffer_alias_roots(buffer_sources: dict[str, dict[str, str]]) -> dict[str, str]:
    return {name: _buffer_alias_root(buffer_sources, name) for name in buffer_sources}


def _buffer_alias_root(buffer_sources: dict[str, dict[str, str]], name: str) -> str:
    current = name
    seen: set[str] = set()
    while current and current not in seen:
        seen.add(current)
        source = buffer_sources.get(current, {}).get("source", "")
        if not source.startswith("alias:"):
            break
        parent = source.split(":", 1)[1].strip()
        if not parent or parent not in buffer_sources:
            break
        current = parent
    return current or name


def _canonical_buffer_name(name: str, alias_roots: dict[str, str]) -> str:
    return alias_roots.get(name, name)


def _canonical_field_access(item: FieldAccess, alias_roots: dict[str, str]) -> FieldAccess:
    buffer = _canonical_buffer_name(item.buffer, alias_roots)
    if buffer == item.buffer:
        return item
    return FieldAccess(
        buffer=buffer,
        structure=item.structure,
        offset=item.offset,
        type=item.type,
        field=item.field,
        access=item.access,
        evidence=item.evidence,
        source=item.source,
        confidence=item.confidence,
    )


def _canonical_field_constraint(item: FieldConstraint, alias_roots: dict[str, str]) -> FieldConstraint:
    buffer = _canonical_buffer_name(item.buffer, alias_roots)
    if buffer == item.buffer:
        return item
    return FieldConstraint(
        buffer=buffer,
        structure=item.structure,
        offset=item.offset,
        field=item.field,
        relation=item.relation,
        value=item.value,
        mask=item.mask,
        valid_relation=item.valid_relation,
        valid_value=item.valid_value,
        evidence=item.evidence,
        source=item.source,
        confidence=item.confidence,
    )


def _canonical_size_constraint(item: BufferSizeConstraint, alias_roots: dict[str, str]) -> BufferSizeConstraint:
    buffer = _canonical_buffer_name(item.buffer, alias_roots)
    if buffer == item.buffer:
        return item
    return BufferSizeConstraint(
        buffer=buffer,
        length=item.length,
        relation=item.relation,
        value=item.value,
        valid_relation=item.valid_relation,
        valid_value=item.valid_value,
        role=item.role,
        evidence=item.evidence,
        source=item.source,
        confidence=item.confidence,
    )


def _canonical_helper_edge(edge: HelperContractEdge, alias_roots: dict[str, str]) -> HelperContractEdge:
    passed_buffers: list[str] = []
    for buffer in edge.passed_buffers:
        _append_unique(passed_buffers, _canonical_buffer_name(buffer, alias_roots))
    arguments = [_canonical_argument_expr(argument, alias_roots) for argument in edge.arguments]
    return HelperContractEdge(
        callee=edge.callee,
        arguments=arguments,
        passed_buffers=passed_buffers,
        resolved=edge.resolved,
        depth=edge.depth,
        evidence=edge.evidence or _call_site_evidence(edge.callee, arguments),
        propagated_size_constraints=[
            _canonical_size_constraint(item, alias_roots)
            for item in edge.propagated_size_constraints
        ],
        propagated_field_accesses=[
            _canonical_field_access(item, alias_roots)
            for item in edge.propagated_field_accesses
        ],
        propagated_field_constraints=[
            _canonical_field_constraint(item, alias_roots)
            for item in edge.propagated_field_constraints
        ],
        nested_edges=[
            _canonical_helper_edge(item, alias_roots)
            for item in edge.nested_edges
        ],
        warnings=list(edge.warnings),
        confidence=edge.confidence,
    )


def _canonical_argument_expr(argument: str, alias_roots: dict[str, str]) -> str:
    identifier = _argument_identifier(argument)
    if not identifier:
        return argument
    canonical = _canonical_buffer_name(identifier, alias_roots)
    if canonical == identifier:
        return argument
    return re.sub(r"\b%s\b" % re.escape(identifier), canonical, argument, count=1)


def _candidate_contract_buffers(
    buffer_sources: dict[str, dict[str, str]],
    size_constraints: list[BufferSizeConstraint],
    field_accesses: list[FieldAccess],
    field_constraints: list[FieldConstraint],
    helper_edges: list[HelperContractEdge],
) -> list[str]:
    evidence_buffers = {
        item.buffer
        for item in field_accesses + field_constraints
        if item.buffer
    } | _helper_buffers_with_contract_evidence(helper_edges) | _helper_buffers_with_escape_evidence(helper_edges)
    if evidence_buffers:
        return sorted(evidence_buffers)
    primary = {
        name
        for name, info in buffer_sources.items()
        if _constraints_apply_to_source(info, size_constraints) and _is_primary_buffer_source(info)
    }
    if primary:
        return sorted(primary)
    return sorted(
        name
        for name, info in buffer_sources.items()
        if _constraints_apply_to_source(info, size_constraints)
    )


def _is_primary_buffer_source(info: dict[str, str]) -> bool:
    source = info.get("source", "")
    return source in {
        "parameter",
        "AssociatedIrp.SystemBuffer",
    } or source.startswith("IRP offset")


def _buffer_confidence(
    size_constraints: list[BufferSizeConstraint],
    field_accesses: list[FieldAccess],
    field_constraints: list[FieldConstraint],
    helper_size_constraints: list[BufferSizeConstraint],
    helper_field_accesses: list[FieldAccess],
    helper_field_constraints: list[FieldConstraint],
) -> float:
    if field_accesses or field_constraints or size_constraints:
        return 0.82
    if helper_field_accesses or helper_field_constraints:
        return 0.76
    if helper_size_constraints:
        return 0.72
    return 0.68


def _merge_buffer_roles(*roles: str) -> str:
    role_set = {role for role in roles if role}
    if "inout" in role_set or ("input" in role_set and "output" in role_set):
        return "inout"
    if "output" in role_set:
        return "output"
    if "input" in role_set:
        return "input"
    return ""


def _role_from_field_accesses(accesses: list[FieldAccess]) -> str:
    access_roles: set[str] = set()
    for item in accesses:
        if item.access in {"write", "read_write"}:
            access_roles.add("output")
        if item.access in {"read", "read_write"}:
            access_roles.add("input")
    return _merge_buffer_roles(*access_roles)


def _merge_csv_values(*values: str) -> str:
    result: list[str] = []
    for value in values:
        for item in str(value or "").split(","):
            item = item.strip()
            if item:
                _append_unique(result, item)
    return ", ".join(result)


def _helper_buffer_info(edges: list[HelperContractEdge], buffer: str) -> dict[str, str]:
    lengths: list[str] = []
    roles: list[str] = []
    sources: list[str] = []
    _collect_helper_buffer_info(edges, buffer, lengths, roles, sources)
    return {
        "role": _combined_buffer_role(roles),
        "length": ", ".join(lengths),
        "source": ", ".join(sources),
    }


def _collect_helper_buffer_info(
    edges: list[HelperContractEdge],
    buffer: str,
    lengths: list[str],
    roles: list[str],
    sources: list[str],
) -> None:
    for edge in edges:
        if buffer in edge.passed_buffers:
            _append_unique(sources, "helper:%s argument" % edge.callee)
            for length in _helper_call_lengths_for_buffer(edge, buffer):
                _append_unique(lengths, length)
                _append_unique(roles, _role_from_length(length))
        for item in edge.propagated_size_constraints:
            if item.buffer != buffer:
                continue
            _append_unique(lengths, item.length)
            _append_unique(roles, item.role)
        for item in edge.propagated_field_accesses:
            if item.buffer == buffer:
                _append_unique(roles, _role_from_field_accesses([item]))
        for item in edge.propagated_field_constraints:
            if item.buffer == buffer:
                _append_unique(roles, "input")
        _collect_helper_buffer_info(edge.nested_edges, buffer, lengths, roles, sources)


def _combined_buffer_role(roles: list[str]) -> str:
    role_set = {role for role in roles if role}
    if "input" in role_set and "output" in role_set:
        return "inout"
    if "output" in role_set:
        return "output"
    if "input" in role_set:
        return "input"
    return ""


def _helper_buffers_with_contract_evidence(edges: list[HelperContractEdge]) -> set[str]:
    result: set[str] = set()
    for edge in edges:
        if edge.propagated_size_constraints or edge.propagated_field_accesses or edge.propagated_field_constraints:
            result.update(edge.passed_buffers)
            result.update(item.buffer for item in edge.propagated_size_constraints if item.buffer)
            result.update(item.buffer for item in edge.propagated_field_accesses if item.buffer)
            result.update(item.buffer for item in edge.propagated_field_constraints if item.buffer)
        result.update(_helper_buffers_with_contract_evidence(edge.nested_edges))
    return result


def _helper_buffers_with_escape_evidence(edges: list[HelperContractEdge]) -> set[str]:
    result: set[str] = set()
    for edge in edges:
        result.update(edge.passed_buffers)
        result.update(_helper_buffers_with_escape_evidence(edge.nested_edges))
    return result


def _helper_call_lengths_for_buffer(edge: HelperContractEdge, buffer: str) -> list[str]:
    result: list[str] = []
    for length in _length_arguments_for_buffer(edge.arguments, buffer).split(","):
        length = length.strip()
        if length:
            _append_unique(result, length)
    return result


def _recover_helper_edges(
    body_text: str,
    buffer_sources: dict[str, dict[str, str]],
    helper_map: dict[str, FunctionCapture],
    max_depth: int,
    depth: int,
    visited: set[str],
) -> list[HelperContractEdge]:
    if depth >= max_depth:
        return _depth_limited_helper_edges(body_text, buffer_sources, depth)
    known_buffers = set(buffer_sources)
    result: list[HelperContractEdge] = []
    seen_edges: set[tuple[str, tuple[str, ...]]] = set()
    for site in _iter_helper_call_sites(body_text):
        callee = site.callee
        arguments = site.arguments
        edge_key = (callee, tuple(arguments))
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        payload_arguments = _helper_payload_arguments(site)
        passed_buffers = _passed_buffer_arguments(payload_arguments, known_buffers)
        if not passed_buffers:
            continue
        helper = helper_map.get(callee)
        if helper is None:
            warnings = _missing_helper_warnings(site, body_text)
            result.append(
                HelperContractEdge(
                    callee=callee,
                    arguments=arguments,
                    passed_buffers=passed_buffers,
                    resolved=False,
                    depth=depth + 1,
                    evidence=site.evidence,
                    warnings=warnings,
                    confidence=0.45,
                )
            )
            continue
        if helper.name in visited:
            result.append(
                HelperContractEdge(
                    callee=callee,
                    arguments=arguments,
                    passed_buffers=passed_buffers,
                    resolved=False,
                    depth=depth + 1,
                    evidence=site.evidence,
                    warnings=["recursive helper edge skipped"],
                    confidence=0.40,
                )
            )
            continue
        edge = _analyze_helper_edge(
            helper,
            arguments,
            passed_buffers,
            helper_map,
            max_depth,
            depth + 1,
            visited | {helper.name},
        )
        result.append(edge)
    return result


def _depth_limited_helper_edges(
    body_text: str,
    buffer_sources: dict[str, dict[str, str]],
    depth: int,
) -> list[HelperContractEdge]:
    known_buffers = set(buffer_sources)
    result: list[HelperContractEdge] = []
    seen_edges: set[tuple[str, tuple[str, ...]]] = set()
    for site in _iter_helper_call_sites(body_text):
        arguments = site.arguments
        edge_key = (site.callee, tuple(arguments))
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        payload_arguments = _helper_payload_arguments(site)
        passed_buffers = _passed_buffer_arguments(payload_arguments, known_buffers)
        if not passed_buffers:
            continue
        warnings = [
            "helper depth limit reached",
            "helper not analyzed because maximum helper depth was reached",
        ]
        if site.indirect:
            warnings.append("indirect helper call target not resolved")
        result.append(
            HelperContractEdge(
                callee=site.callee,
                arguments=arguments,
                passed_buffers=passed_buffers,
                resolved=False,
                depth=depth + 1,
                evidence=site.evidence,
                warnings=warnings,
                confidence=0.35,
            )
        )
    return result


def _missing_helper_warnings(site: _HelperCallSite, body_text: str = "") -> list[str]:
    if _is_indirect_dispatch_thunk(site.callee):
        warnings = [
            "indirect helper call target not resolved",
            "helper not available for buffer contract analysis",
            "buffer pointer escapes to unresolved indirect call",
        ]
        target = _indirect_dispatch_target_argument(site)
        if target:
            warnings.append("indirect dispatch target argument: %s" % target)
        for candidate in _indirect_dispatch_target_candidates(body_text, site):
            warnings.append("indirect dispatch target candidate: %s" % candidate)
        if _site_is_terminal_return(site, body_text):
            warnings.append("terminal helper call returned directly")
        if _site_has_caller_buffer_guard(site, body_text):
            warnings.append("caller case has local buffer guard before terminal helper")
        return warnings
    if site.indirect:
        warnings = [
            "indirect helper call target not resolved",
            "helper not available for buffer contract analysis",
            "buffer pointer escapes to unresolved indirect call",
        ]
        if _site_is_terminal_return(site, body_text):
            warnings.append("terminal helper call returned directly")
        if _site_has_caller_buffer_guard(site, body_text):
            warnings.append("caller case has local buffer guard before terminal helper")
        return warnings
    warnings = [
        "helper not available for buffer contract analysis",
        "buffer pointer escapes to unknown function",
    ]
    if _site_is_terminal_return(site, body_text):
        warnings.append("terminal helper call returned directly")
    if _site_has_caller_buffer_guard(site, body_text):
        warnings.append("caller case has local buffer guard before terminal helper")
    return warnings


def _site_is_terminal_return(site: _HelperCallSite, body_text: str) -> bool:
    line = _call_site_source_line(site, body_text)
    if not line.startswith("return "):
        return False
    return site.evidence in line and line.rstrip().endswith(";")


def _site_has_caller_buffer_guard(site: _HelperCallSite, body_text: str) -> bool:
    if site.offset < 0:
        return False
    source = (body_text or "")[: site.offset]
    if not source:
        return False
    identifiers = [_argument_identifier(argument) for argument in site.arguments]
    argument_names = {identifier for identifier in identifiers if identifier}
    if not argument_names:
        return False
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped.startswith("if"):
            continue
        if _guard_line_references_argument_or_length(stripped, argument_names):
            return True
    return False


def _guard_line_references_argument_or_length(line: str, argument_names: set[str]) -> bool:
    identifiers = set(re.findall(r"\b%s\b" % _IDENT_RE, line or ""))
    if identifiers & argument_names:
        return True
    return any(_looks_like_length_name(identifier) for identifier in identifiers)


def _call_site_source_line(site: _HelperCallSite, body_text: str) -> str:
    source = body_text or ""
    if site.offset < 0 or site.offset >= len(source):
        return ""
    start = source.rfind("\n", 0, site.offset) + 1
    end = source.find("\n", site.offset)
    if end < 0:
        end = len(source)
    return source[start:end].strip()


def _helper_payload_arguments(site: _HelperCallSite) -> list[str]:
    if _is_indirect_dispatch_thunk(site.callee) and site.arguments:
        return list(site.arguments[1:])
    return list(site.arguments)


def _indirect_dispatch_target_argument(site: _HelperCallSite) -> str:
    if not _is_indirect_dispatch_thunk(site.callee) or not site.arguments:
        return ""
    return str(site.arguments[0] or "").strip()


def _indirect_dispatch_target_candidates(body_text: str, site: _HelperCallSite) -> list[str]:
    if not _is_indirect_dispatch_thunk(site.callee):
        return []
    target_argument = _indirect_dispatch_target_argument(site)
    if not target_argument:
        return []
    result: list[str] = []
    direct_candidate = _indirect_target_direct_candidate(target_argument)
    if direct_candidate:
        _append_unique(result, direct_candidate)
    target_identifier = _argument_identifier(target_argument)
    if not target_identifier:
        return result
    source = body_text or ""
    if site.offset >= 0:
        source = source[: site.offset]
    for match in _ASSIGNMENT_RE.finditer(source):
        if _assignment_lhs_identifier(match.group("left")) != target_identifier:
            continue
        for candidate in _indirect_target_expression_candidates(match.group("right")):
            if candidate == target_identifier:
                continue
            _append_unique(result, candidate)
    return result


def _assignment_lhs_identifier(value: str) -> str:
    text = str(value or "").strip()
    if not text or any(marker in text for marker in ("*", "->", "[", "]", ".")):
        return ""
    identifiers = re.findall(_IDENT_RE, text)
    if not identifiers:
        return ""
    return identifiers[-1]


def _indirect_target_direct_candidate(argument: str) -> str:
    candidates = _indirect_target_expression_candidates(argument)
    if len(candidates) != 1:
        return ""
    candidate = candidates[0]
    identifier = _argument_identifier(argument)
    if candidate == identifier and not _looks_like_concrete_indirect_target_name(candidate):
        return ""
    return candidate


def _indirect_target_expression_candidates(expression: str) -> list[str]:
    result: list[str] = []
    text = _strip_leading_casts(str(expression or "").strip())
    text = re.sub(r"^\&\s*", "", text).strip()
    text = _strip_balanced_outer_parentheses(text)
    indexed = re.fullmatch(r"(?P<base>%s)\s*\[[^\]]+\]" % _IDENT_RE, text)
    if indexed:
        base = indexed.group("base")
        if _looks_like_concrete_indirect_target_name(base):
            _append_unique(result, "%s[]" % base)
        return result
    identifier = _argument_identifier(text)
    if identifier and _looks_like_concrete_indirect_target_name(identifier):
        _append_unique(result, identifier)
        return result
    for identifier in re.findall(_IDENT_RE, text):
        if _looks_like_concrete_indirect_target_name(identifier):
            _append_unique(result, identifier)
    return result


def _strip_balanced_outer_parentheses(value: str) -> str:
    result = str(value or "").strip()
    while result.startswith("(") and result.endswith(")"):
        close_index = find_matching_paren(result, 0)
        if close_index != len(result) - 1:
            return result
        result = result[1:-1].strip()
    return result


def _looks_like_concrete_indirect_target_name(name: str) -> bool:
    value = str(name or "").strip()
    if not value:
        return False
    lowered = value.lower()
    if value in _KEYWORDS or value in _TYPE_LIKE_CALL_TOKENS or value in _CALLING_CONVENTION_TOKENS:
        return False
    if _TYPE_LIKE_CALL_RE.fullmatch(value or ""):
        return False
    if re.fullmatch(r"[va]\d+", lowered):
        return False
    if lowered in {"result", "status", "systeminformation", "systembuffer", "input", "output"}:
        return False
    if _looks_like_length_name(value):
        return False
    if re.match(r"(?i)^(sub|off|qword|dword|word|byte|ptr|func)_[0-9A-F]+", value):
        return True
    if any(marker in lowered for marker in ("handler", "dispatch", "callback", "routine", "function", "thunk")):
        return True
    return any(char.isupper() for char in value)


def _is_indirect_dispatch_thunk(callee: str) -> bool:
    lowered = str(callee or "").lower()
    return "guard_dispatch_icall" in lowered


def _passed_buffer_arguments(arguments: list[str], known_buffers: set[str]) -> list[str]:
    result: list[str] = []
    identifiers = [_argument_identifier(argument) for argument in arguments]
    for identifier in identifiers:
        if identifier in known_buffers:
            _append_unique(result, identifier)
    for index, identifier in enumerate(identifiers):
        if not _is_provisional_buffer_argument(arguments, identifiers, index):
            continue
        _append_unique(result, identifier)
    return result


def _is_provisional_buffer_argument(arguments: list[str], identifiers: list[str], index: int) -> bool:
    if index < 0 or index >= len(identifiers):
        return False
    identifier = identifiers[index]
    if not identifier or _looks_like_length_name(identifier):
        return False
    if _argument_is_output_reference(arguments[index]):
        return False
    if _argument_has_integer_cast(arguments[index]):
        return False
    next_identifier = identifiers[index + 1] if index + 1 < len(identifiers) else ""
    return bool(next_identifier and _looks_like_length_name(next_identifier))


def _argument_is_output_reference(argument: str) -> bool:
    value = _strip_leading_casts(argument or "")
    return value.strip().startswith("&")


def _argument_has_integer_cast(argument: str) -> bool:
    return bool(
        re.match(
            r"^\s*\(\s*(?:"
            r"unsigned\s+int|signed\s+int|int|UINT|UINT32|ULONG|LONG|DWORD|SIZE_T|"
            r"ULONG_PTR|LONG_PTR|UINT_PTR|DWORD_PTR|_DWORD|_QWORD|__int64|unsigned\s+__int64"
            r")\s*\)",
            argument or "",
            re.IGNORECASE,
        )
    )


def _length_arguments_for_buffer(arguments: list[str], buffer: str) -> str:
    if not buffer:
        return ""
    identifiers = [_argument_identifier(argument) for argument in arguments]
    result: list[str] = []
    for index, identifier in enumerate(identifiers):
        if identifier != buffer:
            continue
        for candidate in identifiers[index + 1:]:
            if not candidate:
                continue
            if not _looks_like_length_name(candidate):
                break
            _append_unique(result, candidate)
    return ", ".join(result)


def _length_arguments_for_buffer_with_params(
    arguments: list[str],
    params: list[tuple[str, str]],
    buffer: str,
) -> str:
    if not buffer:
        return ""
    identifiers = [_argument_identifier(argument) for argument in arguments]
    result: list[str] = []
    for index, identifier in enumerate(identifiers):
        if identifier != buffer:
            continue
        for arg_index in range(index + 1, min(len(arguments), len(params))):
            candidate = identifiers[arg_index]
            param_name, param_type = params[arg_index]
            if not candidate:
                continue
            if not _helper_param_looks_like_length(param_name, param_type):
                break
            _append_unique(result, candidate)
    return ", ".join(result)


def _helper_param_looks_like_length(name: str, _type_text: str) -> bool:
    return _looks_like_length_name(name)


def _typed_field_layouts_for_params(
    params: list[tuple[str, str]],
    rename_map: dict[str, str],
) -> dict[str, dict[str, dict[str, object]]]:
    result: dict[str, dict[str, dict[str, object]]] = {}
    for param_name, type_text in params:
        buffer = rename_map.get(param_name, param_name)
        if not buffer:
            continue
        layout = _profile_field_layout_for_pointer_type(type_text)
        if layout:
            result[buffer] = layout
    return result


def _typed_pointer_elements_for_params(
    params: list[tuple[str, str]],
    rename_map: dict[str, str],
) -> dict[str, tuple[str, int]]:
    result: dict[str, tuple[str, int]] = {}
    for param_name, type_text in params:
        buffer = rename_map.get(param_name, param_name)
        if not buffer:
            continue
        element = _pointer_element_type_and_size(type_text)
        if element is not None:
            result[buffer] = element
    return result


def _pointer_element_type_and_size(type_text: str) -> tuple[str, int] | None:
    raw = str(type_text or "").strip()
    cleaned = _clean_profile_type(raw)
    if "*" not in raw and not _profile_type_is_pointer(cleaned):
        return None
    element_type = cleaned.replace("*", "").strip()
    aliases = load_kernel_api_family("aliases")
    alias = aliases.get(cleaned, {}) if isinstance(aliases, dict) else {}
    if isinstance(alias, dict):
        target = _clean_profile_type(str(alias.get("target", "") or ""))
        if target:
            element_type = target.replace("*", "").strip()
    if cleaned.startswith("P") and "*" not in cleaned and len(cleaned) > 1:
        element_type = cleaned[1:]
    if not element_type:
        element_type = "_BYTE"
    return element_type, _sizeof_type(element_type)


@lru_cache(maxsize=512)
def _profile_field_layout_for_pointer_type(type_text: str) -> dict[str, dict[str, object]]:
    structure_name = _profile_structure_name_from_pointer_type(type_text)
    if not structure_name:
        return {}
    return _profile_structure_field_layout(structure_name)


def _profile_structure_name_from_pointer_type(type_text: str) -> str:
    raw = str(type_text or "").strip()
    cleaned = _clean_profile_type(raw)
    if not cleaned:
        return ""
    structures = load_kernel_api_family("structures")
    aliases = load_kernel_api_family("aliases")
    candidates: list[str] = []
    if "*" in raw:
        candidates.append(cleaned.replace("*", "").strip())
    alias = aliases.get(cleaned, {}) if isinstance(aliases, dict) else {}
    if isinstance(alias, dict):
        target = _clean_profile_type(str(alias.get("target", "")))
        if target:
            candidates.append(target.replace("*", "").strip())
    if cleaned.startswith("P") and len(cleaned) > 1:
        candidates.append(cleaned[1:])
    for candidate in candidates:
        name = _profile_structure_name(candidate, structures)
        if name:
            return name
    return ""


@lru_cache(maxsize=512)
def _profile_structure_field_layout(structure_name: str) -> dict[str, dict[str, object]]:
    structures = load_kernel_api_family("structures")
    name = _profile_structure_name(structure_name, structures)
    if not name:
        return {}
    payload = structures.get(name, {}) if isinstance(structures, dict) else {}
    fields = payload.get("fields", []) if isinstance(payload, dict) else []
    if not isinstance(fields, list):
        return {}
    result: dict[str, dict[str, object]] = {}
    offset = 0
    for field in fields:
        if not isinstance(field, dict):
            continue
        field_name = str(field.get("name", "") or "").strip()
        if not field_name:
            continue
        field_type = _clean_profile_type(str(field.get("type", "") or ""))
        field_size, field_align = _profile_type_size_align(field_type)
        count = _profile_array_count(str(field.get("array", "") or ""))
        offset = _align_up(offset, field_align)
        result[field_name] = {
            "structure": name,
            "offset": offset,
            "type": field_type or "unknown",
            "size": max(1, field_size) * count,
            "source": "profile:%s" % name,
        }
        offset += max(1, field_size) * count
    return result


def _profile_structure_name(candidate: str, structures: dict[str, object]) -> str:
    token = _clean_profile_type(candidate).replace("*", "").strip()
    if not token or not isinstance(structures, dict):
        return ""
    candidates = [token]
    if token.startswith("_"):
        candidates.append(token[1:])
    else:
        candidates.append("_" + token)
    for item in candidates:
        if item in structures:
            return item
    return ""


def _profile_type_size_align(type_text: str) -> tuple[int, int]:
    cleaned = _clean_profile_type(type_text)
    return _profile_type_size_align_inner(cleaned, set())


def _profile_type_size_align_inner(cleaned: str, seen: set[str]) -> tuple[int, int]:
    if not cleaned:
        return 4, 4
    if _profile_type_is_pointer(cleaned):
        return 8, 8
    normalized = _normalize_c_type(cleaned)
    if normalized in {"UCHAR", "CHAR", "BOOLEAN"}:
        return 1, 1
    if normalized in {"USHORT", "SHORT", "WCHAR"}:
        return 2, 2
    if normalized in {"ULONG", "LONG", "DWORD", "_DWORD", "int", "unsigned int", "NTSTATUS"}:
        return 4, 4
    if normalized in {
        "ULONGLONG",
        "LONGLONG",
        "ULONG_PTR",
        "LONG_PTR",
        "UINT_PTR",
        "INT_PTR",
        "SIZE_T",
        "SSIZE_T",
    }:
        return 8, 8
    if _profile_enum_exists(cleaned):
        return 4, 4
    structure_size = _profile_structure_size(cleaned)
    if structure_size:
        return structure_size, min(8, max(1, structure_size))
    aliases = load_kernel_api_family("aliases")
    alias = aliases.get(cleaned, {}) if isinstance(aliases, dict) else {}
    if isinstance(alias, dict):
        target = _clean_profile_type(str(alias.get("target", "") or ""))
        if target and target != cleaned and target not in seen:
            return _profile_type_size_align_inner(target, seen | {cleaned})
    return 4, 4


def _profile_type_is_pointer(type_text: str) -> bool:
    cleaned = _clean_profile_type(type_text)
    if "*" in cleaned:
        return True
    if cleaned in {"HANDLE", "PVOID", "PCHAR", "PWCHAR", "PSTR", "PWSTR"}:
        return True
    if cleaned.startswith("PFN"):
        return True
    structures = load_kernel_api_family("structures")
    if cleaned.startswith("P") and len(cleaned) > 1 and _profile_structure_name(cleaned[1:], structures):
        return True
    return False


@lru_cache(maxsize=512)
def _profile_structure_size(structure_name: str) -> int:
    layout = _profile_structure_field_layout(structure_name)
    if not layout:
        return 0
    size = 0
    max_align = 1
    for field in layout.values():
        field_size = int(field.get("size", 1) or 1)
        offset = int(field.get("offset", 0) or 0)
        size = max(size, offset + field_size)
        max_align = max(max_align, min(8, field_size))
    return _align_up(size, max_align)


def _profile_enum_exists(enum_name: str) -> bool:
    enums = load_kernel_api_family("enums")
    return isinstance(enums, dict) and enum_name in enums


def _clean_profile_type(type_text: str) -> str:
    text = str(type_text or "").strip()
    text = re.sub(r"\b_[A-Za-z0-9_]*_\b(?:\([^)]*\))?", " ", text)
    text = re.sub(r"\b(?:const|volatile|struct|enum|union)\b", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _profile_array_count(array_text: str) -> int:
    match = re.search(r"\[(?P<count>\d+)\]", array_text or "")
    if not match:
        return 1
    try:
        return max(1, int(match.group("count"), 10))
    except ValueError:
        return 1


def _align_up(value: int, alignment: int) -> int:
    alignment = max(1, alignment)
    return (value + alignment - 1) // alignment * alignment


def _analyze_helper_edge(
    helper: FunctionCapture,
    arguments: list[str],
    passed_buffers: list[str],
    helper_map: dict[str, FunctionCapture],
    max_depth: int,
    depth: int,
    visited: set[str],
) -> HelperContractEdge:
    params = extract_parameters_from_signature(helper.prototype)
    rename_map: dict[str, str] = {}
    for index, (param_name, _type_text) in enumerate(params):
        if index >= len(arguments):
            break
        identifier = _argument_identifier(arguments[index])
        if identifier and _should_rename_helper_param(param_name, _type_text, identifier, passed_buffers):
            rename_map[param_name] = identifier
    helper_text = safe_identifier_replace(helper.pseudocode, rename_map)
    helper_lines = helper_text.splitlines()
    helper_length_aliases = _infer_length_aliases(helper_text)
    typed_field_layouts = _typed_field_layouts_for_params(params, rename_map)
    buffer_element_types = _typed_pointer_elements_for_params(params, rename_map)
    helper_sources: dict[str, dict[str, str]] = {}
    for name in set(passed_buffers):
        length = (
            _length_arguments_for_buffer_with_params(arguments, params, name)
            or _length_arguments_for_buffer(arguments, name)
            or _matching_length_variable(helper_text, name)
        )
        _add_buffer_source(helper_sources, name, "inout", "helper argument", length)
    size_constraints = _recover_size_constraints(
        helper_lines,
        source="helper:%s" % helper.name,
        length_aliases=helper_length_aliases,
        known_lengths=_length_names_from_sources(helper_sources),
    )
    field_accesses = _recover_field_accesses(
        helper_lines,
        helper_sources,
        source="helper:%s" % helper.name,
        typed_field_layouts=typed_field_layouts,
        buffer_element_types=buffer_element_types,
    )
    field_constraints = _recover_field_constraints(helper_lines, field_accesses, source="helper:%s" % helper.name)
    propagated_sizes = [
        _constraint_for_buffer(item, _constraint_buffer_from_sources(item, helper_sources))
        for item in size_constraints
        if _constraint_buffer_from_sources(item, helper_sources)
    ]
    nested_edges = _recover_helper_edges(
        helper_text,
        helper_sources,
        helper_map,
        max_depth=max_depth,
        depth=depth,
        visited=visited,
    )
    return HelperContractEdge(
        callee=helper.name,
        arguments=arguments,
        passed_buffers=passed_buffers,
        resolved=True,
        depth=depth,
        evidence="%s(%s)" % (helper.name, ", ".join(arguments)),
        propagated_size_constraints=propagated_sizes,
        propagated_field_accesses=field_accesses,
        propagated_field_constraints=field_constraints,
        nested_edges=nested_edges,
        warnings=[],
        confidence=0.78 if propagated_sizes or field_accesses or field_constraints or nested_edges else 0.55,
    )


def _should_rename_helper_param(
    param_name: str,
    type_text: str,
    argument_identifier: str,
    passed_buffers: list[str],
) -> bool:
    if argument_identifier in set(passed_buffers):
        return True
    if _looks_like_length_name(argument_identifier):
        return True
    if _helper_param_looks_like_length(param_name, type_text):
        return True
    return bool(_profile_structure_name_from_pointer_type(type_text))


def _native_switch_case_bodies(text: str, dispatcher: str) -> dict[int, list[str]]:
    if not dispatcher:
        return {}
    switch_re = re.compile(r"\bswitch\s*\(\s*(?:\(\s*[^()]+\s*\)\s*)*%s\s*\)" % re.escape(dispatcher))
    lines = (text or "").splitlines()
    cases: dict[int, list[str]] = {}
    for index, line in enumerate(lines):
        if switch_re.search(line):
            _collect_native_switch_case_bodies(lines, index, cases)
    return {value: _trim_case_lines(body) for value, body in cases.items()}


def _collect_native_switch_case_bodies(
    lines: list[str],
    switch_index: int,
    cases: dict[int, list[str]],
) -> None:
    current_values: list[int] = []
    current_body: list[str] = []
    depth = 0
    seen_open = False
    for line in lines[switch_index:]:
        stripped = line.strip()
        if not seen_open:
            opens = stripped.count("{")
            closes = stripped.count("}")
            if not opens:
                continue
            seen_open = True
            depth += opens - closes
            if depth <= 0:
                return
            continue

        case_match = _CASE_LABEL_RE.match(stripped) if depth == 1 else None
        if case_match:
            value = _parse_case_label_value(case_match.group("value"))
            if current_body:
                _store_native_case_body(cases, current_values, current_body)
                current_values = []
                current_body = []
            if value is not None:
                current_values.append(value)
                remainder = stripped[case_match.end():].strip()
                if remainder and remainder not in {"{", "}"}:
                    current_body.append(remainder)
            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0:
                _store_native_case_body(cases, current_values, current_body)
                return
            continue
        if depth == 1 and _is_default_case_line(stripped):
            _store_native_case_body(cases, current_values, current_body)
            current_values = []
            current_body = []
            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0:
                return
            continue

        if current_values:
            if stripped not in {"{", "}"} and not _is_default_case_line(stripped):
                current_body.append(line)
        depth += stripped.count("{") - stripped.count("}")
        if seen_open and depth <= 0:
            _store_native_case_body(cases, current_values, current_body)
            return


def _store_native_case_body(
    cases: dict[int, list[str]],
    values: list[int],
    body: list[str],
) -> None:
    trimmed = _trim_case_lines(body)
    if not trimmed:
        return
    for value in values:
        current = cases.get(value)
        if current is None or _native_case_body_score(trimmed) > _native_case_body_score(current):
            cases[value] = list(trimmed)


def _native_case_body_score(lines: list[str]) -> int:
    score = len([line for line in lines if line.strip()])
    for line in lines:
        lowered = line.lower()
        if "length" in lowered or "size" in lowered or re.search(r"\bv\d+\b", line):
            score += 1
        if "*" in line or "->" in line or "memmove" in lowered or "probe" in lowered:
            score += 3
        if "status_info_length_mismatch" in lowered or "status_invalid_parameter" in lowered:
            score += 2
    return score


def _trim_case_lines(lines: list[str]) -> list[str]:
    result = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == "break;":
            result.append(line)
            continue
        result.append(line)
    return result


def _dispatcher_kind(capture: FunctionCapture, flow: FlowRewrite) -> str:
    name = (capture.name or "").lower()
    prototype = capture.prototype or ""
    dispatcher = (flow.dispatcher or "").lower()
    if "iocontrolcode" in dispatcher or any(decode_ioctl_code(value) for value in flow.recovered_cases):
        return "ioctl"
    if name == "ntsetinformationprocess" or "PROCESSINFOCLASS" in prototype:
        return "ntset_process"
    if name == "ntsetinformationthread" or "THREADINFOCLASS" in prototype:
        return "ntset_thread"
    if name == "ntsetsysteminformation" or "SYSTEM_INFORMATION_CLASS" in prototype:
        return "ntset_system"
    return "generic"


def _has_strong_generic_buffer_evidence(text: str) -> bool:
    lowered = (text or "").lower()
    return "buffer" in lowered and ("length" in lowered or "sizeof" in lowered)


def _looks_like_length_name(name: str) -> bool:
    compact = re.sub(r"[^A-Za-z0-9]", "", name or "").lower()
    return compact.endswith("length") or compact.endswith("size") or compact.endswith("bytes")


def _looks_like_constraint_value(value: str) -> bool:
    return bool(re.fullmatch(_C_VALUE_RE, value or ""))


def _clean_operand(value: str) -> str:
    return re.sub(r"^\(\s*(?:unsigned\s+int|int|ULONG|SIZE_T|DWORD)\s*\)\s*", "", value.strip())


def _invert_relation(relation: str) -> str:
    return {
        "<": ">",
        ">": "<",
        "<=": ">=",
        ">=": "<=",
        "==": "==",
        "!=": "!=",
    }.get(relation, relation)


def _role_from_length(length: str) -> str:
    lowered = (length or "").lower()
    tokens = set(_semantic_name_tokens(length))
    if "output" in lowered or "out" in tokens:
        return "output"
    return "input"


def _role_from_buffer_name(buffer: str) -> str:
    lowered = (buffer or "").lower()
    if "output" in lowered or "userbuffer" in lowered:
        return "output"
    if "systembuffer" in lowered:
        return "inout"
    return "input"


def _constraints_apply_to_source(info: dict[str, str], constraints: list[BufferSizeConstraint]) -> bool:
    length_text = info.get("length", "")
    if not length_text:
        return False
    lengths = {item.strip() for item in length_text.split(",") if item.strip()}
    return any(item.length in lengths for item in constraints)


def _constraint_matches_buffer(item: BufferSizeConstraint, info: dict[str, str], role: str) -> bool:
    length_text = info.get("length", "")
    lengths = {part.strip() for part in length_text.split(",") if part.strip()}
    if item.length in lengths:
        return True
    if role == "inout" and not lengths and _looks_like_length_name(item.length):
        return True
    return False


def _constraint_for_buffer(item: BufferSizeConstraint, buffer: str) -> BufferSizeConstraint:
    return BufferSizeConstraint(
        buffer=buffer,
        length=item.length,
        relation=item.relation,
        value=item.value,
        valid_relation=item.valid_relation,
        valid_value=item.valid_value,
        role=item.role,
        evidence=item.evidence,
        source=item.source,
        confidence=item.confidence,
    )


def _constraint_buffer_from_sources(item: BufferSizeConstraint, sources: dict[str, dict[str, str]]) -> str:
    for buffer, info in sources.items():
        if _constraint_matches_buffer(item, info, info.get("role", "")):
            return buffer
    return ""


def _assignment_left(line: str) -> str:
    match = _ASSIGNMENT_RE.search(line)
    if not match:
        return ""
    return match.group("left").strip()


def _access_kind(expression: str, left_expr: str) -> str:
    if left_expr and expression in left_expr:
        return "write"
    return "read"


def _merge_field_access(access_by_key: dict[tuple[str, int, str, str], FieldAccess], item: FieldAccess) -> None:
    key = (item.buffer, item.offset, item.field, item.type)
    current = access_by_key.get(key)
    if current is None:
        access_by_key[key] = item
        return
    if current.access != item.access:
        current.access = "read_write"
    if len(item.evidence) < len(current.evidence):
        current.evidence = item.evidence


def _field_expression_for_access(access: FieldAccess, line: str) -> str:
    if access.field.startswith("field_"):
        offset = access.offset
        type_text = access.type or "_BYTE"
        candidates = [
            "*(%s *)(%s + %d)" % (type_text, access.buffer, offset),
            "*(%s *)%s" % (type_text, access.buffer) if offset == 0 else "",
        ]
        for candidate in candidates:
            if candidate and candidate in line:
                return candidate
        return ""
    expression = "%s->%s" % (access.buffer, access.field)
    return expression if expression in line else ""


def _parse_offset(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        return 0


def _normalize_c_type(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", (value or "").strip())
    aliases = {
        "_DWORD": "ULONG",
        "DWORD": "ULONG",
        "_QWORD": "ULONGLONG",
        "__int64": "ULONGLONG",
        "char": "CHAR",
        "_BYTE": "UCHAR",
        "BYTE": "UCHAR",
        "_WORD": "USHORT",
        "WORD": "USHORT",
    }
    return aliases.get(cleaned, cleaned)


def _sizeof_type(type_text: str) -> int:
    normalized = _normalize_c_type(type_text)
    if normalized in {"UCHAR", "CHAR", "BYTE", "_BYTE"}:
        return 1
    if normalized in {"USHORT", "WORD", "_WORD"}:
        return 2
    if normalized in {"ULONG", "LONG", "DWORD", "_DWORD", "int", "unsigned int"}:
        return 4
    if normalized in {"__int128", "_OWORD", "__m128i", "__m128"}:
        return 16
    return 8


def _field_name(offset: int) -> str:
    return "field_0x%02X" % max(0, offset)


def _dedupe_field_constraints(items: list[FieldConstraint]) -> list[FieldConstraint]:
    result = []
    seen = set()
    for item in items:
        key = (
            item.buffer,
            item.offset,
            item.field,
            item.relation,
            item.value,
            item.mask,
            item.valid_relation,
            item.valid_value,
            item.evidence,
            item.source,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _structure_name(kind: str, command_value: int, command_name: str, role: str) -> str:
    suffix = "INOUT" if role == "inout" else ("OUTPUT" if role == "output" else "INPUT")
    if kind == "ioctl":
        return "PF_IOCTL_%08X_%s" % (command_value & 0xFFFFFFFF, suffix)
    prefix = (
        "PF_SYSTEM"
        if kind == "ntset_system"
        else "PF_PROCESS"
        if kind == "ntset_process"
        else "PF_THREAD"
        if kind == "ntset_thread"
        else "PF_COMMAND"
    )
    if command_name:
        name = re.sub(r"[^A-Za-z0-9_]", "_", command_name).strip("_")
        if name:
            return "%s_%s_%s" % (prefix, name, suffix)
    return "%s_%d_%s" % (prefix, command_value, suffix)


def _contract_warnings(
    kind: str,
    command_value: int,
    buffers: list[BufferContract],
    size_constraints: list[BufferSizeConstraint],
    field_accesses: list[FieldAccess],
    helper_edges: list[HelperContractEdge],
) -> list[str]:
    warnings: list[str] = []
    decoded = decode_ioctl_code(command_value) if kind == "ioctl" else None
    if decoded is not None and decoded.method_name == "METHOD_BUFFERED":
        if any(buffer.role == "inout" for buffer in buffers):
            warnings.append("METHOD_BUFFERED uses one system buffer for input and output; verify direction per field")
    equality_values: dict[str, set[str]] = {}
    for item in size_constraints:
        if item.relation == "==":
            equality_values.setdefault(item.length, set()).add(item.value)
    for length, values in equality_values.items():
        if len(values) > 1:
            warnings.append("conflicting equality size constraints for %s: %s" % (length, ", ".join(sorted(values))))
    types_by_field: dict[tuple[str, int], set[str]] = {}
    for access in field_accesses:
        types_by_field.setdefault((access.buffer, access.offset), set()).add(access.type)
    for (buffer, offset), types in types_by_field.items():
        if len(types) > 1:
            warnings.append("field offset used with multiple types: %s+0x%X = %s" % (buffer, offset, ", ".join(sorted(types))))
    for edge in helper_edges:
        for warning in edge.warnings:
            if warning not in warnings:
                warnings.append("%s: %s" % (edge.callee, warning))
    return warnings


def _command_confidence(
    buffers: list[BufferContract],
    helper_edges: list[HelperContractEdge],
    warnings: list[str],
) -> float:
    score = 0.45
    if buffers:
        score += 0.25
    if any(buffer.field_accesses for buffer in buffers):
        score += 0.12
    if any(buffer.size_constraints for buffer in buffers):
        score += 0.10
    if any(edge.resolved for edge in helper_edges):
        score += 0.05
    score -= min(0.20, len(warnings) * 0.03)
    return round(max(0.10, min(0.95, score)), 2)


def _argument_identifier(argument: str) -> str:
    value = _strip_leading_casts(argument or "")
    value = re.sub(r"^\&\s*", "", value)
    match = re.fullmatch(_IDENT_RE, value)
    return match.group(0) if match else ""


def _strip_leading_casts(value: str) -> str:
    result = (value or "").strip()
    while True:
        stripped = re.sub(r"^\(\s*[^()]+\s*\)\s*", "", result, count=1)
        if stripped == result:
            return result
        result = stripped.strip()


def _normalize_helper_captures(
    helper_captures: dict[str, FunctionCapture] | Iterable[FunctionCapture] | None,
) -> dict[str, FunctionCapture]:
    if helper_captures is None:
        return {}
    if isinstance(helper_captures, dict):
        return {name: capture for name, capture in helper_captures.items() if name and capture is not None}
    return {capture.name: capture for capture in helper_captures if capture.name}


def _looks_like_buffer_name(name: str) -> bool:
    if _looks_like_length_name(name):
        return False
    lowered = (name or "").lower()
    return "buffer" in lowered or lowered in {"processinformation", "systeminformation", "input", "output"}

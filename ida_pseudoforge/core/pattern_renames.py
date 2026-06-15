from __future__ import annotations

import re
from typing import Any

from ida_pseudoforge.core.kernel_api import kernel_function_metadata
from ida_pseudoforge.core.normalize import extract_parameters_from_signature, find_matching_paren, split_parameters_with_spans
from ida_pseudoforge.core.plan_schema import FunctionCapture, RenameSuggestion


def pattern_renames(
    capture: FunctionCapture,
    api_semantic_diagnostics: list[dict[str, Any]] | None = None,
) -> list[RenameSuggestion]:
    text = capture.pseudocode
    suggestions = []
    patterns = [
        (
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(unsigned\s+int\)\s*a3\b",
            "inputLength",
            0.93,
            "local is a 32-bit copy of SystemInformationLength",
        ),
        (
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*a2\b",
            "systemInfo128",
            0.90,
            "local aliases SystemInformation as a vector-sized pointer",
        ),
        (
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(int\)\s*a1\b",
            "infoClass",
            0.97,
            "local is the integer dispatcher copied from SystemInformationClass",
        ),
        (
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*KeGetCurrentThread\(\)->PreviousMode\b",
            "previousMode",
            0.99,
            "local captures current thread PreviousMode",
        ),
        (
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*KeGetCurrentThread\(\)->ApcState\.Process\b",
            "currentProcess",
            0.94,
            "local captures current thread process object",
        ),
    ]
    for pattern, new_name, confidence, evidence in patterns:
        match = re.search(pattern, text)
        if not match:
            continue
        old_name = match.group("dst")
        if new_name == "systemInfo128":
            alias_kind = _m128_pointer_alias_kind(capture, old_name, "a2")
            if not alias_kind:
                continue
            if alias_kind == "reused":
                new_name = "infoBuffer128"
                confidence = min(confidence, 0.86)
                evidence = "typed m128 buffer pointer is reused after the original parameter alias"
        if old_name == new_name:
            continue
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=old_name,
                new=new_name,
                confidence=confidence,
                source="pattern",
                evidence=evidence,
            )
        )
    suggestions.extend(_saved_previous_mode_renames(capture))
    suggestions.extend(_same_named_field_local_renames(capture))
    suggestions.extend(_runtime_memory_parameter_renames(capture))
    suggestions.extend(_output_buffer_contract_parameter_renames(capture))
    suggestions.extend(_structure_base_parameter_renames(capture))
    suggestions.extend(_api_out_parameter_local_renames(capture, api_semantic_diagnostics))
    suggestions.extend(_api_result_local_renames(capture))
    suggestions.extend(_api_argument_local_renames(capture, api_semantic_diagnostics))
    suggestions.extend(_list_entry_head_parameter_renames(capture))
    suggestions.extend(_list_entry_head_local_renames(capture))
    suggestions.extend(_lookaside_entry_allocation_renames(capture))
    suggestions.extend(_cpu_set_mask_renames(text))
    suggestions.extend(_pool_allocation_renames(text))
    return suggestions


def _cpu_set_mask_renames(text: str) -> list[RenameSuggestion]:
    suggestions = []
    suggestions.extend(_cpu_set_modify_mask_renames(text))
    suggestions.extend(_cpu_set_tag_mask_renames(text))
    suggestions.extend(_cpu_set_allowed_mask_renames(text))
    return suggestions


def _cpu_set_modify_mask_renames(text: str) -> list[RenameSuggestion]:
    suggestions = []
    for match in re.finditer(
        r"\bmemmove\(\s*(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*&[A-Za-z_][A-Za-z0-9_]*->m128i_u64\[1\]\s*,\s*(?:\([^)]+\)\s*)?(?P<size>[A-Za-z_][A-Za-z0-9_]*)\s*\);",
        text,
    ):
        old_name = match.group("dst")
        size_name = match.group("size")
        tail = text[match.end() : match.end() + 800]
        if _first_cpu_set_callee(tail) != "KeModifySystemAllowedCpuSets":
            continue
        if old_name != "cpuSetMaskStackBuffer":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=old_name,
                    new="cpuSetMaskStackBuffer",
                    confidence=0.90,
                    source="pattern",
                    evidence="stack buffer receives CPU set mask entries before KeModifySystemAllowedCpuSets",
                )
            )
        if size_name != "cpuSetMaskBytes":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=size_name,
                    new="cpuSetMaskBytes",
                    confidence=0.88,
                    source="pattern",
                    evidence="byte count for CPU set mask stack buffer",
                )
            )
        _append_cpu_set_count_renames(suggestions, tail, size_name)
        _append_cpu_set_buffer_alias_renames(suggestions, tail, old_name)
        _append_cpu_set_operation_renames(suggestions, text, tail, match.start())
    return suggestions


def _append_cpu_set_count_renames(
    suggestions: list[RenameSuggestion],
    tail: str,
    size_name: str,
) -> None:
    count_match = re.search(
        r"\b(?P<count>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*>>\s*3\s*;" % re.escape(size_name),
        tail,
    )
    if count_match and count_match.group("count") != "cpuSetCount":
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=count_match.group("count"),
                new="cpuSetCount",
                confidence=0.86,
                source="pattern",
                evidence="CPU set mask byte count converted to element count",
            )
        )


def _append_cpu_set_buffer_alias_renames(
    suggestions: list[RenameSuggestion],
    tail: str,
    old_name: str,
) -> None:
    buffer_match = re.search(
        r"\b(?P<buffer>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*;" % re.escape(old_name),
        tail,
    )
    if buffer_match and buffer_match.group("buffer") != "cpuSetMaskBuffer":
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=buffer_match.group("buffer"),
                new="cpuSetMaskBuffer",
                confidence=0.86,
                source="pattern",
                evidence="pointer aliases CPU set mask stack buffer",
            )
        )


def _append_cpu_set_operation_renames(
    suggestions: list[RenameSuggestion],
    text: str,
    tail: str,
    match_start: int,
) -> None:
    prefix = text[max(0, match_start - 500) : match_start]
    operation_matches = list(
        re.finditer(
            r"\b(?P<operation>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"[A-Za-z_][A-Za-z0-9_]*->m128i_i64\[0\]\s*;",
            prefix,
        )
    )
    if not operation_matches:
        return
    operation_name = operation_matches[-1].group("operation")
    if not _looks_like_cpu_set_operation_use(tail, operation_name):
        return
    if operation_name != "cpuSetOperation":
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=operation_name,
                new="cpuSetOperation",
                confidence=0.86,
                source="pattern",
                evidence="operation selector read from the CPU set request header",
            )
        )
    operation32_match = re.search(
        r"\b(?P<operation32>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*;" % re.escape(operation_name),
        tail,
    )
    if operation32_match and operation32_match.group("operation32") != "cpuSetOperation32":
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=operation32_match.group("operation32"),
                new="cpuSetOperation32",
                confidence=0.82,
                source="pattern",
                evidence="32-bit operation selector passed to KeModifySystemAllowedCpuSets",
            )
        )


def _cpu_set_tag_mask_renames(text: str) -> list[RenameSuggestion]:
    suggestions = []
    for match in re.finditer(
        r"\bmemmove\(\s*(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*&[A-Za-z_][A-Za-z0-9_]*->m128i_u64\[1\]\s*,\s*(?:\([^)]+\)\s*)?(?P<size>[A-Za-z_][A-Za-z0-9_]*)\s*\);",
        text,
    ):
        old_name = match.group("dst")
        size_name = match.group("size")
        tail = text[match.end() : match.end() + 800]
        if _first_cpu_set_callee(tail) != "KeSetTagCpuSets":
            continue
        if old_name != "cpuSetTagMaskStackBuffer":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=old_name,
                    new="cpuSetTagMaskStackBuffer",
                    confidence=0.88,
                    source="pattern",
                    evidence="stack buffer receives CPU set tag mask entries before KeSetTagCpuSets",
                )
            )
        if size_name != "cpuSetTagMaskBytes":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=size_name,
                    new="cpuSetTagMaskBytes",
                    confidence=0.86,
                    source="pattern",
                    evidence="byte count for CPU set tag mask stack buffer",
                )
            )
    return suggestions


def _cpu_set_allowed_mask_renames(text: str) -> list[RenameSuggestion]:
    suggestions = []
    for match in re.finditer(
        r"\bmemmove\(\s*(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*(?!&)(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*(?:\([^)]+\)\s*)?(?P<size>[A-Za-z_][A-Za-z0-9_]*)\s*\);",
        text,
    ):
        old_name = match.group("dst")
        tail = text[match.end() : match.end() + 800]
        if _first_cpu_set_callee(tail) != "KeModifySystemAllowedCpuSets":
            continue
        if old_name != "cpuSetAllowedMaskStackBuffer":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=old_name,
                    new="cpuSetAllowedMaskStackBuffer",
                    confidence=0.86,
                    source="pattern",
                    evidence="stack buffer receives direct CPU set mask before KeModifySystemAllowedCpuSets",
                )
            )
    return suggestions


def _pool_allocation_renames(text: str) -> list[RenameSuggestion]:
    suggestions = []
    for match in re.finditer(
        r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(void\s*\*\)\s*ExAllocatePool2\s*\(",
        text,
    ):
        old_name = match.group("dst")
        if old_name != "allocatedBuffer":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=old_name,
                    new="allocatedBuffer",
                    confidence=0.88,
                    source="pattern",
                    evidence="local receives an ExAllocatePool2 allocation result",
                )
            )
    return suggestions


def _api_out_parameter_local_renames(
    capture: FunctionCapture,
    diagnostics: list[dict[str, Any]] | None = None,
) -> list[RenameSuggestion]:
    local_names = {var.name for var in capture.lvars if var.name}
    byref_names = _byref_local_names(capture.pseudocode)
    large_dispatcher = _looks_like_large_dispatcher(capture.pseudocode or "")
    suggestions = []
    for call in _iter_profiled_calls(capture.pseudocode):
        params = call["params"]
        arguments = call["arguments"]
        for index, argument in enumerate(arguments):
            if index >= len(params):
                continue
            local_name = _addressed_local_name(argument)
            if not local_name or local_name not in local_names:
                continue
            if not _looks_like_generic_temporary(local_name):
                continue
            if byref_names and local_name not in byref_names:
                _append_api_semantic_diagnostic(
                    diagnostics,
                    stage="api-out-param",
                    reason="not_byref_local",
                    old=local_name,
                    callee=str(call["name"]),
                    argument_index=index,
                    argument=argument,
                )
                continue
            param = params[index]
            param_name = str(param.get("name", ""))
            param_type = str(param.get("type", ""))
            if not _is_pointer_like_profile_type(param_type):
                _append_api_semantic_diagnostic(
                    diagnostics,
                    stage="api-out-param",
                    reason="not_pointer_profile_type",
                    old=local_name,
                    callee=str(call["name"]),
                    argument_index=index,
                    argument=argument,
                    parameter=param_name,
                    parameter_type=param_type,
                )
                continue
            new_name = _semantic_name_from_api_parameter(param_name, param_type, str(call["name"]))
            if not new_name or new_name == local_name:
                _append_api_semantic_diagnostic(
                    diagnostics,
                    stage="api-out-param",
                    reason="weak_parameter_name",
                    old=local_name,
                    new=new_name,
                    callee=str(call["name"]),
                    argument_index=index,
                    argument=argument,
                    parameter=param_name,
                    parameter_type=param_type,
                )
                continue
            if large_dispatcher:
                _append_api_semantic_diagnostic(
                    diagnostics,
                    stage="api-out-param",
                    reason="large_dispatcher",
                    old=local_name,
                    new=new_name,
                    callee=str(call["name"]),
                    argument_index=index,
                    argument=argument,
                    parameter=param_name,
                    parameter_type=param_type,
                )
                continue
            if _would_shadow_case_variant(local_names, local_name, new_name):
                _append_api_semantic_diagnostic(
                    diagnostics,
                    stage="api-out-param",
                    reason="shadow",
                    old=local_name,
                    new=new_name,
                    callee=str(call["name"]),
                    argument_index=index,
                    argument=argument,
                    parameter=param_name,
                    parameter_type=param_type,
                )
                continue
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=local_name,
                    new=new_name,
                    confidence=0.86,
                    source="api-out-param",
                    evidence="%s argument %d is an address-taken local for profile parameter %s"
                    % (call["name"], index, param_name),
                )
            )
    return _unique_semantic_suggestions(suggestions, diagnostics, "api-out-param")


def _api_result_local_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    type_by_name = {var.name: var.type for var in capture.lvars if var.name}
    local_names = set(type_by_name)
    suggestions = []
    assignment_pattern = re.compile(
        r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?"
        r"(?P<callee>[A-Za-z_][A-Za-z0-9_]*)\s*\("
    )
    for match in assignment_pattern.finditer(capture.pseudocode):
        old_name = match.group("dst")
        if not _looks_like_generic_temporary(old_name) and not _looks_like_pascal_local(old_name):
            continue
        callee = match.group("callee")
        metadata = kernel_function_metadata(callee)
        return_type = str(metadata.get("return_type", ""))
        if not return_type or return_type.upper() == "VOID":
            continue
        new_name = _semantic_name_from_api_result(callee, return_type, type_by_name.get(old_name, ""))
        if not new_name or new_name == old_name:
            continue
        if _would_shadow_case_variant(local_names, old_name, new_name):
            continue
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=old_name,
                new=new_name,
                confidence=0.84,
                source="api-result",
                evidence="local receives %s return value of %s" % (return_type, callee),
            )
        )
    return _unique_semantic_suggestions(suggestions)


def _api_argument_local_renames(
    capture: FunctionCapture,
    diagnostics: list[dict[str, Any]] | None = None,
) -> list[RenameSuggestion]:
    local_names = {var.name for var in capture.lvars if var.name}
    parameter_names = {name for name, _type_text in extract_parameters_from_signature(capture.prototype)}
    candidate_names = local_names | parameter_names
    large_dispatcher = _looks_like_large_dispatcher(capture.pseudocode or "")
    suggestions = []
    for call in _iter_profiled_calls(capture.pseudocode):
        params = call["params"]
        arguments = call["arguments"]
        for index, argument in enumerate(arguments):
            if index >= len(params):
                continue
            local_name = _plain_local_argument_name(argument)
            if not local_name or local_name not in candidate_names:
                continue
            if not (_looks_like_generic_temporary(local_name) or _looks_like_generic_argument(local_name)):
                continue
            is_parameter = local_name in parameter_names
            param = params[index]
            param_name = str(param.get("name", ""))
            param_type = str(param.get("type", ""))
            new_name = _semantic_name_from_api_parameter(param_name, param_type, str(call["name"]))
            if not new_name or new_name == local_name:
                _append_api_semantic_diagnostic(
                    diagnostics,
                    stage="api-argument",
                    reason="weak_parameter_name",
                    old=local_name,
                    new=new_name,
                    callee=str(call["name"]),
                    argument_index=index,
                    argument=argument,
                    parameter=param_name,
                    parameter_type=param_type,
                    candidate_kind="arg" if is_parameter else "lvar",
                )
                continue
            if local_name in local_names and large_dispatcher:
                _append_api_semantic_diagnostic(
                    diagnostics,
                    stage="api-argument",
                    reason="large_dispatcher",
                    old=local_name,
                    new=new_name,
                    callee=str(call["name"]),
                    argument_index=index,
                    argument=argument,
                    parameter=param_name,
                    parameter_type=param_type,
                    candidate_kind="lvar",
                )
                continue
            if is_parameter and _is_unsafe_wrapper_parameter_role(new_name):
                _append_api_semantic_diagnostic(
                    diagnostics,
                    stage="api-argument",
                    reason="unsafe_wrapper_role",
                    old=local_name,
                    new=new_name,
                    callee=str(call["name"]),
                    argument_index=index,
                    argument=argument,
                    parameter=param_name,
                    parameter_type=param_type,
                    candidate_kind="arg",
                )
                continue
            if _would_shadow_case_variant(candidate_names, local_name, new_name):
                _append_api_semantic_diagnostic(
                    diagnostics,
                    stage="api-argument",
                    reason="shadow",
                    old=local_name,
                    new=new_name,
                    callee=str(call["name"]),
                    argument_index=index,
                    argument=argument,
                    parameter=param_name,
                    parameter_type=param_type,
                    candidate_kind="arg" if is_parameter else "lvar",
                )
                continue
            suggestions.append(
                RenameSuggestion(
                    kind="arg" if is_parameter else "lvar",
                    old=local_name,
                    new=new_name,
                    confidence=0.86 if is_parameter else 0.82,
                    source="api-argument",
                    evidence="local is passed to %s profile parameter %s"
                    % (call["name"], param_name),
                )
            )
    return _unique_semantic_suggestions(suggestions, diagnostics, "api-argument")


def _saved_previous_mode_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    text = capture.pseudocode
    type_by_name = {var.name: var.type for var in capture.lvars}
    previous_mode_sources = {
        match.group("dst")
        for match in re.finditer(
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*KeGetCurrentThread\(\)->PreviousMode\b",
            text,
        )
    }
    suggestions = []
    for source in previous_mode_sources:
        for match in re.finditer(
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*;" % re.escape(source),
            text,
        ):
            old_name = match.group("dst")
            if old_name == source:
                continue
            type_text = type_by_name.get(old_name, "")
            if type_text and "KPROCESSOR_MODE" not in type_text:
                continue
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=old_name,
                    new="savedPreviousMode",
                    confidence=0.88,
                    source="pattern",
                    evidence="local stores a saved copy of PreviousMode",
                )
            )
    return suggestions


def _same_named_field_local_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    local_names = {var.name for var in capture.lvars if var.name}
    if not local_names:
        return []

    suggestions = []
    existing_names = set(local_names)
    for match in re.finditer(
        r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;\n]*?(?:->|\.)\s*(?P=dst)\s*;",
        capture.pseudocode,
    ):
        old_name = match.group("dst")
        if old_name not in local_names:
            continue
        new_name = _lower_camel_from_pascal(old_name)
        if not new_name or new_name == old_name or new_name in existing_names:
            continue
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=old_name,
                new=new_name,
                confidence=0.84,
                source="field-fallback",
                evidence="local shadows a same-named structure field",
            )
        )
    return suggestions


def _structure_base_parameter_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    candidates = []
    for old_name, _type_text in extract_parameters_from_signature(capture.prototype):
        if not re.fullmatch(r"a\d+", old_name or ""):
            continue
        offsets = _constant_pointer_offset_uses(capture.pseudocode, old_name)
        if len(offsets) >= 3:
            candidates.append(old_name)
    if len(candidates) != 1:
        return []
    old_name = candidates[0]
    return [
        RenameSuggestion(
            kind="arg",
            old=old_name,
            new="context",
            confidence=0.86,
            source="structure-base",
            evidence="parameter is repeatedly used as a constant-offset structure base",
        )
    ]


def _runtime_memory_parameter_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    params = extract_parameters_from_signature(capture.prototype)
    if len(params) != 3:
        return []
    destination_name, destination_type = params[0]
    source_or_fill_name, source_or_fill_type = params[1]
    byte_count_name, byte_count_type = params[2]
    if not _is_pointer_type(destination_type) or not _is_integer_size_type(byte_count_type):
        return []
    text = capture.pseudocode
    if _looks_like_memmove_body(text, destination_name, source_or_fill_name, byte_count_name, source_or_fill_type):
        return _parameter_rename_suggestions(
            [
                (destination_name, "destination", 0.92, "first pointer parameter is returned and used as the memory copy destination"),
                (source_or_fill_name, "source", 0.92, "second pointer parameter is used as the memory copy source"),
                (byte_count_name, "byteCount", 0.90, "third integer parameter controls the memory copy byte count"),
            ],
            source="runtime-memory",
        )
    if _looks_like_memset_body(text, destination_name, source_or_fill_name, byte_count_name, source_or_fill_type):
        return _parameter_rename_suggestions(
            [
                (destination_name, "destination", 0.92, "first pointer parameter is returned and used as the memory fill destination"),
                (source_or_fill_name, "fillByte", 0.91, "second byte-sized parameter is expanded into a repeated fill pattern"),
                (byte_count_name, "byteCount", 0.90, "third integer parameter controls the memory fill byte count"),
            ],
            source="runtime-memory",
        )
    return []


def _parameter_rename_suggestions(
    entries: list[tuple[str, str, float, str]],
    *,
    source: str,
) -> list[RenameSuggestion]:
    suggestions = []
    for old_name, new_name, confidence, evidence in entries:
        if old_name == new_name:
            continue
        suggestions.append(
            RenameSuggestion(
                kind="arg",
                old=old_name,
                new=new_name,
                confidence=confidence,
                source=source,
                evidence=evidence,
            )
        )
    return suggestions


def _output_buffer_contract_parameter_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    params = extract_parameters_from_signature(capture.prototype)
    if len(params) != 4:
        return []
    output_name, output_type = params[1]
    length_name, length_type = params[2]
    return_length_name, return_length_type = params[3]
    if not _is_pointer_type(output_type):
        return []
    if not _is_integer_size_type(length_type):
        return []
    if not _is_pointer_type(return_length_type):
        return []
    text = capture.pseudocode
    if not _looks_like_output_buffer_contract(text, output_name, length_name, return_length_name):
        return []
    return _parameter_rename_suggestions(
        [
            (output_name, "outputBuffer", 0.88, "pointer parameter receives structured output writes"),
            (length_name, "outputBufferLength", 0.88, "integer parameter bounds the structured output buffer"),
            (return_length_name, "returnLength", 0.88, "pointer parameter receives required or written output length"),
        ],
        source="buffer-contract",
    )


def _looks_like_output_buffer_contract(
    text: str,
    output_name: str,
    length_name: str,
    return_length_name: str,
) -> bool:
    output = re.escape(output_name)
    length = re.escape(length_name)
    return_length = re.escape(return_length_name)
    has_length_guard = re.search(r"\b%s\s*<\s*(?:0x[0-9A-Fa-f]+|\d+)\b" % length, text)
    has_output_header_store = re.search(r"\*\s*%s\s*=|%s\s*\[\s*(?:0|1|2|3|4|5)\s*\]\s*=" % (output, output), text)
    has_indexed_output_store = re.search(r"\b%s\s*\[[^;\n]+\]\s*=|&\s*%s\s*\[[^;\n]+\]" % (output, output), text)
    has_return_length_store = re.search(r"\*\s*%s\s*=" % return_length, text)
    return bool(has_length_guard and has_output_header_store and has_indexed_output_store and has_return_length_store)


def _looks_like_memmove_body(
    text: str,
    destination_name: str,
    source_name: str,
    byte_count_name: str,
    source_type: str,
) -> bool:
    if not _is_pointer_type(source_type):
        return False
    if not _returns_first_parameter(text, destination_name):
        return False
    destination = re.escape(destination_name)
    source = re.escape(source_name)
    byte_count = re.escape(byte_count_name)
    has_overlap_branch = re.search(r"\b%s\s*<\s*%s\b|\b%s\s*<\s*%s\b" % (source, destination, destination, source), text)
    has_pointer_delta = re.search(r"\b%s\s*-\s*%s\b|\b%s\s*-\s*%s\b" % (source, destination, destination, source), text)
    has_byte_count_guard = re.search(
        r"\b%s\s*(?:<|>|<=|>=|==|!=)\s*(?:0x[0-9A-Fa-f]+|\d+)|\b(?:if|while)\s*\(\s*%s\s*\)"
        % (byte_count, byte_count),
        text,
    )
    has_sized_access = re.search(
        r"\b%s\s*\[\s*%s\b|\b%s\s*\[\s*%s\b|&\s*%s\s*\[\s*%s\b|&\s*%s\s*\[\s*%s\b"
        % (destination, byte_count, source, byte_count, destination, byte_count, source, byte_count),
        text,
    )
    return bool(has_overlap_branch and has_pointer_delta and has_byte_count_guard and has_sized_access)


def _looks_like_memset_body(
    text: str,
    destination_name: str,
    fill_name: str,
    byte_count_name: str,
    fill_type: str,
) -> bool:
    if _is_pointer_type(fill_type):
        return False
    if not _returns_first_parameter(text, destination_name):
        return False
    destination = re.escape(destination_name)
    fill = re.escape(fill_name)
    byte_count = re.escape(byte_count_name)
    has_fill_expansion = re.search(
        r"(?:0x0?101010101010101(?:LL|uLL|ULL)?\s*\*\s*%s|%s\s*\*\s*0x0?101010101010101(?:LL|uLL|ULL)?)"
        % (fill, fill),
        text,
    )
    has_byte_count_guard = re.search(r"\b%s\s*(?:<|>|<=|>=|==|!=)\s*(?:0x[0-9A-Fa-f]+|\d+)" % byte_count, text)
    has_destination_store = re.search(r"\*\s*\([^;\n)]*\*\s*\)\s*%s\s*=" % destination, text) or re.search(
        r"\*\s*%s\s*=" % destination,
        text,
    )
    has_sized_destination_access = re.search(r"\b%s\s*\[\s*%s\b|&\s*%s\s*\[\s*%s\b" % (destination, byte_count, destination, byte_count), text)
    return bool(has_fill_expansion and has_byte_count_guard and (has_destination_store or has_sized_destination_access))


def _returns_first_parameter(text: str, name: str) -> bool:
    escaped = re.escape(name)
    direct_return = re.search(r"\breturn\s+(?:\([^)]+\)\s*)?%s\s*;" % escaped, text)
    if direct_return:
        return True
    alias_pattern = re.compile(
        r"\b(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?%s\s*;" % escaped
    )
    for match in alias_pattern.finditer(text):
        alias_name = match.group("alias")
        if _alias_is_returned_without_reassignment(text, alias_name, match.end()):
            return True
    return False


def _alias_is_returned_without_reassignment(text: str, alias_name: str, start_index: int) -> bool:
    escaped = re.escape(alias_name)
    tail = text[start_index:]
    return_match = re.search(r"\breturn\s+%s\s*;" % escaped, tail)
    if not return_match:
        return False
    before_return = tail[: return_match.start()]
    mutation_match = re.search(
        r"(?m)^\s*%s\s*(?:[-+*/%%&|^]?=|\+\+|--)|^\s*(?:\+\+|--)\s*%s\b"
        % (escaped, escaped),
        before_return,
    )
    return mutation_match is None


def _is_pointer_type(type_text: str) -> bool:
    return "*" in (type_text or "") or "&" in (type_text or "")


def _is_integer_size_type(type_text: str) -> bool:
    text = type_text or ""
    if _is_pointer_type(text):
        return False
    return bool(re.search(r"\b(?:size_t|SIZE_T|__int64|int64|ULONG|DWORD|int|char|unsigned|signed)\b", text))


def _constant_pointer_offset_uses(text: str, name: str) -> set[str]:
    offsets: set[str] = set()
    escaped = re.escape(name)
    for line in (text or "").splitlines():
        if not re.search(r"\b%s\s*\+" % escaped, line):
            continue
        if not _line_has_pointer_offset_evidence(line, name):
            continue
        for match in re.finditer(r"\b%s\s*\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)\b" % escaped, line):
            offsets.add(match.group("offset").lower())
    return offsets


def _line_has_pointer_offset_evidence(line: str, name: str) -> bool:
    escaped = re.escape(name)
    return bool(
        re.search(r"\*\s*\([^;\n)]*\*\s*\)\s*\(\s*%s\s*\+" % escaped, line)
        or re.search(r"\(\s*(?:P[A-Z0-9_]+|struct\s+[A-Za-z_][A-Za-z0-9_]*\s*\*[\*\s]*|[A-Za-z_][A-Za-z0-9_\s]*\*[\*\s]*)\)\s*\(\s*%s\s*\+" % escaped, line)
    )


def _list_entry_head_parameter_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    candidates = []
    for old_name, type_text in extract_parameters_from_signature(capture.prototype):
        if "*" not in type_text:
            continue
        if _looks_like_list_entry_head_parameter(capture.pseudocode, old_name):
            candidates.append(old_name)
    if len(candidates) != 1:
        return []
    old_name = candidates[0]
    if old_name == "listHead":
        return []
    return [
        RenameSuggestion(
            kind="arg",
            old=old_name,
            new="listHead",
            confidence=0.90,
            source="kernel-list",
            evidence="pointer parameter is used as a self-referential LIST_ENTRY head",
        )
    ]


def _list_entry_head_local_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    candidates = []
    for local in capture.lvars:
        if "*" not in (local.type or ""):
            continue
        if _looks_like_list_entry_head_local(capture.pseudocode, local.name):
            candidates.append(local.name)
    if len(candidates) != 1:
        return []
    old_name = candidates[0]
    if old_name == "listHead":
        return []
    return [
        RenameSuggestion(
            kind="lvar",
            old=old_name,
            new="listHead",
            confidence=0.88,
            source="kernel-list",
            evidence="local pointer is used as a self-referential LIST_ENTRY head",
        )
    ]


def _lookaside_entry_allocation_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    candidates = []
    for match in re.finditer(
        r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?"
        r"ExAllocateFromNPagedLookasideList\s*\(",
        capture.pseudocode,
    ):
        old_name = match.group("dst")
        if _looks_like_generic_temporary(old_name):
            candidates.append(old_name)
    candidates = _unique_preserve_order(candidates)
    if len(candidates) != 1:
        return []
    old_name = candidates[0]
    if old_name == "lookasideEntry":
        return []
    return [
        RenameSuggestion(
            kind="lvar",
            old=old_name,
            new="lookasideEntry",
            confidence=0.86,
            source="kernel-list",
            evidence="local receives a single lookaside-list allocation result",
        )
    ]


def _looks_like_list_entry_head_parameter(text: str, name: str) -> bool:
    escaped = re.escape(name)
    self_flink_patterns = (
        r"\(\s*[^)]*\*\s*\)\s*\*\s*%s\s*==\s*%s\b" % (escaped, escaped),
        r"\*\s*%s\s*==\s*%s\b" % (escaped, escaped),
        r"\b%s\s*==\s*\(\s*[^)]*\*\s*\)\s*\*\s*%s\b" % (escaped, escaped),
    )
    has_self_flink = any(re.search(pattern, text) for pattern in self_flink_patterns)
    if not has_self_flink:
        return False
    has_blink_use = bool(re.search(r"\b%s\s*\[\s*1\s*\]" % escaped, text))
    has_neighbor_check = bool(
        re.search(r"\*\s*[A-Za-z_][A-Za-z0-9_]*\s*!=\s*%s\b" % escaped, text)
        or re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*==\s*%s\b" % escaped, text)
    )
    return has_blink_use or has_neighbor_check


def _looks_like_list_entry_head_local(text: str, name: str) -> bool:
    if not _looks_like_generic_temporary(name):
        return False
    escaped = re.escape(name)
    has_self_deref_check = bool(
        re.search(r"\*\s*%s\s*==\s*%s\b" % (escaped, escaped), text)
        or re.search(r"%s\s*==\s*\*\s*%s\b" % (escaped, escaped), text)
    )
    if not has_self_deref_check:
        return False
    has_neighbor_integrity = bool(
        re.search(r"\[\s*1\s*\]\s*!=\s*%s\b" % escaped, text)
        or re.search(r"\*\s*[A-Za-z_][A-Za-z0-9_]*\s*!=\s*%s\b" % escaped, text)
        or re.search(r"\[\s*1\s*\]\s*=\s*%s\b" % escaped, text)
        or re.search(r"=\s*%s\s*;" % escaped, text)
    )
    return has_neighbor_integrity


def _looks_like_generic_temporary(name: str) -> bool:
    return bool(re.fullmatch(r"v\d+", name or ""))


def _looks_like_generic_argument(name: str) -> bool:
    return bool(re.fullmatch(r"a\d+", name or ""))


def _looks_like_pascal_local(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Z][A-Za-z0-9_]*", name or "")) and not (name or "").isupper()


def _looks_like_large_dispatcher(text: str) -> bool:
    lines = text.splitlines()
    if len(lines) >= 180:
        return True
    return_count = len(re.findall(r"\breturn\b", text))
    label_count = len(re.findall(r"\bLABEL_\d+\b", text))
    branch_count = len(re.findall(r"\bif\s*\(", text)) + len(re.findall(r"(?m)^\s*case\b", text))
    if label_count >= 8 and return_count >= 8:
        return True
    return return_count >= 16 and branch_count >= 16


def _iter_profiled_calls(text: str) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []
    for match in re.finditer(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(", text or ""):
        name = match.group("name")
        metadata = kernel_function_metadata(name)
        params = metadata.get("params")
        if not isinstance(params, list) or not params:
            continue
        open_index = (text or "").find("(", match.start())
        close_index = find_matching_paren(text or "", open_index)
        if close_index < 0:
            continue
        parameter_text = (text or "")[open_index + 1 : close_index]
        arguments = [argument.strip() for argument, _span in split_parameters_with_spans(parameter_text)]
        calls.append({"name": name, "params": params, "arguments": arguments})
    return calls


def _byref_local_names(text: str) -> set[str]:
    return {
        match.group("name")
        for match in re.finditer(
            r"(?m)^\s*(?:struct\s+)?[A-Za-z_][A-Za-z0-9_:\s\*\&<>]*?\s+"
            r"[\*\&]?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]+\])?\s*;[^\n]*\bBYREF\b",
            text or "",
        )
    }


def _addressed_local_name(argument: str) -> str:
    stripped = (argument or "").strip()
    match = re.fullmatch(r"&\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)", stripped)
    if match:
        return match.group("name")
    match = re.fullmatch(
        r"\(\s*(?:struct\s+)?[A-Za-z_][A-Za-z0-9_:\s]*\*+\s*\)\s*&\s*"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
        stripped,
    )
    if match:
        return match.group("name")
    return ""


def _plain_local_argument_name(argument: str) -> str:
    stripped = (argument or "").strip()
    match = re.fullmatch(r"(?:\([^)]+\)\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)", stripped)
    return match.group("name") if match else ""


def _is_unsafe_wrapper_parameter_role(name: str) -> bool:
    return name in {"irp"}


def _semantic_name_from_api_result(function_name: str, return_type: str, local_type: str) -> str:
    if "KIRQL" in (return_type or "") and "Acquire" in function_name and "SpinLock" in function_name:
        return "oldIrql"
    current_match = re.search(r"Get(Current[A-Za-z0-9_]+)$", function_name or "")
    if current_match:
        return _lower_camel_from_pascal(current_match.group(1))
    getter_match = re.search(r"Get([A-Za-z0-9_]+)$", function_name or "")
    if getter_match:
        return _lower_camel_from_pascal(getter_match.group(1))
    allocate_match = re.search(r"Allocate([A-Za-z0-9_]+)$", function_name or "")
    if allocate_match and _is_pointer_like_profile_type(return_type):
        allocated_name = _lower_camel_from_pascal(allocate_match.group(1))
        if allocated_name in {"mdl", "workItem"}:
            return allocated_name
    if "KIRQL" in (local_type or ""):
        return "oldIrql"
    return ""


def _semantic_name_from_api_parameter(param_name: str, param_type: str, function_name: str = "") -> str:
    if not param_name:
        return ""
    name = _normalized_api_parameter_name(param_name, param_type)
    if not name:
        return ""
    if _is_weak_api_parameter_name(name):
        return ""
    if name == "lookaside" and "LOOKASIDE_LIST" in (param_type or ""):
        return "lookasideList"
    if name in _HIGH_SIGNAL_API_PARAMETER_NAMES:
        return name
    if _is_handle_profile_type(param_type) and name.endswith("Handle"):
        return name
    if _is_pointer_like_profile_type(param_type) and _has_high_signal_pointer_parameter_suffix(name):
        return name
    if _is_integer_profile_type(param_type) and _has_high_signal_value_parameter_suffix(name):
        return name
    if _is_enum_like_profile_type(param_type) and _has_high_signal_enum_parameter_suffix(name):
        return name
    if function_name.startswith(("Zw", "Nt")) and name.endswith(("InformationClass", "InformationLength")):
        return name
    if name.lower().endswith("irql"):
        return "oldIrql" if "restores" in (param_type or "").lower() else name
    return ""


_HIGH_SIGNAL_API_PARAMETER_NAMES = {
    "accessMode",
    "alertable",
    "baseAddress",
    "byteCount",
    "currentTime",
    "desiredAccess",
    "deviceObject",
    "driverObject",
    "entry",
    "event",
    "eventHandle",
    "fileHandle",
    "fileObject",
    "filter",
    "inputBuffer",
    "inputBufferLength",
    "interval",
    "ioControlCode",
    "ioStatusBlock",
    "irp",
    "keyHandle",
    "memoryDescriptorList",
    "mdl",
    "newProtect",
    "notifyRoutine",
    "numberOfBytesTransferred",
    "object",
    "objectAttributes",
    "objectType",
    "outputBuffer",
    "outputBufferLength",
    "process",
    "processHandle",
    "processId",
    "registration",
    "returnLength",
    "spinLock",
    "thread",
    "threadHandle",
    "threadId",
    "timeout",
    "virtualAddress",
    "waitMode",
    "waitReason",
    "workItem",
}


def _normalized_api_parameter_name(param_name: str, param_type: str) -> str:
    name = _lower_camel_from_pascal(param_name)
    if not name:
        return ""
    if name == "retFilter" and "FLT_FILTER" in (param_type or ""):
        return "filter"
    if name == "memoryDescriptorList" and "MDL" in (param_type or ""):
        return "mdl"
    return name


def _is_weak_api_parameter_name(name: str) -> bool:
    return bool(
        re.fullmatch(
            r"(?i)(?:arg\d+|argument\d+|param\d+|parameter\d+|reserved\d*|unused\d*|unknown\d*|buffer|length|size|flags|value)",
            name or "",
        )
    )


def _has_high_signal_pointer_parameter_suffix(name: str) -> bool:
    return name.endswith(
        (
            "Attributes",
            "Buffer",
            "Context",
            "Entry",
            "Event",
            "Filter",
            "Handle",
            "Information",
            "List",
            "Object",
            "Process",
            "Registration",
            "StatusBlock",
            "String",
            "Thread",
            "WorkItem",
        )
    )


def _has_high_signal_value_parameter_suffix(name: str) -> bool:
    return name.endswith(
        (
            "Access",
            "ByteCount",
            "Characteristics",
            "Code",
            "Count",
            "Disposition",
            "Flags",
            "Length",
            "Mask",
            "Mode",
            "Protect",
            "Reason",
            "Size",
            "Tag",
            "Type",
        )
    )


def _has_high_signal_enum_parameter_suffix(name: str) -> bool:
    return name.endswith(("Class", "Disposition", "Mode", "Reason", "Type"))


def _is_handle_profile_type(type_text: str) -> bool:
    text = (type_text or "").strip().upper()
    return text == "HANDLE" or text.endswith("HANDLE")


def _is_integer_profile_type(type_text: str) -> bool:
    text = (type_text or "").upper()
    if _is_pointer_type(text):
        return False
    return bool(re.search(r"\b(?:ACCESS_MASK|BOOLEAN|CHAR|DWORD|INT|KIRQL|LONG|SIZE_T|ULONG|USHORT|WORD|__INT64)\b", text))


def _is_enum_like_profile_type(type_text: str) -> bool:
    text = (type_text or "").strip()
    return bool(
        re.search(r"(?:_CLASS|CLASS|_TYPE|TYPE|_MODE|MODE|_REASON|REASON|DISPOSITION)$", text)
        and not _is_pointer_like_profile_type(text)
    )


def _is_pointer_like_profile_type(type_text: str) -> bool:
    text = (type_text or "").strip()
    if _is_pointer_type(text):
        return True
    if not re.fullmatch(r"P[A-Z0-9_]+", text):
        return False
    non_pointer_prefixes = (
        "POOL_",
        "POWER_",
        "PROCESS",
        "PAGE",
        "PCI_",
        "PEP_",
        "PNP_",
        "POLICY_",
        "PORT_",
    )
    return not any(text.startswith(prefix) for prefix in non_pointer_prefixes)


def _unique_target_suggestions(suggestions: list[RenameSuggestion]) -> list[RenameSuggestion]:
    by_target: dict[str, list[RenameSuggestion]] = {}
    for suggestion in suggestions:
        by_target.setdefault(suggestion.new, []).append(suggestion)
    result = []
    for target_suggestions in by_target.values():
        old_names = {item.old for item in target_suggestions}
        if len(old_names) == 1:
            result.append(target_suggestions[0])
    return result


def _unique_semantic_suggestions(
    suggestions: list[RenameSuggestion],
    diagnostics: list[dict[str, Any]] | None = None,
    stage: str = "",
) -> list[RenameSuggestion]:
    by_target: dict[str, list[RenameSuggestion]] = {}
    by_old: dict[str, list[RenameSuggestion]] = {}
    for suggestion in suggestions:
        by_target.setdefault(suggestion.new, []).append(suggestion)
        by_old.setdefault(suggestion.old, []).append(suggestion)
    result = []
    for suggestion in suggestions:
        target_old_names = {item.old for item in by_target.get(suggestion.new, [])}
        old_target_names = {item.new for item in by_old.get(suggestion.old, [])}
        if len(target_old_names) != 1:
            _append_api_semantic_diagnostic(
                diagnostics,
                stage=stage or suggestion.source,
                reason="conflict_target",
                old=suggestion.old,
                new=suggestion.new,
                evidence=suggestion.evidence,
                candidates=sorted(target_old_names),
            )
            continue
        if len(old_target_names) != 1:
            _append_api_semantic_diagnostic(
                diagnostics,
                stage=stage or suggestion.source,
                reason="conflict_old",
                old=suggestion.old,
                new=suggestion.new,
                evidence=suggestion.evidence,
                candidates=sorted(old_target_names),
            )
            continue
        result.append(suggestion)
    return result


def _append_api_semantic_diagnostic(
    diagnostics: list[dict[str, Any]] | None,
    *,
    stage: str,
    reason: str,
    old: str,
    new: str = "",
    callee: str = "",
    argument_index: int = -1,
    argument: str = "",
    parameter: str = "",
    parameter_type: str = "",
    candidate_kind: str = "",
    evidence: str = "",
    candidates: list[str] | None = None,
) -> None:
    if diagnostics is None:
        return
    item: dict[str, Any] = {
        "stage": stage,
        "status": "rejected",
        "reason": reason,
        "old": old,
    }
    optional_values: dict[str, Any] = {
        "new": new,
        "callee": callee,
        "argument_index": argument_index if argument_index >= 0 else "",
        "argument": argument,
        "parameter": parameter,
        "parameter_type": parameter_type,
        "candidate_kind": candidate_kind,
        "evidence": evidence,
        "candidates": candidates or [],
    }
    for key, value in optional_values.items():
        if value not in ("", [], None):
            item[key] = value
    diagnostics.append(item)


def _would_shadow_case_variant(local_names: set[str], old_name: str, new_name: str) -> bool:
    new_lower = (new_name or "").lower()
    old_lower = (old_name or "").lower()
    return any(name.lower() == new_lower and name.lower() != old_lower for name in local_names)


def _unique_preserve_order(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _lower_camel_from_pascal(name: str) -> str:
    if not name or not re.match(r"^[A-Z][A-Za-z0-9_]*$", name):
        return ""
    if name.upper() == name:
        return ""

    prefix_len = 1
    while prefix_len < len(name) and name[prefix_len].isupper():
        next_index = prefix_len + 1
        if next_index < len(name) and name[next_index].islower():
            break
        prefix_len += 1

    return name[:prefix_len].lower() + name[prefix_len:]


def _m128_pointer_alias_kind(capture: FunctionCapture, local_name: str, parameter_name: str) -> str:
    for name, type_text in extract_parameters_from_signature(capture.prototype):
        if name == parameter_name and "__m128i" in type_text:
            return "reused" if _local_alias_reassigned(capture.pseudocode, local_name, parameter_name) else "stable"

    names = "%s|%s" % (re.escape(local_name), re.escape(parameter_name))
    if not (
        re.search(r"\b(?:%s)->m128i_" % names, capture.pseudocode)
        or re.search(r"\b(?:%s)\s*\[[^\]]+\]\s*\.m128i_" % names, capture.pseudocode)
    ):
        return ""
    if _local_alias_reassigned(capture.pseudocode, local_name, parameter_name):
        return "reused"
    return "stable"


def _local_alias_reassigned(text: str, local_name: str, parameter_name: str) -> bool:
    pattern = re.compile(r"\b%s\s*=\s*(?P<expr>[^;\n]+);" % re.escape(local_name))
    for match in pattern.finditer(text):
        if _assignment_rhs_is_parameter_alias(match.group("expr"), parameter_name):
            continue
        return True
    return False


def _assignment_rhs_is_parameter_alias(expr: str, parameter_name: str) -> bool:
    value = re.sub(r"\s+", "", expr or "")
    if value == parameter_name:
        return True
    while value.startswith("("):
        close_index = value.find(")")
        if close_index < 0:
            return False
        cast_text = value[1:close_index]
        if not cast_text or parameter_name in cast_text:
            return False
        value = value[close_index + 1 :]
        if value == parameter_name:
            return True
    return False


def _first_cpu_set_callee(text: str) -> str:
    match = re.search(r"\b(?P<callee>KeModifySystemAllowedCpuSets|KeSetTagCpuSets)\s*\(", text)
    if not match:
        return ""
    return match.group("callee")


def _looks_like_cpu_set_operation_use(text: str, operation_name: str) -> bool:
    escaped = re.escape(operation_name)
    return bool(
        re.search(r"\bif\s*\(\s*%s\s*>?=\s*2\s*\)" % escaped, text)
        or re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*%s\s*;" % escaped, text)
    )

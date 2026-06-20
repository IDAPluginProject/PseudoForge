from __future__ import annotations

import re
from typing import Any

from ida_pseudoforge.core.field_layout_hints import domain_identity_role_comments, field_layout_comments
from ida_pseudoforge.core.ioctl import decode_ioctl_code, parse_c_integer_literal
from ida_pseudoforge.core.normalize import (
    extract_call_arguments,
    extract_parameters_from_signature,
    safe_identifier_replace,
)

from ida_pseudoforge.core.plan_schema import FunctionCapture, RenameSuggestion
from ida_pseudoforge.core.registry_domain import registry_domain_comments


_LIST_HEAD_RE = re.compile(r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\([^)]*\*\)\((?P<head>[A-Za-z_][A-Za-z0-9_]*ListHead)\s*-\s*(?P<offset>\d+)")
_LINK_FROM_RECORD_RE = re.compile(r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<record>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*(?P<offset>\d+)\s*;")
_NEXT_LINK_RE = re.compile(r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\*\(_QWORD \*\)(?P<link>[A-Za-z_][A-Za-z0-9_]*)\s*;")
_PREV_LINK_RE = re.compile(r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(_QWORD \*\)\*\(\(_QWORD \*\)(?P<record>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*(?P<index>\d+)\)")
_ALLOC_RE = re.compile(r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*ExAllocatePool2\([^;]*\)")
_NEW_LINK_RE = re.compile(r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(_QWORD \*\)\((?P<record>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*(?P<offset>\d+)\)")
_TAIL_LINK_RE = re.compile(r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(_QWORD \*\)qword_[A-Fa-f0-9]+\s*;")
_POOL_TAG_RE = re.compile(r"\b(?P<tag>0x[0-9A-Fa-f]{8})u?(?:LL|i64|L)?\b")
_STATUS_LITERAL_RE = re.compile(r"(?:-107374\d+|322122\d+|0x[4C][0-9A-Fa-f]{7})")
_ZW_STATUS_NAMES = {
    "ZwClose": "closeStatus",
    "ZwWaitForSingleObject": "waitStatus",
    "ZwQueryObject": "queryObjectStatus",
    "ZwCreateEvent": "createEventStatus",
    "ZwOpenKey": "openKeyStatus",
    "ZwOpenProcessTokenEx": "openProcessTokenStatus",
    "ZwOpenThreadTokenEx": "openThreadTokenStatus",
    "ZwCreateFile": "createFileStatus",
}
_ZW_OBJECT_ATTRIBUTE_ARGUMENTS = {
    "ZwCreateEvent": 2,
    "ZwCreateFile": 2,
    "ZwOpenFile": 2,
    "ZwOpenKey": 2,
    "ZwCreateKey": 2,
}
_ZW_HANDLE_OUTPUT_ARGUMENTS = {
    "ZwCreateEvent": 0,
    "ZwCreateFile": 0,
    "ZwOpenFile": 0,
    "ZwOpenKey": 0,
    "ZwCreateKey": 0,
}
_ZW_TOKEN_HANDLE_OUTPUT_ARGUMENTS = {
    "ZwOpenProcessTokenEx": 3,
    "ZwOpenThreadTokenEx": 4,
}
_ZW_QUERY_BUFFER_ARGUMENTS = {
    "ZwQueryInformationFile": 2,
    "ZwQueryInformationToken": 2,
    "ZwQueryKey": 2,
    "ZwQueryObject": 2,
    "ZwQueryValueKey": 3,
}
_ZW_RETURN_LENGTH_ARGUMENTS = {
    "ZwQueryInformationToken": 4,
    "ZwQueryKey": 4,
    "ZwQueryObject": 4,
    "ZwQueryValueKey": 5,
}
_ZW_CATEGORY_ROUTINES = {
    "object": {"ZwCreateEvent", "ZwQueryObject", "ZwWaitForSingleObject"},
    "registry": {"ZwOpenKey", "ZwCreateKey"},
    "token": {"ZwOpenProcessTokenEx", "ZwOpenThreadTokenEx"},
    "file": {"ZwCreateFile", "ZwOpenFile"},
}


def kernel_rename_suggestions(capture: FunctionCapture) -> list[RenameSuggestion]:
    text = capture.pseudocode or ""
    suggestions: list[RenameSuggestion] = []
    record_vars: set[str] = set()
    link_vars: set[str] = set()
    allocated_vars: set[str] = set()

    status_var = _status_accumulator_name(text)
    if status_var:
        suggestions.append(
            _rename(
                status_var,
                "status",
                0.94,
                "kernel-status",
                "Local accumulates NTSTATUS-style values and is returned",
            )
        )

    if looks_like_driver_entry(capture):
        for old_name, new_name, evidence in _driver_entry_local_rename_roles(text):
            suggestions.append(_rename(old_name, new_name, 0.93, "kernel-driver-entry", evidence))

    if looks_like_driver_dispatch(capture):
        for old_name, new_name, evidence in _driver_dispatch_local_rename_roles(text):
            suggestions.append(_rename(old_name, new_name, 0.94, "kernel-driver-dispatch", evidence))

    if looks_like_irp_dispatch(capture):
        for old_name, new_name, evidence in _irp_device_control_rename_roles(text):
            suggestions.append(_rename(old_name, new_name, 0.94, "kernel-irp-stack", evidence))

    for old_name, new_name, evidence in _callback_registration_local_rename_roles(text):
        suggestions.append(_rename(old_name, new_name, 0.94, "kernel-callback-registration", evidence))

    for old_name, new_name, evidence in _registry_callback_local_rename_roles(text):
        suggestions.append(_rename(old_name, new_name, 0.94, "kernel-registry-callback", evidence))

    for old_name, new_name, evidence in _memory_manager_probe_local_rename_roles(text):
        suggestions.append(_rename(old_name, new_name, 0.94, "kernel-mm-probe", evidence))

    for old_name, new_name, evidence in _zw_api_probe_local_rename_roles(text):
        suggestions.append(_rename(old_name, new_name, 0.94, "kernel-zw-probe", evidence))

    for match in _LIST_HEAD_RE.finditer(text):
        record_vars.add(match.group("dst"))
        suggestions.append(
            _rename(
                match.group("dst"),
                "providerRecord",
                0.91,
                "kernel-list",
                "Variable is derived from a LIST_ENTRY head with a containing-record offset",
            )
        )

    for match in _LINK_FROM_RECORD_RE.finditer(text):
        record = match.group("record")
        if record in record_vars or _looks_like_record_name(record):
            link_vars.add(match.group("dst"))
            new_name = "providerLink" if record in record_vars else _link_name_from_record(record)
            suggestions.append(
                _rename(
                    match.group("dst"),
                    new_name,
                    0.90,
                    "kernel-list",
                    "Variable points at a LIST_ENTRY field inside a record",
                )
            )

    for match in _NEXT_LINK_RE.finditer(text):
        link = match.group("link")
        if link in link_vars or _looks_like_link_name(link):
            suggestions.append(
                _rename(
                    match.group("dst"),
                    "nextLink",
                    0.88,
                    "kernel-list",
                    "Variable loads LIST_ENTRY.Flink",
                )
            )

    for match in _PREV_LINK_RE.finditer(text):
        suggestions.append(
            _rename(
                match.group("dst"),
                "previousLink",
                0.88,
                "kernel-list",
                "Variable loads LIST_ENTRY.Blink",
            )
        )

    for match in _ALLOC_RE.finditer(text):
        allocated_vars.add(match.group("dst"))
        suggestions.append(
            _rename(
                match.group("dst"),
                "newProviderRecord",
                0.89,
                "kernel-pool",
                "Variable receives an ExAllocatePool2 record allocation",
            )
        )

    for match in _NEW_LINK_RE.finditer(text):
        record = match.group("record")
        if record in allocated_vars or record.lower().startswith("new"):
            suggestions.append(
                _rename(
                    match.group("dst"),
                    "newProviderLink",
                    0.90,
                    "kernel-list",
                    "Variable points at the LIST_ENTRY field in a newly allocated record",
                )
            )

    for match in _TAIL_LINK_RE.finditer(text):
        suggestions.append(
            _rename(
                match.group("dst"),
                "tailLink",
                0.86,
                "kernel-list",
                "Variable aliases a global LIST_ENTRY tail pointer",
            )
        )

    return suggestions


def kernel_comments(capture: FunctionCapture, rename_map: dict[str, str]) -> list[dict[str, Any]]:
    raw_text = capture.pseudocode or ""
    text = _apply_rename_map(raw_text, rename_map)
    comments: list[dict[str, Any]] = []

    if looks_like_driver_entry(capture):
        has_driver_entry_sequence = (
            "IoCreateDevice" in text and "MajorFunction" in text and "DriverUnload" in text
        )
        comments.append(
            _comment(
                "driver_entry",
                (
                    "DriverEntry-style dispatch table, unload routine, and device creation sequence detected"
                    if has_driver_entry_sequence
                    else "DriverEntry entrypoint or wrapper detected; body lacks full device creation sequence"
                ),
                0.92 if has_driver_entry_sequence else 0.74,
            )
        )
        if "MajorFunction" in text:
            comments.append(
                _comment(
                    "driver_dispatch_table",
                    "IRP major-function table initialization is present",
                    0.90,
                )
            )
        if "DeviceExtension" in text and "IoCreateDevice" in text:
            comments.append(
                _comment(
                    "device_extension_layout",
                    "DeviceExtension field offsets can be rendered as a preview-only inferred driver extension",
                    0.84,
                )
            )

    if "ExAcquireResourceExclusiveLite" in text and "ExReleaseResourceLite" in text:
        comments.append(
            _comment(
                "resource",
                "ERESOURCE exclusive acquisition with common release tail",
                0.92,
            )
        )

    if "KeGetCurrentThread()" in text and "KernelApcDisable" in text and "KeLeaveCriticalRegion" in text:
        comments.append(
            _comment(
                "critical_region",
                "Inline critical region entry can be normalized to KeEnterCriticalRegion and paired with KeLeaveCriticalRegion",
                0.88,
            )
        )

    if "__fastfail(3" in text:
        comments.append(
            _comment(
                "failfast",
                "FAST_FAIL_CORRUPT_LIST_ENTRY style path detected; review LIST_ENTRY integrity checks",
                0.94,
            )
        )

    if _has_list_unlink_pattern(raw_text) or _has_list_unlink_pattern(text):
        comments.append(
            _comment(
                "list_entry_unlink",
                "LIST_ENTRY unlink pattern detected: validates neighboring links before unlinking a record",
                0.91,
            )
        )

    if _has_list_insert_tail_pattern(raw_text) or _has_list_insert_tail_pattern(text):
        comments.append(
            _comment(
                "list_entry_insert_tail",
                "LIST_ENTRY tail insertion pattern detected for a newly allocated record",
                0.88,
            )
        )

    if "ExAllocatePool2" in text:
        tag_comments = _pool_tag_comments(text)
        comments.extend(tag_comments)
        comments.extend(_record_layout_comments(text))
        comments.append(
            _comment(
                "pool",
                "Pool allocation path detected; pair allocation failures with STATUS_INSUFFICIENT_RESOURCES",
                0.86,
            )
        )

    if _has_callback_registration_toggle_evidence(text):
        comments.append(
            _comment(
                "callback_registration",
                "Process, image, thread, and object callback registration toggle detected",
                0.90,
            )
        )

    if _has_registry_callback_registration_evidence(text):
        comments.append(
            _comment(
                "registry_callback_registration",
                "Configuration Manager registry callback version and registration probe detected",
                0.90,
            )
        )

    if _has_memory_manager_probe_evidence(text):
        comments.append(
            _comment(
                "memory_manager_probe",
                "Memory Manager routine lookup, virtual copy, MDL, and allocation probe detected",
                0.88,
            )
        )

    if _has_zw_api_probe_evidence(text):
        comments.append(
            _comment(
                "zw_api_probe",
                "Zw system API corpus probe with object, registry, token, and file calls detected",
                0.90,
            )
        )

    if "ObfDereferenceObject" in text or "ObDereferenceObject" in text or "PsReferenceSiloContext" in text:
        comments.append(
            _comment(
                "object_reference",
                "Kernel object/context reference ownership changes are present",
                0.84,
            )
        )

    comments.extend(registry_domain_comments(capture, rename_map))
    layout_comments = field_layout_comments(text, profile_context=capture.profile_context)
    layout_identity_bases = {
        str(comment.get("base", ""))
        for comment in layout_comments
        if comment.get("kind") == "domain_structure_identity"
    }
    comments.extend(
        domain_identity_role_comments(
            text,
            profile_context=capture.profile_context,
            exclude_bases=layout_identity_bases,
        )
    )
    comments.extend(layout_comments)

    if "previousMode" in text and "STATUS_PRIVILEGE_NOT_HELD" in text:
        comments.append(
            _comment(
                "previous_mode_gate",
                "User-mode caller is rejected before touching kernel-only registration state",
                0.86,
            )
        )

    return comments


def kernel_warnings(capture: FunctionCapture) -> list[str]:
    text = capture.pseudocode or ""
    warnings = []
    suspicious_operands = suspicious_ps_reference_silo_context_operands(text)
    if suspicious_operands:
        if any(_operand_looks_like_driver_object(operand) for operand in suspicious_operands):
            reason = "operand is DriverObject and removal path uses ObfDereferenceObject"
        else:
            reason = "operand looks like an object pointer and object release path uses ObfDereferenceObject"
        warnings.append(
            "Potential bad call target PsReferenceSiloContext: %s." % reason
        )
    return warnings


def _rename(old: str, new: str, confidence: float, source: str, evidence: str) -> RenameSuggestion:
    return RenameSuggestion(
        kind="lvar",
        old=old,
        new=new,
        confidence=confidence,
        source=source,
        evidence=evidence,
    )


def looks_like_driver_entry(capture: FunctionCapture) -> bool:
    return _has_driver_entry_evidence(capture.pseudocode or "", capture.prototype or "", capture.name or "")


def driver_entry_parameter_names(capture: FunctionCapture) -> list[str]:
    if not looks_like_driver_entry(capture):
        return []
    params = extract_parameters_from_signature(capture.prototype)
    if len(params) < 2:
        return []
    return ["driverObject", "registryPath"]


def driver_dispatch_parameter_names(capture: FunctionCapture) -> list[str]:
    if not looks_like_irp_dispatch(capture):
        return []
    return ["deviceObject", "irp"]


def callback_registration_parameter_names(capture: FunctionCapture) -> list[str]:
    text = capture.pseudocode or ""
    if not _has_callback_registration_toggle_evidence(text):
        return []
    params = extract_parameters_from_signature(capture.prototype)
    if len(params) != 2:
        return []
    first_name = params[0][0]
    second_name = params[1][0]
    if not _parameter_has_offset_use(text, first_name):
        return []
    if not _parameter_controls_callback_enable(text, second_name):
        return []
    return ["deviceExtension", "enable"]


def registry_callback_parameter_names(capture: FunctionCapture) -> list[str]:
    text = capture.pseudocode or ""
    if not _has_registry_callback_registration_evidence(text):
        return []
    params = extract_parameters_from_signature(capture.prototype)
    if len(params) != 1:
        return []
    name = params[0][0]
    if not _parameter_is_registry_callback_context(text, name):
        return []
    return ["callbackContext"]


def looks_like_callback_registration_toggle(capture: FunctionCapture) -> bool:
    return _has_callback_registration_toggle_evidence(capture.pseudocode or "")


def looks_like_registry_callback_registration(capture: FunctionCapture) -> bool:
    return _has_registry_callback_registration_evidence(capture.pseudocode or "")


def looks_like_zw_api_probe(capture: FunctionCapture) -> bool:
    return _has_zw_api_probe_evidence(capture.pseudocode or "")


def looks_like_driver_dispatch(capture: FunctionCapture) -> bool:
    return _has_driver_dispatch_evidence(capture.pseudocode or "", capture.prototype or "")


def looks_like_irp_dispatch(capture: FunctionCapture) -> bool:
    return _has_irp_dispatch_evidence(capture.pseudocode or "", capture.prototype or "")


def _comment(kind: str, text: str, confidence: float) -> dict[str, Any]:
    return {
        "kind": kind,
        "text": text,
        "confidence": confidence,
    }


def _has_driver_entry_evidence(text: str, prototype: str, function_name: str) -> bool:
    if function_name == "DriverEntry":
        return True
    if "IoCreateDevice" not in text or "MajorFunction" not in text or "DriverUnload" not in text:
        return False
    params = extract_parameters_from_signature(prototype)
    if len(params) != 2:
        return False
    first_name, first_type = params[0]
    if "DRIVER_OBJECT" in first_type.upper():
        return True
    escaped = re.escape(first_name)
    return re.search(r"\b%s\s*->\s*MajorFunction\b" % escaped, text) is not None


def _has_driver_dispatch_evidence(text: str, prototype: str) -> bool:
    if not _has_irp_dispatch_evidence(text, prototype):
        return False
    params = extract_parameters_from_signature(prototype)
    device_param = params[0][0]
    escaped_device = re.escape(device_param)
    has_device_extension_load = (
        re.search(r"\*\(\s*_QWORD\s+\*\s*\)\s*\(\s*%s\s*\+\s*64\s*\)" % escaped_device, text) is not None
        or re.search(r"\b%s\s*->\s*DeviceExtension\b" % escaped_device, text) is not None
    )
    return has_device_extension_load


def _has_irp_dispatch_evidence(text: str, prototype: str) -> bool:
    params = extract_parameters_from_signature(prototype)
    if len(params) != 2:
        return False
    if not _first_parameter_can_be_device_object(params[0][1]):
        return False
    irp_param = _candidate_irp_parameter_name(text, params)
    if not irp_param:
        return False
    irp_names = {irp_param}
    irp_names.update(_irp_alias_names(text, irp_param))
    name_pattern = "|".join(re.escape(name) for name in sorted(irp_names))
    has_irp_completion = any(_parameter_is_completed_irp(text, name) for name in irp_names)
    has_io_status = re.search(r"\b(?:%s)\s*->\s*IoStatus\." % name_pattern, text) is not None
    return has_irp_completion or has_io_status


def _first_parameter_can_be_device_object(type_name: str) -> bool:
    normalized = " ".join(type_name.replace("*", " * ").split()).upper()
    if "DEVICE_OBJECT" in normalized:
        return True
    if normalized in {"__INT64", "UINT64", "ULONG64", "DWORD64", "QWORD", "PVOID", "VOID *"}:
        return True
    if "*" in normalized:
        obvious_scalars = (
            "BOOLEAN",
            "CHAR",
            "UCHAR",
            "SHORT",
            "USHORT",
            "INT",
            "UINT",
            "LONG",
            "ULONG",
            "NTSTATUS",
        )
        return not any(re.fullmatch(r"(?:CONST\s+)?%s\s+\*" % scalar, normalized) for scalar in obvious_scalars)
    return False


def _candidate_irp_parameter_name(text: str, params: list[tuple[str, str]]) -> str:
    if len(params) != 2:
        return ""
    irp_param, irp_type = params[1]
    if "IRP" in irp_type.upper():
        return irp_param
    escaped = re.escape(irp_param)
    if _parameter_is_completed_irp(text, irp_param):
        return irp_param
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*\(\s*IRP\s+\*\s*\)%s\s*;" % escaped, text):
        return irp_param
    if (
        re.search(r"\*\([^;\n]*\*+\s*\)\s*\(\s*%s\s*\+\s*184\s*\)" % escaped, text)
        and re.search(r"\*\([^;\n]*\*+\s*\)\s*\(\s*%s\s*\+\s*24\s*\)" % escaped, text)
    ):
        return irp_param
    return ""


def _parameter_is_completed_irp(text: str, parameter: str) -> bool:
    cast_pattern = r"(?:\(\s*(?:PIRP|(?:struct\s+)?_?IRP\s*\*)\s*\)\s*)?"
    return (
        re.search(
            r"\bIof?CompleteRequest\s*\(\s*%s%s\s*," % (cast_pattern, re.escape(parameter)),
            text,
        )
        is not None
    )


def _irp_alias_names(text: str, irp_param: str) -> set[str]:
    escaped = re.escape(irp_param)
    return {
        match.group("alias")
        for match in re.finditer(
            r"\b(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(\s*IRP\s+\*\s*\)%s\s*;"
            % escaped,
            text,
        )
    }


def _driver_entry_local_rename_roles(text: str) -> list[tuple[str, str, str]]:
    roles: list[tuple[str, str, str]] = []

    create_device_match = re.search(
        r"\b(?P<status>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*IoCreateDevice\s*\(.*?,\s*"
        r"&(?P<device>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
        text,
        re.DOTALL,
    )
    if create_device_match is not None:
        roles.append(
            (
                create_device_match.group("status"),
                "status",
                "Local receives NTSTATUS from IoCreateDevice in DriverEntry setup",
            )
        )
        roles.append(
            (
                create_device_match.group("device"),
                "deviceObject",
                "Local is the IoCreateDevice output PDEVICE_OBJECT",
            )
        )

    extension_match = re.search(
        r"\b(?P<extension>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(?:\([^;\n]*\)\s*)?(?P<device>[A-Za-z_][A-Za-z0-9_]*)->DeviceExtension\s*;",
        text,
    )
    if extension_match is not None:
        roles.append(
            (
                extension_match.group("extension"),
                "extension",
                "Local receives DEVICE_OBJECT.DeviceExtension in DriverEntry setup",
            )
        )
        roles.append(
            (
                extension_match.group("device"),
                "deviceObject",
                "Local is the IoCreateDevice output PDEVICE_OBJECT",
            )
        )

    device_name_match = re.search(
        r"RtlInitUnicodeString\s*\(\s*&(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*"
        r"L\"\\\\Device\\\\",
        text,
    )
    if device_name_match is not None:
        roles.append(
            (
                device_name_match.group("name"),
                "deviceName",
                "UNICODE_STRING local is initialized with the NT device name",
            )
        )

    major_match = re.search(
        r"for\s*\(\s*(?P<index>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*0\s*;"
        r"\s*(?P=index)\s*<=\s*(?:0x1B|27)(?:u|U)?\s*;"
        r"\s*\+\+(?P=index)\s*\).*?MajorFunction\s*\[\s*(?P=index)\s*\]",
        text,
        re.DOTALL,
    )
    if major_match is not None:
        roles.append(
            (
                major_match.group("index"),
                "majorIndex",
                "Loop initializes DriverObject.MajorFunction entries through IRP_MJ_MAXIMUM_FUNCTION",
            )
        )

    return _dedupe_role_renames(roles)


def _dedupe_role_renames(roles: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    result: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for old_name, new_name, evidence in roles:
        if old_name in seen:
            continue
        seen.add(old_name)
        result.append((old_name, new_name, evidence))
    return result


def _callback_registration_local_rename_roles(text: str) -> list[tuple[str, str, str]]:
    if not _has_callback_registration_toggle_evidence(text):
        return []

    roles: list[tuple[str, str, str]] = []
    for variable, routine in _assigned_callback_status_variables(text):
        roles.append(
            (
                variable,
                _callback_status_name(routine),
                "Local receives status from %s registration call" % routine,
            )
        )

    altitude = _callback_altitude_string_variable(text)
    if altitude:
        roles.append(
            (
                altitude,
                "altitudeString",
                "UNICODE_STRING is copied into OB_CALLBACK_REGISTRATION.Altitude",
            )
        )

    operation_registration = _operation_registration_variable(text)
    if operation_registration:
        roles.append(
            (
                operation_registration,
                "operationRegistration",
                "Local array is assigned to OB_CALLBACK_REGISTRATION.OperationRegistration",
            )
        )

    return _dedupe_role_renames(roles)


def _has_callback_registration_toggle_evidence(text: str) -> bool:
    has_process = (
        "PsSetCreateProcessNotifyRoutine(" in text
        or "PsSetCreateProcessNotifyRoutineEx(" in text
    )
    has_image = "PsSetLoadImageNotifyRoutine(" in text
    has_thread = "PsSetCreateThreadNotifyRoutine(" in text
    has_object = "ObRegisterCallbacks(" in text and "ObUnRegisterCallbacks" in text
    return has_process and has_image and has_thread and has_object


def _parameter_has_offset_use(text: str, name: str) -> bool:
    offset_uses = {
        match.group("offset")
        for match in re.finditer(
            r"\b%s\s*\+\s*(?P<offset>\d+)\b" % re.escape(name),
            text,
        )
    }
    if len(offset_uses) >= 2:
        return True
    return re.search(
        r"\bRegistrationContext\s*=\s*\(\s*PVOID\s*\)\s*%s\s*;" % re.escape(name),
        text,
    ) is not None


def _parameter_controls_callback_enable(text: str, name: str) -> bool:
    return re.search(r"\bif\s*\(\s*%s\s*\)" % re.escape(name), text) is not None


def _assigned_callback_status_variables(text: str) -> list[tuple[str, str]]:
    roles: list[tuple[str, str]] = []
    for routine in (
        "PsSetCreateProcessNotifyRoutineEx",
        "PsSetCreateProcessNotifyRoutine",
        "PsSetLoadImageNotifyRoutine",
        "PsSetCreateThreadNotifyRoutine",
        "ObRegisterCallbacks",
    ):
        match = re.search(
            r"\b(?P<variable>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*\(" % re.escape(routine),
            text,
        )
        if match is not None:
            roles.append((match.group("variable"), routine))
    return roles


def _callback_status_name(routine: str) -> str:
    if "CreateProcess" in routine:
        return "processStatus"
    if "LoadImage" in routine:
        return "imageStatus"
    if "CreateThread" in routine:
        return "threadStatus"
    if routine == "ObRegisterCallbacks":
        return "obStatus"
    return "callbackStatus"


def _callback_altitude_string_variable(text: str) -> str:
    match = re.search(
        r"\bqmemcpy\s*\(\s*&[A-Za-z_][A-Za-z0-9_]*\.Altitude\s*,\s*"
        r"&(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*,",
        text,
    )
    if match is not None:
        return match.group("name")
    match = re.search(
        r"\b[A-Za-z_][A-Za-z0-9_]*\.Altitude\s*=\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;",
        text,
    )
    if match is not None:
        return match.group("name")
    return ""


def _operation_registration_variable(text: str) -> str:
    match = re.search(
        r"\bOperationRegistration\s*=\s*\(\s*OB_OPERATION_REGISTRATION\s*\*\s*\)"
        r"&?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;",
        text,
    )
    if match is not None:
        return match.group("name")
    match = re.search(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*0\s*\]\s*=\s*Ps[A-Za-z0-9_]*Type\s*;",
        text,
    )
    if match is not None:
        return match.group("name")
    return ""


def _registry_callback_local_rename_roles(text: str) -> list[tuple[str, str, str]]:
    if not _has_registry_callback_registration_evidence(text):
        return []

    roles: list[tuple[str, str, str]] = []
    for variable, routine in _assigned_registry_callback_status_variables(text):
        roles.append(
            (
                variable,
                "registerExStatus" if routine == "CmRegisterCallbackEx" else "registerStatus",
                "Local receives status from %s" % routine,
            )
        )

    version_vars = _registry_callback_version_variables(text)
    if version_vars:
        roles.append((version_vars[0], "majorVersion", "CmGetCallbackVersion major output"))
        roles.append((version_vars[1], "minorVersion", "CmGetCallbackVersion minor output"))

    cookie = _registry_callback_cookie_variable(text)
    if cookie:
        roles.append((cookie, "callbackCookie", "LARGE_INTEGER receives the Cm callback registration cookie"))

    altitude = _registry_callback_altitude_variable(text)
    if altitude:
        roles.append((altitude, "altitudeString", "UNICODE_STRING is passed as CmRegisterCallbackEx altitude"))

    return _dedupe_role_renames(roles)


def _has_registry_callback_registration_evidence(text: str) -> bool:
    return (
        "CmGetCallbackVersion(" in text
        and "CmRegisterCallbackEx(" in text
        and "CmRegisterCallback(" in text
        and "CmUnRegisterCallback(" in text
    )


def _parameter_is_registry_callback_context(text: str, name: str) -> bool:
    escaped = re.escape(name)
    legacy = re.search(r"\bCmRegisterCallback\s*\([^,]+,\s*%s\s*," % escaped, text)
    extended = re.search(r"\bCmRegisterCallbackEx\s*\([^,]+,\s*[^,]+,\s*[^,]+,\s*%s\s*," % escaped, text)
    return legacy is not None or extended is not None


def _assigned_registry_callback_status_variables(text: str) -> list[tuple[str, str]]:
    roles: list[tuple[str, str]] = []
    for routine in ("CmRegisterCallbackEx", "CmRegisterCallback"):
        match = re.search(
            r"\b(?P<variable>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*\(" % re.escape(routine),
            text,
        )
        if match is not None:
            roles.append((match.group("variable"), routine))
    return roles


def _registry_callback_version_variables(text: str) -> tuple[str, str] | None:
    match = re.search(
        r"\bCmGetCallbackVersion\s*\(\s*&(?P<major>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*"
        r"&(?P<minor>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
        text,
    )
    if match is None:
        return None
    return match.group("major"), match.group("minor")


def _registry_callback_cookie_variable(text: str) -> str:
    match = re.search(
        r"\bCmUnRegisterCallback\s*\(\s*(?P<cookie>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
        text,
    )
    if match is None:
        return ""
    cookie = match.group("cookie")
    if re.search(r"&%s\b" % re.escape(cookie), text) is None:
        return ""
    return cookie


def _registry_callback_altitude_variable(text: str) -> str:
    match = re.search(
        r"\bCmRegisterCallbackEx\s*\([^,]+,\s*&(?P<altitude>[A-Za-z_][A-Za-z0-9_]*)\s*,",
        text,
    )
    if match is None:
        return ""
    return match.group("altitude")


def _memory_manager_probe_local_rename_roles(text: str) -> list[tuple[str, str, str]]:
    if not _has_memory_manager_probe_evidence(text):
        return []

    roles: list[tuple[str, str, str]] = []

    for variable, new_name, evidence in (
        (
            _stable_assignment_lhs_for_call(text, "MmGetSystemRoutineAddress"),
            "systemRoutineAddress",
            "Local receives MmGetSystemRoutineAddress result",
        ),
        (
            _stable_assignment_lhs_for_call(text, "ExAllocatePool2"),
            "poolBuffer",
            "Local receives ExAllocatePool2 scratch buffer",
        ),
        (
            _stable_assignment_lhs_for_call(text, "IoAllocateMdl"),
            "mdl",
            "Local receives IoAllocateMdl result",
        ),
        (
            _stable_assignment_lhs_for_call(text, "MmAllocateNonCachedMemory"),
            "nonCachedMemory",
            "Local receives MmAllocateNonCachedMemory result",
        ),
        (
            _stable_assignment_lhs_for_call(text, "MmAllocateContiguousMemorySpecifyCache"),
            "contiguousMemory",
            "Local receives MmAllocateContiguousMemorySpecifyCache result",
        ),
        (
            _stable_assignment_lhs_for_call(text, "MmIsAddressValid"),
            "isAddressValid",
            "Local receives MmIsAddressValid result",
        ),
        (
            _stable_assignment_lhs_for_call(text, "MmGetPhysicalAddress"),
            "physicalAddress",
            "Local receives MmGetPhysicalAddress result",
        ),
    ):
        if variable:
            roles.append((variable, new_name, evidence))

    probe_sink = _memory_manager_probe_sink_variable(text)
    if probe_sink:
        roles.append(
            (probe_sink, "probeSinkValue", "Scratch sink records heterogeneous memory-manager probe results")
        )

    routine_name = _mm_system_routine_name_variable(text)
    if routine_name:
        roles.append((routine_name, "systemRoutineName", "UNICODE_STRING names MmGetSystemRoutineAddress target"))

    bytes_copied = _mm_copy_memory_bytes_variable(text)
    if bytes_copied:
        roles.append((bytes_copied, "bytesCopied", "Local receives MmCopyMemory NumberOfBytesTransferred"))

    copy_target = _mm_copy_memory_target_variable(text)
    if copy_target:
        roles.append((copy_target, "copyBuffer", "Stack buffer receives MmCopyMemory output"))

    source_buffer = _pool_source_buffer_variable(text)
    if source_buffer and source_buffer != copy_target:
        roles.append((source_buffer, "sourceBuffer", "Stack buffer is copied into the allocated pool buffer"))

    for old_name, new_name in (
        ("LowestAcceptableAddress", "lowestAcceptableAddress"),
        ("HighestAcceptableAddress", "highestAcceptableAddress"),
        ("BoundaryAddressMultiple", "boundaryAddressMultiple"),
    ):
        if re.search(r"\b%s\b" % old_name, text):
            roles.append((old_name, new_name, "PHYSICAL_ADDRESS bound for contiguous memory allocation"))

    return _dedupe_role_renames(roles)


def _has_memory_manager_probe_evidence(text: str) -> bool:
    if "MmGetSystemRoutineAddress(" not in text or "MmCopyMemory(" not in text:
        return False
    mm_calls = {
        match.group(1)
        for match in re.finditer(r"\b(Mm[A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
    }
    has_mdl_path = "IoAllocateMdl(" in text or "MmBuildMdlForNonPagedPool(" in text
    has_allocation_path = any(
        routine in text
        for routine in (
            "ExAllocatePool2(",
            "ExAllocatePoolWithTag(",
            "MmAllocateContiguousMemory",
            "MmAllocateNonCachedMemory(",
        )
    )
    return len(mm_calls) >= 4 and has_mdl_path and has_allocation_path


def _assignment_lhs_for_call(text: str, call_name: str) -> str:
    match = re.search(
        r"(?m)^\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?%s\s*\("
        % re.escape(call_name),
        text,
    )
    if match is None:
        return ""
    return match.group("lhs")


def _stable_assignment_lhs_for_call(text: str, call_name: str) -> str:
    for variable in _assignment_lhs_for_calls(text, (call_name,)).get(call_name, []):
        if _is_unstable_assignment_sink(text, variable):
            continue
        return variable
    return ""


def _assignment_lhs_for_calls(text: str, call_names) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for call_name in call_names:
        matches = re.findall(
            r"(?m)^\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]*\)\s*)?%s\s*\("
            % re.escape(call_name),
            text,
        )
        result[call_name] = matches
    return result


def _is_unstable_assignment_sink(text: str, name: str) -> bool:
    rhs_values = _nontrivial_direct_assignment_rhs_values(text, name)
    if len(rhs_values) <= 1:
        return False
    if _is_decompiler_global_name(name):
        return True
    return len(rhs_values) >= 3


def _memory_manager_probe_sink_variable(text: str) -> str:
    assignments = _direct_assignment_rhs_by_lhs(text)
    for name, rhs_values in assignments.items():
        if not _is_decompiler_global_name(name):
            continue
        nontrivial_values = [rhs for rhs in rhs_values if not _is_zero_like_rhs(rhs)]
        if len(nontrivial_values) < 4:
            continue
        joined = "\n".join(nontrivial_values)
        if re.search(
            r"\bMm[A-Za-z0-9_]*\b|\bMdl\b|->(?:ByteCount|ByteOffset|MappedSystemVa|StartVa)\b",
            joined,
        ):
            return name
    return ""


def _nontrivial_direct_assignment_rhs_values(text: str, name: str) -> list[str]:
    return [rhs for rhs in _direct_assignment_rhs_values(text, name) if not _is_zero_like_rhs(rhs)]


def _direct_assignment_rhs_values(text: str, name: str) -> list[str]:
    return _direct_assignment_rhs_by_lhs(text).get(name, [])


def _direct_assignment_rhs_by_lhs(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for match in re.finditer(
        r"(?m)^\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>[^;\n]+);",
        text or "",
    ):
        result.setdefault(match.group("lhs"), []).append(match.group("rhs").strip())
    return result


def _is_zero_like_rhs(rhs: str) -> bool:
    return bool(
        re.fullmatch(
            r"(?:\([^)]*\)\s*)?(?:0|0u|0LL|0i64|NULL|nullptr|FALSE|false)",
            (rhs or "").strip(),
        )
    )


def _is_decompiler_global_name(name: str) -> bool:
    return bool(re.fullmatch(r"(?:qword|dword|word|byte|off|unk)_[0-9A-Fa-f]+", name or ""))


def _first_single_routine_assignment_lhs(candidates: list[str], lhs_routine_count: dict[str, set[str]]) -> str:
    for candidate in candidates:
        if len(lhs_routine_count.get(candidate, set())) == 1:
            return candidate
    return ""


def _mm_system_routine_name_variable(text: str) -> str:
    for match in re.finditer(
        r"\bRtlInitUnicodeString\s*\(\s*&(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*"
        r"L\"(?P<routine>[A-Za-z_][A-Za-z0-9_]*)\"\s*\)",
        text,
    ):
        name = match.group("name")
        if re.search(r"\bMmGetSystemRoutineAddress\s*\(\s*&%s\s*\)" % re.escape(name), text):
            return name
    return ""


def _mm_copy_memory_bytes_variable(text: str) -> str:
    for arguments in extract_call_arguments(text, "MmCopyMemory"):
        if len(arguments) < 5:
            continue
        variable = _out_argument_identifier(arguments[4])
        if variable:
            return variable
    return ""


def _out_argument_identifier(argument: str) -> str:
    match = re.fullmatch(
        r"(?:\([^)]*\)\s*)*&?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
        (argument or "").strip(),
    )
    if match is None:
        return ""
    return match.group("name")


def _mm_copy_memory_target_variable(text: str) -> str:
    match = re.search(
        r"\bMmCopyMemory\s*\(\s*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*,",
        text,
    )
    if match is None:
        return ""
    return match.group("target")


def _pool_source_buffer_variable(text: str) -> str:
    pool = _stable_assignment_lhs_for_call(text, "ExAllocatePool2")
    if not pool:
        return ""
    match = re.search(
        r"\bqmemcpy\s*\(\s*%s\s*,\s*(?P<source>[A-Za-z_][A-Za-z0-9_]*)\s*,"
        % re.escape(pool),
        text,
    )
    if match is not None:
        return match.group("source")
    match = re.search(
        r"\*\s*%s\s*=\s*(?P<source>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*0\s*\]\s*;"
        % re.escape(pool),
        text or "",
    )
    if match is not None:
        return match.group("source")
    return ""


def _zw_api_probe_local_rename_roles(text: str) -> list[tuple[str, str, str]]:
    if not _has_zw_api_probe_evidence(text):
        return []

    roles: list[tuple[str, str, str]] = []
    routine_lhs = _assignment_lhs_for_calls(text, _ZW_STATUS_NAMES)
    lhs_routine_count: dict[str, set[str]] = {}
    for routine, variables in routine_lhs.items():
        for variable in variables:
            lhs_routine_count.setdefault(variable, set()).add(routine)
    for routine, new_name in _ZW_STATUS_NAMES.items():
        variable = _first_single_routine_assignment_lhs(routine_lhs.get(routine, []), lhs_routine_count)
        if variable:
            roles.append((variable, new_name, "Local receives status from %s" % routine))

    generic_handle = _zw_probe_generic_handle_variable(text)
    if generic_handle:
        roles.append((generic_handle, "genericHandle", "Handle local is reused by Zw event, key, and file APIs"))

    token_handle = _zw_probe_token_handle_variable(text)
    if token_handle:
        roles.append((token_handle, "tokenHandle", "Handle local receives Zw token open results"))

    object_path = _zw_probe_object_path_variable(text)
    if object_path:
        roles.append((object_path, "objectPath", "UNICODE_STRING local receives registry and file object paths"))

    info_buffer = _zw_probe_info_buffer_variable(text)
    if info_buffer:
        roles.append((info_buffer, "infoBuffer", "Scratch buffer is reused across heterogeneous Zw query APIs"))

    return_length = _zw_probe_return_length_variable(text)
    if return_length:
        roles.append((return_length, "returnLength", "ULONG receives Zw query result lengths"))

    object_attributes = _first_identifier(_zw_probe_object_attribute_variables(text))
    if object_attributes:
        roles.append((object_attributes, "objectAttributes", "OBJECT_ATTRIBUTES local is passed to Zw object opens"))

    timeout = _zw_probe_timeout_variable(text)
    if timeout:
        roles.append((timeout, "timeout", "LARGE_INTEGER timeout is used by ZwWaitForSingleObject"))

    io_status = _zw_probe_io_status_block_variable(text)
    if io_status:
        roles.append((io_status, "ioStatusBlock", "IO_STATUS_BLOCK is passed to Zw file APIs"))

    value_name = _zw_probe_value_name_variable(text)
    if value_name:
        roles.append((value_name, "valueName", "UNICODE_STRING names the queried registry value"))

    return _dedupe_role_renames(roles)


def _has_zw_api_probe_evidence(text: str) -> bool:
    zw_calls = {
        match.group(1)
        for match in re.finditer(r"\b(Zw[A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
    }
    if len(zw_calls) < 8:
        return False
    matched_categories = {
        category
        for category, routines in _ZW_CATEGORY_ROUTINES.items()
        if routines.intersection(zw_calls)
    }
    if len(matched_categories) < 4:
        return False
    return bool(_zw_probe_object_attribute_variables(text)) and bool(_zw_probe_info_buffer_variable(text))


def _zw_probe_generic_handle_variable(text: str) -> str:
    candidates = []
    for routine, index in _ZW_HANDLE_OUTPUT_ARGUMENTS.items():
        for arguments in extract_call_arguments(text, routine):
            handle = _identifier_from_reference(_argument_at(arguments, index))
            if handle:
                candidates.append(handle)
    if not candidates:
        return ""
    for candidate in candidates:
        if candidates.count(candidate) >= 2:
            return candidate
    return ""


def _zw_probe_token_handle_variable(text: str) -> str:
    for routine, index in _ZW_TOKEN_HANDLE_OUTPUT_ARGUMENTS.items():
        for arguments in extract_call_arguments(text, routine):
            handle = _identifier_from_reference(_argument_at(arguments, index))
            if handle:
                return handle
    return ""


def _zw_probe_object_path_variable(text: str) -> str:
    object_attributes = _zw_probe_object_attribute_variables(text)
    path_vars = []
    for object_name in object_attributes:
        for match in re.finditer(
            r"\b%s\.ObjectName\s*=\s*&(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;"
            % re.escape(object_name),
            text,
        ):
            path_vars.append(match.group("name"))
    if not path_vars:
        return ""
    return _first_repeated_or_first(path_vars)


def _zw_probe_info_buffer_variable(text: str) -> str:
    candidates: list[str] = []
    for routine, index in _ZW_QUERY_BUFFER_ARGUMENTS.items():
        for arguments in extract_call_arguments(text, routine):
            buffer_name = _plain_identifier(_argument_at(arguments, index))
            if buffer_name:
                candidates.append(buffer_name)
    return _first_repeated_or_first(candidates)


def _zw_probe_return_length_variable(text: str) -> str:
    candidates: list[str] = []
    for routine, index in _ZW_RETURN_LENGTH_ARGUMENTS.items():
        for arguments in extract_call_arguments(text, routine):
            name = _identifier_from_reference(_argument_at(arguments, index))
            if name:
                candidates.append(name)
    return _first_repeated_or_first(candidates)


def _zw_probe_object_attribute_variables(text: str) -> set[str]:
    variables: set[str] = set()
    for routine, index in _ZW_OBJECT_ATTRIBUTE_ARGUMENTS.items():
        for arguments in extract_call_arguments(text, routine):
            name = _identifier_from_reference(_argument_at(arguments, index))
            if name:
                variables.add(name)
    return variables


def _zw_probe_timeout_variable(text: str) -> str:
    candidates: list[str] = []
    for arguments in extract_call_arguments(text, "ZwWaitForSingleObject"):
        name = _identifier_from_reference(_argument_at(arguments, 2))
        if name:
            candidates.append(name)
    return _first_repeated_or_first(candidates)


def _zw_probe_io_status_block_variable(text: str) -> str:
    candidates: list[str] = []
    for arguments in extract_call_arguments(text, "ZwCreateFile"):
        name = _identifier_from_reference(_argument_at(arguments, 3))
        if name:
            candidates.append(name)
    for arguments in extract_call_arguments(text, "ZwQueryInformationFile"):
        name = _identifier_from_reference(_argument_at(arguments, 1))
        if name:
            candidates.append(name)
    return _first_repeated_or_first(candidates)


def _zw_probe_value_name_variable(text: str) -> str:
    for arguments in extract_call_arguments(text, "ZwQueryValueKey"):
        name = _identifier_from_reference(_argument_at(arguments, 1))
        if name:
            return name
    return ""


def _argument_at(arguments: list[str], index: int) -> str:
    if index < 0 or index >= len(arguments):
        return ""
    return arguments[index]


def _identifier_from_reference(argument: str) -> str:
    return _plain_identifier(_strip_casts_and_reference(argument))


def _plain_identifier(argument: str) -> str:
    argument = _strip_casts_and_reference(argument)
    match = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", argument)
    return match.group(0) if match is not None else ""


def _strip_casts_and_reference(argument: str) -> str:
    result = argument.strip()
    while True:
        previous = result
        result = re.sub(r"^\([^)]*\)\s*", "", result).strip()
        if result.startswith("&"):
            result = result[1:].strip()
        if result == previous:
            return result


def _first_repeated_or_first(candidates: list[str]) -> str:
    for candidate in candidates:
        if candidates.count(candidate) >= 2:
            return candidate
    return candidates[0] if candidates else ""


def _first_identifier(values: set[str]) -> str:
    return sorted(values)[0] if values else ""


def _driver_dispatch_local_rename_roles(text: str) -> list[tuple[str, str, str]]:
    roles: list[tuple[str, str, str]] = []
    for match in re.finditer(
        r"(?m)^\s*(?P<extension>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"\*\(\s*_QWORD\s+\*\s*\)\s*\(\s*(?P<device>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*64\s*\)\s*;",
        text,
    ):
        roles.append(
            (
                match.group("extension"),
                "deviceExtension",
                "Local receives DEVICE_OBJECT.DeviceExtension from a driver dispatch DeviceObject parameter",
            )
        )
    for match in re.finditer(
        r"(?m)^\s*(?P<extension>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(?P<device>[A-Za-z_][A-Za-z0-9_]*)->DeviceExtension\s*;",
        text,
    ):
        roles.append(
            (
                match.group("extension"),
                "deviceExtension",
                "Local receives DEVICE_OBJECT.DeviceExtension from a driver dispatch DeviceObject parameter",
            )
        )
    return _dedupe_role_renames(roles)


def _irp_device_control_rename_roles(text: str) -> list[tuple[str, str, str]]:
    roles: list[tuple[str, str, str]] = []
    for stack_name in _dword_stack_location_candidates(text):
        io_control_var = _io_control_code_variable(text, stack_name)
        if not io_control_var:
            continue
        roles.append(
            (
                stack_name,
                "ioStackLocation",
                "Local indexes IO_STACK_LOCATION.Parameters.DeviceIoControl fields",
            )
        )
        roles.append(
            (
                io_control_var,
                "ioControlCode",
                "Local receives IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode",
            )
        )
        system_buffer = _irp_device_control_system_buffer_variable(text, io_control_var)
        if system_buffer:
            roles.append(
                (
                    system_buffer,
                    "systemBuffer",
                    "Local receives IRP AssociatedIrp.SystemBuffer for METHOD_BUFFERED IOCTL cases",
                )
            )
        information = _irp_information_variable(text)
        if information:
            roles.append(
                (
                    information,
                    "information",
                    "Local is written to IRP IoStatus.Information before completion",
                )
            )
        for index, field_name in (("2", "outputBufferLength"), ("4", "inputBufferLength")):
            for dst in re.findall(
                r"(?m)^\s*(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*\[\s*%s\s*\]\s*;"
                % (re.escape(stack_name), index),
                text,
            ):
                roles.append(
                    (
                        dst,
                        field_name,
                        "Local receives IO_STACK_LOCATION.Parameters.DeviceIoControl.%s"
                        % ("OutputBufferLength" if index == "2" else "InputBufferLength"),
                    )
                )
    return _dedupe_role_renames(roles)


def _irp_information_variable(text: str) -> str:
    for match in re.finditer(
        r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*->IoStatus\.Information\s*=\s*"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;",
        text,
    ):
        return match.group("name")
    return ""


def _dword_stack_location_candidates(text: str) -> list[str]:
    return [
        match.group("name")
        for match in re.finditer(
            r"(?m)^\s*(?:_DWORD|unsigned\s+int|ULONG)\s+\*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;[^\n]*$",
            text,
        )
    ]


def _io_control_code_variable(text: str, stack_name: str) -> str:
    escaped = re.escape(stack_name)
    match = re.search(
        r"(?m)^\s*(?P<ioctl>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*\[\s*6\s*\]\s*;" % escaped,
        text,
    )
    if match is None:
        return ""
    ioctl_var = match.group("ioctl")
    if re.search(r"\bswitch\s*\(\s*(?:\(\s*[^()]+\s*\)\s*)*%s\s*\)" % re.escape(ioctl_var), text) is None:
        return ""
    return ioctl_var


def _irp_device_control_system_buffer_variable(text: str, io_control_var: str) -> str:
    if not _all_switch_cases_method_buffered(text, io_control_var):
        return ""
    params = extract_parameters_from_signature(text.split("{", 1)[0])
    irp_param = _candidate_irp_parameter_name(text, params)
    if not irp_param:
        return ""
    escaped = re.escape(irp_param)
    for match in re.finditer(
        r"(?m)^\s*(?P<buffer>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"\*\([^;\n]*\*+\s*\)\s*\(\s*%s\s*\+\s*24\s*\)\s*;" % escaped,
        text,
    ):
        buffer_name = match.group("buffer")
        if re.search(r"\bif\s*\(\s*!\s*%s\s*&&" % re.escape(buffer_name), text):
            return buffer_name
    return ""


def _all_switch_cases_method_buffered(text: str, dispatcher: str) -> bool:
    case_values = _switch_case_values_for_dispatcher(text, dispatcher)
    if not case_values:
        return False
    for value in case_values:
        decoded = decode_ioctl_code(value)
        if decoded is None or decoded.method != 0:
            return False
    return True


def _switch_case_values_for_dispatcher(text: str, dispatcher: str) -> list[int]:
    switch_match = re.search(
        r"\bswitch\s*\(\s*(?:\(\s*[^()]+\s*\)\s*)*%s\s*\)" % re.escape(dispatcher),
        text,
    )
    if switch_match is None:
        return []
    open_index = text.find("{", switch_match.end())
    if open_index < 0:
        return []
    depth = 0
    end_index = -1
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end_index = index
                break
    if end_index < 0:
        return []
    values: list[int] = []
    body = text[open_index:end_index]
    for match in re.finditer(r"\bcase\s+(?P<value>0x[0-9A-Fa-f]+|\d+)(?:[A-Za-z0-9]*)?\s*:", body):
        value = parse_c_integer_literal(match.group("value"))
        if value is not None:
            values.append(value)
    return values


def _looks_like_record_name(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith("record") or lowered.endswith("entry") or lowered.startswith("provider")


def _looks_like_link_name(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith("link") or lowered.endswith("listentry") or lowered.endswith("list_entry")


def _link_name_from_record(record: str) -> str:
    if record.startswith("new"):
        return "newProviderLink"
    if record.startswith("provider"):
        return "providerLink"
    return "recordLink"


def _has_list_unlink_pattern(text: str) -> bool:
    return (
        "__fastfail(3" in text
        and "ObfDereferenceObject" in text
        and "ExFreePoolWithTag" in text
        and re.search(r"\*\(_QWORD \*\)\([^)]*\+\s*8\)\s*=", text) is not None
    )


def _has_list_insert_tail_pattern(text: str) -> bool:
    if "ExAllocatePool2" not in text:
        return False
    generic_insert = re.search(
        r"\*(?P<new>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*&(?P<head>[A-Za-z_][A-Za-z0-9_]*ListHead)\s*;"
        r"\s*(?P=new)\[1\]\s*=\s*(?P<tail>[A-Za-z_][A-Za-z0-9_]*)\s*;"
        r"\s*\*(?P=tail)\s*=\s*(?P=new)\s*;"
        r"\s*qword_[A-Fa-f0-9]+\s*=\s*\(__int64\)(?P=new)\s*;",
        text,
        re.DOTALL,
    )
    if generic_insert is not None:
        return True
    return (
        re.search(r"\[[01]\]\s*=\s*tailLink", text) is not None
        and re.search(r"\*tailLink\s*=\s*new", text) is not None
    )


def _has_bad_driver_object_reference_name(text: str) -> bool:
    return bool(suspicious_ps_reference_silo_context_operands(text))


def suspicious_ps_reference_silo_context_operands(text: str) -> tuple[str, ...]:
    if "PsReferenceSiloContext" not in text or "Ob" not in text:
        return ()

    suspicious: list[str] = []
    for match in re.finditer(r"\bPsReferenceSiloContext\((?P<operand>[^;\n]+)\);", text):
        operand = _normalize_call_operand(match.group("operand"))
        if not operand:
            continue
        if _operand_looks_like_driver_object(operand):
            suspicious.append(operand)
            continue
        if _operand_looks_like_object_pointer(text, operand):
            suspicious.append(operand)

    return tuple(dict.fromkeys(suspicious))


def _normalize_call_operand(operand: str) -> str:
    return re.sub(r"\s+", " ", operand.strip())


def _operand_looks_like_driver_object(operand: str) -> bool:
    return (
        "DriverObject" in operand
        or re.search(r"\+\s*16\)", operand) is not None
    )


def _operand_looks_like_object_pointer(text: str, operand: str) -> bool:
    if re.search(r"^[A-Za-z_][A-Za-z0-9_]*$", operand) is None:
        return False
    escaped = re.escape(operand)
    if (
        re.search(r"\bObf?DereferenceObject(?:WithTag|DeferDelete)?\(\s*%s\s*[,)]" % escaped, text)
        is not None
    ):
        return True
    return (
        re.search(
            r"(?m)^\s*(?:P[A-Z0-9_]*OBJECT|PFILE_OBJECT|PDEVICE_OBJECT|PDRIVER_OBJECT|PACCESS_TOKEN|"
            r"struct\s+_[A-Za-z0-9_]*OBJECT\s*\*)\s+%s\b" % escaped,
            text,
        )
        is not None
    )


def _record_layout_comments(text: str) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    if (
        "ExAllocatePool2" in text
        and "ProviderSignature" in text
        and "+ 24" in text
        and "+ 32" in text
    ):
        comments.append(
            _comment(
                "inferred_record_layout",
                (
                    "Inferred provider record layout: +0x00 ProviderSignature, "
                    "+0x08 FirmwareTableHandler, +0x10 DriverObject, "
                    "+0x18 LIST_ENTRY Link, size 0x28"
                ),
                0.82,
            )
        )
    return comments


def _pool_tag_comments(text: str) -> list[dict[str, Any]]:
    comments = []
    seen = set()
    for match in _POOL_TAG_RE.finditer(text):
        literal = match.group("tag")
        tag = _decode_pool_tag(literal)
        if not tag or (literal, tag) in seen:
            continue
        seen.add((literal, tag))
        comments.append(
            _comment(
                "pool_tag",
                "Pool tag %s decodes to '%s'",
                0.80,
            )
        )
        comments[-1]["text"] = comments[-1]["text"] % (literal, tag)
    return comments


def _decode_pool_tag(literal: str) -> str:
    try:
        value = int(literal, 16)
    except ValueError:
        return ""
    chars = []
    for shift in (0, 8, 16, 24):
        byte = (value >> shift) & 0xFF
        if byte < 0x20 or byte > 0x7E:
            return ""
        chars.append(chr(byte))
    return "".join(chars)


def _status_accumulator_name(text: str) -> str:
    candidates = re.findall(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*0\s*;", text)
    for name in candidates:
        if re.search(r"\breturn\s+%s\s*;" % re.escape(name), text) is None:
            continue
        assignments = re.findall(r"\b%s\s*=\s*([^;]+);" % re.escape(name), text)
        if any(_STATUS_LITERAL_RE.search(item) for item in assignments):
            return name
    for name in re.findall(r"(?m)^\s*NTSTATUS\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;", text):
        returned = re.search(
            r"\breturn\s+(?:\(\s*(?:unsigned\s+int|ULONG|NTSTATUS)\s*\)\s*)?%s\s*;" % re.escape(name),
            text,
        )
        if returned is None:
            continue
        assignments = re.findall(r"\b%s\s*=\s*([^;]+);" % re.escape(name), text)
        if any(_STATUS_LITERAL_RE.search(item) or "IoCreate" in item or "STATUS_" in item for item in assignments):
            return name
    return ""


def _apply_rename_map(text: str, rename_map: dict[str, str]) -> str:
    return safe_identifier_replace(text, rename_map)

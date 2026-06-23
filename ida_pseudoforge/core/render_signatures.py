from __future__ import annotations

import re

from ida_pseudoforge.core.api_semantics import FUNCTION_SIGNATURE_OVERRIDES
from ida_pseudoforge.core.domain_identity import DomainIdentityPrototype, domain_identity_function_prototypes
from ida_pseudoforge.core.kernel_semantics import (
    looks_like_callback_registration_toggle,
    looks_like_driver_entry,
    looks_like_irp_dispatch,
    looks_like_registry_callback_registration,
    looks_like_zw_api_probe,
)
from ida_pseudoforge.core.normalize import (
    extract_function_name,
    find_matching_paren,
    split_parameters_with_spans,
)
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture, ParameterTypeCorrection
from ida_pseudoforge.core.render_callbacks import (
    apply_known_callback_signature as _apply_known_callback_signature_impl,
    normalize_callback_registration_toggle_body as _normalize_callback_registration_toggle_body,
    normalize_registry_callback_registration_body as _normalize_registry_callback_registration_body,
)
from ida_pseudoforge.core.render_driver_entry import (
    driver_entry_signature_override as _driver_entry_signature_override,
    normalize_driver_entry_body as _normalize_driver_entry_body,
)
from ida_pseudoforge.core.render_ioctl import (
    irp_dispatch_signature_override as _irp_dispatch_signature_override,
    normalize_irp_dispatch_body as _normalize_irp_dispatch_body,
)
from ida_pseudoforge.core.render_ntset import (
    normalize_ntset_system_information_body as _normalize_ntset_system_information_body,
)
from ida_pseudoforge.core.render_zw import normalize_zw_api_probe_body as _normalize_zw_api_probe_body


def apply_known_function_signature(text: str, capture: FunctionCapture) -> str:
    function_name = capture.name or extract_function_name(capture.prototype)
    override = FUNCTION_SIGNATURE_OVERRIDES.get(function_name)
    if not override and looks_like_driver_entry(capture):
        override = _driver_entry_signature_override()
    if not override and looks_like_irp_dispatch(capture):
        override = _irp_dispatch_signature_override(function_name)
    if not override or not function_name:
        return text

    lines = text.splitlines()
    for index, line in enumerate(lines):
        if re.search(r"\b%s\s*\(" % re.escape(function_name), line):
            end_index = find_signature_end(lines, index)
            if end_index < index:
                return text
            lines = lines[:index] + override + lines[end_index + 1 :]
            return "\n".join(lines)
    return text


def apply_known_callback_signature(text: str, capture: FunctionCapture) -> str:
    return _apply_known_callback_signature_impl(text, capture, find_signature_end)


def apply_profile_parameter_type_corrections(
    text: str,
    capture: FunctionCapture,
    plan: CleanPlan,
) -> str:
    prototype = _select_profile_signature_prototype(capture, plan)
    corrections = {
        item.parameter_index: item
        for item in plan.type_corrections
        if item.apply_to_preview and not item.blockers and item.canonical_type
    }
    if not corrections and prototype is None:
        return text

    function_names = _signature_function_name_candidates(capture)
    if not function_names:
        return text
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not any(_line_has_function_signature(line, function_name) for function_name in function_names):
            continue
        end_index = find_signature_end(lines, index)
        if end_index < index:
            return text
        signature = "\n".join(lines[index:end_index + 1])
        corrected = _correct_signature_prototype(signature, prototype, function_names)
        corrected = _correct_signature_parameters(corrected, corrections)
        if corrected == signature:
            return text
        lines = lines[:index] + corrected.splitlines() + lines[end_index + 1:]
        return "\n".join(lines)
    return text


def _select_profile_signature_prototype(
    capture: FunctionCapture,
    plan: CleanPlan,
) -> DomainIdentityPrototype | None:
    prototypes = [
        item
        for item in domain_identity_function_prototypes(
            capture.pseudocode,
            profile_context=capture.profile_context,
        )
        if item.signature_preview and not item.blockers
    ]
    if not prototypes:
        return None

    correction_profile_ids = {
        item.profile_id
        for item in plan.type_corrections
        if item.apply_to_preview and not item.blockers
    }
    if correction_profile_ids:
        prototypes = [item for item in prototypes if item.profile_id in correction_profile_ids]
    if len(prototypes) != 1:
        return None
    prototype = prototypes[0]
    if not prototype.return_type and not prototype.calling_convention:
        return None
    return prototype


def _signature_function_name_candidates(capture: FunctionCapture) -> list[str]:
    candidates = [
        capture.name,
        extract_function_name(capture.prototype),
    ]
    result: list[str] = []
    for candidate in candidates:
        if _is_signature_function_name_candidate(candidate) and candidate not in result:
            result.append(candidate)
    return result


def _is_signature_function_name_candidate(function_name: str) -> bool:
    return bool(function_name and len(function_name) > 1)


def _line_has_function_signature(line: str, function_name: str) -> bool:
    if not function_name:
        return False
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", function_name):
        return bool(re.search(r"\b%s\s*\(" % re.escape(function_name), line))
    return bool(re.search(r"%s\s*\(" % re.escape(function_name), line))


def apply_known_signature_body_rewrites(text: str, capture: FunctionCapture) -> str:
    function_name = capture.name or extract_function_name(capture.prototype)
    if function_name != "NtSetSystemInformation":
        if looks_like_driver_entry(capture):
            return _normalize_driver_entry_body(text)
        if looks_like_irp_dispatch(capture):
            return _normalize_irp_dispatch_body(text)
        if looks_like_callback_registration_toggle(capture):
            return _normalize_callback_registration_toggle_body(text, capture)
        if looks_like_registry_callback_registration(capture):
            return _normalize_registry_callback_registration_body(text)
        if looks_like_zw_api_probe(capture):
            return _normalize_zw_api_probe_body(text)
        return text
    return _normalize_ntset_system_information_body(text)


def _correct_signature_parameters(
    signature: str,
    corrections: dict[int, ParameterTypeCorrection],
) -> str:
    open_index = signature.find("(")
    close_index = find_matching_paren(signature, open_index)
    if open_index < 0 or close_index <= open_index:
        return signature
    parameter_text = signature[open_index + 1:close_index]
    parameters = split_parameters_with_spans(parameter_text)
    if not parameters:
        return signature

    replacements: list[tuple[int, int, str]] = []
    for parameter_index, (_parameter, span) in enumerate(parameters):
        correction = corrections.get(parameter_index)
        if correction is None:
            continue
        current_name = _parameter_name(_parameter)
        if not current_name:
            continue
        render_name = current_name
        if current_name == correction.new_name:
            render_name = correction.new_name
        elif current_name == correction.old_name and correction.new_name == correction.old_name:
            render_name = correction.new_name
        render_type = correction.display_type or correction.canonical_type
        replacement = "%s %s" % (render_type, render_name)
        replacements.append((span[0], span[1], replacement))

    if not replacements:
        return signature
    updated_parameters = parameter_text
    for start, end, replacement in sorted(replacements, reverse=True):
        updated_parameters = updated_parameters[:start] + replacement + updated_parameters[end:]
    return signature[:open_index + 1] + updated_parameters + signature[close_index:]


def _correct_signature_prototype(
    signature: str,
    prototype: DomainIdentityPrototype | None,
    function_names: list[str],
) -> str:
    if prototype is None:
        return signature
    open_index = signature.find("(")
    if open_index < 0:
        return signature

    leader = signature[:open_index].rstrip()
    trailing_space = signature[len(leader):open_index]
    name_span = _signature_name_span(leader, function_names)
    if name_span is None:
        return signature

    existing_specifiers = leader[:name_span[0]].strip()
    function_name = leader[name_span[0]:name_span[1]].strip()
    if not function_name:
        return signature

    calling_convention = prototype.calling_convention or _signature_calling_convention(existing_specifiers)
    return_type = prototype.return_type or _signature_return_type(existing_specifiers, calling_convention)
    specifiers = " ".join(item for item in (return_type, calling_convention) if item)
    if not specifiers:
        return signature
    replacement = "%s %s" % (specifiers, function_name)
    return replacement + trailing_space + signature[open_index:]


def _signature_name_span(
    leader: str,
    function_names: list[str],
) -> tuple[int, int] | None:
    best: tuple[int, int] | None = None
    for function_name in sorted(function_names, key=len, reverse=True):
        if not function_name:
            continue
        match = re.search(r"%s\s*\Z" % re.escape(function_name), leader)
        if match:
            best = (match.start(), match.end())
            break
    if best is not None:
        return _extend_qualified_name_span(leader, best)

    match = re.search(
        r"((?:[A-Za-z_~][A-Za-z0-9_~<>:$]*::)*[A-Za-z_~][A-Za-z0-9_~<>:$]*)\s*\Z",
        leader,
    )
    if not match:
        return None
    return (match.start(1), match.end(1))


def _extend_qualified_name_span(
    leader: str,
    span: tuple[int, int],
) -> tuple[int, int]:
    start, end = span
    prefix_match = re.search(
        r"((?:[A-Za-z_~][A-Za-z0-9_~<>:$]*::)+)\Z",
        leader[:start],
    )
    if prefix_match:
        start = prefix_match.start(1)
    return start, end


def _signature_calling_convention(specifiers: str) -> str:
    match = re.search(r"\b__(?:cdecl|fastcall|stdcall|thiscall|vectorcall)\b", specifiers)
    return match.group(0) if match else ""


def _signature_return_type(
    specifiers: str,
    calling_convention: str,
) -> str:
    value = specifiers.strip()
    if calling_convention:
        value = re.sub(r"\s*%s\b" % re.escape(calling_convention), "", value, count=1).strip()
    value = re.sub(r"\s*__(?:cdecl|fastcall|stdcall|thiscall|vectorcall)\b", "", value).strip()
    return value


def _parameter_name(parameter: str) -> str:
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?$", parameter.strip())
    return match.group(1) if match else ""


def find_signature_end(lines: list[str], start_index: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start_index, len(lines)):
        for char in lines[index]:
            if char == "(":
                depth += 1
                seen_open = True
            elif char == ")":
                depth -= 1
                if seen_open and depth <= 0:
                    return index
    return -1

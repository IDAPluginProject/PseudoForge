from __future__ import annotations

import re

from ida_pseudoforge.core.api_semantics import FUNCTION_SIGNATURE_OVERRIDES
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
    corrections = {
        item.parameter_index: item
        for item in plan.type_corrections
        if item.apply_to_preview and not item.blockers and item.canonical_type
    }
    if not corrections:
        return text

    function_name = capture.name or extract_function_name(capture.prototype)
    if not function_name:
        return text
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not re.search(r"\b%s\s*\(" % re.escape(function_name), line):
            continue
        end_index = find_signature_end(lines, index)
        if end_index < index:
            return text
        signature = "\n".join(lines[index:end_index + 1])
        corrected = _correct_signature_parameters(signature, corrections)
        if corrected == signature:
            return text
        lines = lines[:index] + corrected.splitlines() + lines[end_index + 1:]
        return "\n".join(lines)
    return text


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
        replacement = "%s %s" % (correction.canonical_type, render_name)
        replacements.append((span[0], span[1], replacement))

    if not replacements:
        return signature
    updated_parameters = parameter_text
    for start, end, replacement in sorted(replacements, reverse=True):
        updated_parameters = updated_parameters[:start] + replacement + updated_parameters[end:]
    return signature[:open_index + 1] + updated_parameters + signature[close_index:]


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

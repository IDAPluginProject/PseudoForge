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
from ida_pseudoforge.core.normalize import extract_function_name
from ida_pseudoforge.core.plan_schema import FunctionCapture
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

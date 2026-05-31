from __future__ import annotations

import re

from ida_pseudoforge.core.normalize import extract_call_arguments

_C_INTEGER_SUFFIX_PATTERN = r"(?i:ui64|i64|u?ll|llu|ul|lu|u|l)"
_C_UNSIGNED_INTEGER_LITERAL_PATTERN = r"(?:0x[0-9A-Fa-f]+|\d+)(?:%s)?" % _C_INTEGER_SUFFIX_PATTERN
_OBJECT_ATTRIBUTE_FLAGS = (
    (0x2, "OBJ_INHERIT"),
    (0x10, "OBJ_PERMANENT"),
    (0x20, "OBJ_EXCLUSIVE"),
    (0x40, "OBJ_CASE_INSENSITIVE"),
    (0x80, "OBJ_OPENIF"),
    (0x100, "OBJ_OPENLINK"),
    (0x200, "OBJ_KERNEL_HANDLE"),
    (0x400, "OBJ_FORCE_ACCESS_CHECK"),
    (0x800, "OBJ_IGNORE_IMPERSONATED_DEVICEMAP"),
    (0x1000, "OBJ_DONT_REPARSE"),
)
_ZW_OBJECT_ATTRIBUTE_ARGUMENTS = {
    "ZwCreateEvent": 2,
    "ZwCreateFile": 2,
    "ZwOpenFile": 2,
    "ZwOpenKey": 2,
    "ZwCreateKey": 2,
}


def normalize_zw_api_probe_body(text: str) -> str:
    result = re.sub(
        r"\b(?P<status>[A-Za-z_][A-Za-z0-9_]*Status)\s*>=\s*0\b",
        r"NT_SUCCESS(\g<status>)",
        text,
    )
    for object_name in sorted(_zw_probe_object_attribute_variables(result)):
        escaped = re.escape(object_name)
        result = re.sub(
            r"\b%s\.Length\s*=\s*(?P<value>%s)\s*;"
            % (escaped, _C_UNSIGNED_INTEGER_LITERAL_PATTERN),
            lambda match: _rewrite_object_attributes_length_assignment(object_name, match.group("value")),
            result,
        )
        result = re.sub(
            r"\b%s\.Attributes\s*=\s*(?P<value>%s)\s*;"
            % (escaped, _C_UNSIGNED_INTEGER_LITERAL_PATTERN),
            lambda match: _rewrite_object_attributes_flags_assignment(object_name, match.group("value")),
            result,
        )
    result = re.sub(
        r"\bZwOpenProcessTokenEx\s*\(\s*\(HANDLE\)0xFFFFFFFFFFFFFFFF(?:%s)?\s*,"
        % _C_INTEGER_SUFFIX_PATTERN,
        "ZwOpenProcessTokenEx(NtCurrentProcess(),",
        result,
    )
    result = re.sub(
        r"\bZwOpenThreadTokenEx\s*\(\s*\(HANDLE\)0xFFFFFFFFFFFFFFFE(?:%s)?\s*,"
        % _C_INTEGER_SUFFIX_PATTERN,
        "ZwOpenThreadTokenEx(NtCurrentThread(),",
        result,
    )
    return result


def _zw_probe_object_attribute_variables(text: str) -> set[str]:
    variables: set[str] = set()
    for routine, index in _ZW_OBJECT_ATTRIBUTE_ARGUMENTS.items():
        for arguments in extract_call_arguments(text, routine):
            name = _identifier_argument(_argument_at(arguments, index))
            if name:
                variables.add(name)
    return variables


def _argument_at(arguments: list[str], index: int) -> str:
    if index < 0 or index >= len(arguments):
        return ""
    return arguments[index]


def _identifier_argument(argument: str) -> str:
    match = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", _strip_casts_and_reference(argument))
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


def _rewrite_object_attributes_length_assignment(object_name: str, value_text: str) -> str:
    value = _parse_c_integer_literal(value_text)
    if value == 48:
        return "%s.Length = sizeof(OBJECT_ATTRIBUTES);" % object_name
    return "%s.Length = %s;" % (object_name, value_text)


def _rewrite_object_attributes_flags_assignment(object_name: str, value_text: str) -> str:
    value = _parse_c_integer_literal(value_text)
    if value is None:
        return "%s.Attributes = %s;" % (object_name, value_text)
    return "%s.Attributes = %s;" % (object_name, _format_object_attribute_flags(value))


def _format_object_attribute_flags(value: int) -> str:
    if value == 0:
        return "0"
    names: list[str] = []
    remaining = value
    for flag, name in _OBJECT_ATTRIBUTE_FLAGS:
        if remaining & flag:
            names.append(name)
            remaining &= ~flag
    if remaining:
        names.append("0x%X" % remaining)
    return " | ".join(names)


def _parse_c_integer_literal(value_text: str) -> int | None:
    value = re.sub(r"%s$" % _C_INTEGER_SUFFIX_PATTERN, "", value_text.strip()).strip()
    try:
        return int(value, 0)
    except ValueError:
        return None

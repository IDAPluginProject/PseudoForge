from __future__ import annotations

import re


def driver_entry_signature_override() -> list[str]:
    return [
        "NTSTATUS __fastcall DriverEntry(",
        "        PDRIVER_OBJECT driverObject,",
        "        PUNICODE_STRING registryPath)",
    ]


def normalize_driver_entry_body(text: str) -> str:
    result = re.sub(
        r"(?m)^(\s*)(?:int|unsigned int|ULONG)\s+status(\s*;[^\n]*)$",
        r"\1NTSTATUS status\2",
        text,
        count=1,
    )
    result = re.sub(r"\bstatus\s*>=\s*0\b", "NT_SUCCESS(status)", result)
    result = re.sub(r"\bstatus\s*<\s*0\b", "!NT_SUCCESS(status)", result)
    result = re.sub(r"\breturn\s+\(\s*unsigned\s+int\s*\)\s*status\s*;", "return status;", result)
    result = _rewrite_driver_entry_major_function_constants(result)
    result = _rewrite_driver_entry_device_flags(result)
    result = _rewrite_driver_entry_io_create_device(result)
    return result


def _rewrite_driver_entry_major_function_constants(text: str) -> str:
    result = re.sub(
        r"(?P<prefix>\bmajorIndex\s*<=\s*)(?:0x1B|27)(?:u|U)?\b",
        r"\g<prefix>IRP_MJ_MAXIMUM_FUNCTION",
        text,
    )
    major_codes = {
        "0": "IRP_MJ_CREATE",
        "2": "IRP_MJ_CLOSE",
        "14": "IRP_MJ_DEVICE_CONTROL",
    }

    def replace_index(match: re.Match[str]) -> str:
        value = match.group("value")
        name = major_codes.get(value)
        if not name:
            return match.group(0)
        return "%s%s%s" % (match.group("prefix"), name, match.group("suffix"))

    return re.sub(
        r"(?P<prefix>\bMajorFunction\s*\[\s*)(?P<value>0|2|14)(?P<suffix>\s*\])",
        replace_index,
        result,
    )


def _rewrite_driver_entry_device_flags(text: str) -> str:
    result = re.sub(
        r"(?P<prefix>\b[A-Za-z_][A-Za-z0-9_]*->Flags\s*\|=\s*)4(?:u|U)?\b",
        r"\g<prefix>DO_BUFFERED_IO",
        text,
    )
    result = re.sub(
        r"(?P<prefix>\b[A-Za-z_][A-Za-z0-9_]*->Flags\s*&=\s*)~0x80(?:u|U)?\b",
        r"\g<prefix>~DO_DEVICE_INITIALIZING",
        result,
    )
    return result


def _rewrite_driver_entry_io_create_device(text: str) -> str:
    return re.sub(
        r"(?P<prefix>\bIoCreateDevice\s*\([^;]*?,\s*)0x100(?:u|U)?(?P<suffix>\s*,\s*FALSE\s*,)",
        r"\g<prefix>FILE_DEVICE_SECURE_OPEN\g<suffix>",
        text,
        count=1,
        flags=re.DOTALL,
    )

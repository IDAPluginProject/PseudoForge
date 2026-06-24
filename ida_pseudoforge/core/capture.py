from __future__ import annotations

import ctypes
import re
import sys
from pathlib import Path

from ida_pseudoforge.core.normalize import (
    extract_calls,
    extract_function_name,
    extract_function_signature,
    strip_ida_tags,
)
from ida_pseudoforge.core.plan_schema import FunctionCapture, LocalVariable


DECL_RE = re.compile(
    r"^\s*(?P<type>(?:const\s+)?[A-Za-z_][A-Za-z0-9_:\s\*\&<>]*?)\s+"
    r"(?P<ptr>[\*\&][\*\&\s]*)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=|,|\[)"
)


def capture_from_pseudocode(
    pseudocode: str,
    name: str = "",
    ea: int = 0,
    source_path: str = "",
    profile_context: dict[str, object] | None = None,
) -> FunctionCapture:
    clean_text = strip_ida_tags(pseudocode)
    signature = extract_function_signature(clean_text)
    function_name = name or extract_function_name(signature)
    lvars = _extract_declared_lvars(clean_text)
    calls = extract_calls(clean_text)
    return FunctionCapture(
        ea=ea,
        name=function_name,
        prototype=signature,
        pseudocode=clean_text,
        lvars=lvars,
        calls=calls,
        source_path=source_path,
        profile_context=_profile_context(source_path, profile_context),
    )


def _profile_context(source_path: str, profile_context: dict[str, object] | None) -> dict[str, object]:
    result = profile_context_from_source_path(source_path)
    result.update(dict(profile_context or {}))
    return result


def profile_context_from_source_path(source_path: str) -> dict[str, object]:
    path_text = str(source_path or "").strip()
    if not path_text:
        return {}
    path = Path(path_text)
    context: dict[str, object] = {}
    image = _image_name_from_source_path(path)
    if image:
        context["image"] = image
    build = _build_number_from_source_path(path)
    if build:
        context["build"] = build
    arch = _arch_from_source_path(path)
    if arch:
        context["arch"] = arch
    return context


def _image_name_from_source_path(path: Path) -> str:
    name = path.name
    lowered = name.lower()
    for suffix in (".i64", ".idb"):
        if lowered.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _build_number_from_source_path(path: Path) -> str:
    for part in reversed(path.parts[:-1]):
        match = re.fullmatch(r"\d{4,6}(?:\.\d{1,6})+", str(part))
        if match:
            return match.group(0)
    return _build_number_from_file_version(path)


def _build_number_from_file_version(path: Path) -> str:
    if sys.platform != "win32":
        return ""
    if not path.is_file():
        return ""
    try:
        version = ctypes.windll.version
        size = version.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            return ""
        buffer = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(path), 0, size, buffer):
            return ""
        value = ctypes.c_void_p()
        value_len = ctypes.c_uint()
        if not version.VerQueryValueW(buffer, "\\", ctypes.byref(value), ctypes.byref(value_len)):
            return ""
        if not value.value or value_len.value < 13:
            return ""
        fixed_info = _VSFixedFileInfo.from_address(value.value)
        build = (fixed_info.dwFileVersionLS >> 16) & 0xFFFF
        revision = fixed_info.dwFileVersionLS & 0xFFFF
        if not build:
            return ""
        return "%d.%d" % (build, revision)
    except Exception:
        return ""


class _VSFixedFileInfo(ctypes.Structure):
    _fields_ = [
        ("dwSignature", ctypes.c_uint32),
        ("dwStrucVersion", ctypes.c_uint32),
        ("dwFileVersionMS", ctypes.c_uint32),
        ("dwFileVersionLS", ctypes.c_uint32),
        ("dwProductVersionMS", ctypes.c_uint32),
        ("dwProductVersionLS", ctypes.c_uint32),
        ("dwFileFlagsMask", ctypes.c_uint32),
        ("dwFileFlags", ctypes.c_uint32),
        ("dwFileOS", ctypes.c_uint32),
        ("dwFileType", ctypes.c_uint32),
        ("dwFileSubtype", ctypes.c_uint32),
        ("dwFileDateMS", ctypes.c_uint32),
        ("dwFileDateLS", ctypes.c_uint32),
    ]


def _arch_from_source_path(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".i64":
        return "x64"
    if suffix == ".idb":
        return "x86"
    return ""


def _extract_declared_lvars(pseudocode: str) -> list[LocalVariable]:
    lvars = []
    seen = set()
    in_body = False
    for line in (pseudocode or "").splitlines():
        stripped = line.strip()
        if stripped == "{":
            in_body = True
            continue
        if not in_body:
            continue
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.startswith(("if ", "if(", "return", "switch", "for ", "while", "do ")):
            continue
        match = DECL_RE.match(line)
        if not match:
            if lvars and not stripped.startswith(("__", "_", "P", "K", "U", "H", "int", "char", "void", "struct")):
                break
            continue
        var_name = match.group("name")
        if var_name in seen:
            continue
        seen.add(var_name)
        var_type = match.group("type").strip()
        ptr = (match.group("ptr") or "").strip()
        if ptr:
            var_type = f"{var_type} {ptr}"
        lvars.append(LocalVariable(name=var_name, type=var_type))
    return lvars

from __future__ import annotations

import re
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
    return ""


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

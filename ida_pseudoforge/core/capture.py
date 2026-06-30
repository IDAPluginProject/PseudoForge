from __future__ import annotations

import ctypes
import re
import sys
from pathlib import Path

from ida_pseudoforge.core.ir_evidence import text_only_ir_evidence, textual_flow_ir_evidence
from ida_pseudoforge.core.normalize import (
    extract_calls,
    extract_function_name,
    extract_function_signature,
    strip_ida_tags,
)
from ida_pseudoforge.core.plan_schema import FunctionCapture, LocalVariable, TargetContext
from ida_pseudoforge.core.targeting import (
    apply_runtime_clue_defaults,
    attach_domain_pack_activation,
    import_families,
    infer_target_family,
    runtime_clues,
    section_clues,
)


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
    resolved_profile_context = _profile_context(source_path, profile_context)
    ir_evidence = text_only_ir_evidence()
    if _truthy(resolved_profile_context.get("enable_textual_ir_evidence")):
        ir_evidence = textual_flow_ir_evidence(clean_text, lvars, calls)
    return FunctionCapture(
        ea=ea,
        name=function_name,
        prototype=signature,
        pseudocode=clean_text,
        lvars=lvars,
        calls=calls,
        source_path=source_path,
        profile_context=resolved_profile_context,
        target_context=build_target_context(
            source_path,
            resolved_profile_context,
            call_names=calls,
            function_name=function_name,
        ),
        ir_evidence=ir_evidence,
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


def build_target_context(
    source_path: str = "",
    profile_context: dict[str, object] | None = None,
    profile_root: str = "",
    active_domain_packs: list[str] | tuple[str, ...] | None = None,
    call_names: list[str] | tuple[str, ...] | None = None,
    function_name: str = "",
    domain_pack_manifests: list[dict[str, object]] | None = None,
) -> TargetContext:
    context = dict(profile_context or {})
    source_text = str(source_path or context.get("source_path", "") or "").strip()
    image_name = str(context.get("image", "") or "")
    if not image_name and source_text:
        image_name = _image_name_from_source_path(Path(source_text))
    architecture = _normalize_arch(context.get("architecture") or context.get("arch"))
    format_name, format_evidence = _target_format(source_text, image_name, context)
    platform, platform_evidence = _target_platform(source_text, image_name, context)
    bitness = _target_bitness(context.get("bitness"), architecture)
    endianness = _normalize_unknown(context.get("endianness"))
    privilege_domain, privilege_evidence = _target_privilege_domain(source_text, image_name, context)
    compiler_family = _normalize_unknown(context.get("compiler_family"))
    abi = _normalize_unknown(context.get("abi"))
    language_runtime = _normalize_unknown(context.get("language_runtime"))
    symbol_state = _normalize_unknown(context.get("symbol_state"))
    evidence = {}
    if format_evidence:
        evidence["format"] = format_evidence
    if platform_evidence:
        evidence["platform"] = platform_evidence
    if architecture != "unknown":
        evidence["architecture"] = "profile_context.arch"
    if bitness:
        evidence["bitness"] = "architecture"
    if image_name:
        evidence["image_name"] = "profile_context.image"
    if privilege_evidence:
        evidence["privilege_domain"] = privilege_evidence
    imports = _string_list(context.get("imports"))
    exports = _string_list(context.get("exports"))
    sections = _string_list(context.get("sections"))
    calls = _string_list(call_names or context.get("calls"))
    runtime_evidence = runtime_clues(
        compiler_family,
        abi,
        language_runtime,
        imports,
        calls=calls,
        function_name=function_name or str(context.get("function_name", "") or ""),
    )
    manifests = _domain_pack_manifests(domain_pack_manifests)
    active_pack_ids = sorted(_string_list(active_domain_packs or context.get("active_domain_packs")))
    if not active_pack_ids:
        active_pack_ids = sorted(
            str(item.get("id", "") or "")
            for item in manifests
            if str(item.get("id", "") or "")
        )
    target_context = TargetContext(
        source_path=source_text,
        image_name=image_name,
        format=format_name,
        architecture=architecture,
        bitness=bitness,
        endianness=endianness,
        platform=platform,
        privilege_domain=privilege_domain,
        compiler_family=compiler_family,
        abi=abi,
        language_runtime=language_runtime,
        symbol_state=symbol_state,
        imports=imports,
        exports=exports,
        sections=sections,
        import_families=import_families(imports, calls),
        section_clues=section_clues(sections),
        runtime_clues=runtime_evidence,
        profile_root=str(profile_root or context.get("profile_root", "") or ""),
        active_domain_packs=active_pack_ids,
        evidence=evidence,
    )
    apply_runtime_clue_defaults(target_context)
    target_context.target_family, target_context.confidence, family_evidence = infer_target_family(target_context)
    target_context.evidence.update(family_evidence)
    if manifests:
        attach_domain_pack_activation(target_context, manifests)
    return target_context


def _domain_pack_manifests(
    explicit: list[dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    if explicit is not None:
        return [dict(item) for item in explicit if isinstance(item, dict)]
    try:
        from ida_pseudoforge.profiles.loader import active_domain_pack_manifests

        return [dict(item) for item in active_domain_pack_manifests()]
    except Exception:
        return []


def _target_format(
    source_path: str,
    image_name: str,
    context: dict[str, object],
) -> tuple[str, str]:
    explicit = _normalize_unknown(context.get("format"))
    if explicit != "unknown":
        return explicit, "profile_context.format"
    suffix = Path(source_path).suffix.lower()
    if suffix in {".i64", ".idb"}:
        return "idb", "source_path_suffix"
    image_suffix = Path(image_name).suffix.lower()
    if image_suffix in {".exe", ".dll", ".sys", ".efi", ".ocx"}:
        return "pe", "image_name_suffix"
    if suffix in {".exe", ".dll", ".sys", ".efi", ".ocx"}:
        return "pe", "source_path_suffix"
    if suffix in {".elf", ".so"} or ".so." in Path(source_path).name.lower():
        return "elf", "source_path_suffix"
    if suffix in {".dylib", ".macho"}:
        return "macho", "source_path_suffix"
    return "unknown", ""


def _target_platform(
    source_path: str,
    image_name: str,
    context: dict[str, object],
) -> tuple[str, str]:
    explicit = _normalize_unknown(context.get("platform"))
    if explicit != "unknown":
        return explicit, "profile_context.platform"
    suffixes = {Path(source_path).suffix.lower(), Path(image_name).suffix.lower()}
    if suffixes.intersection({".exe", ".dll", ".sys", ".ocx"}):
        return "windows", "path_suffix"
    if ".so." in Path(source_path).name.lower() or suffixes.intersection({".elf", ".so"}):
        return "linux", "path_suffix"
    if suffixes.intersection({".dylib", ".macho"}):
        return "macos", "path_suffix"
    if suffixes.intersection({".efi"}):
        return "uefi", "path_suffix"
    return "unknown", ""


def _target_privilege_domain(
    source_path: str,
    image_name: str,
    context: dict[str, object],
) -> tuple[str, str]:
    explicit = _normalize_unknown(context.get("privilege_domain"))
    if explicit != "unknown":
        return explicit, "profile_context.privilege_domain"
    source_suffix = Path(source_path).suffix.lower()
    image_suffix = Path(image_name).suffix.lower()
    image_lower = Path(image_name).name.lower()
    if source_suffix == ".sys" or image_suffix == ".sys":
        return "kernel", "image_suffix"
    if image_lower in {
        "ci.dll",
        "fltmgr.sys",
        "hal.dll",
        "ntkrnlmp.exe",
        "ntkrnlpa.exe",
        "ntkrpamp.exe",
        "ntoskrnl.exe",
        "win32k.sys",
        "win32kbase.sys",
        "win32kfull.sys",
    }:
        return "kernel", "image_name"
    if source_suffix in {".efi"} or image_suffix in {".efi"}:
        return "firmware", "image_suffix"
    if source_suffix in {".exe", ".dll", ".ocx"} or image_suffix in {".exe", ".dll", ".ocx"}:
        return "user", "image_suffix"
    return "unknown", ""


def _normalize_arch(value: object) -> str:
    text = _normalize_unknown(value)
    aliases = {
        "amd64": "x64",
        "x86_64": "x64",
        "i386": "x86",
        "i686": "x86",
        "arm64": "aarch64",
    }
    return aliases.get(text.lower(), text)


def _target_bitness(value: object, architecture: str) -> int:
    try:
        parsed = int(value)
        if parsed in {16, 32, 64}:
            return parsed
    except (TypeError, ValueError):
        pass
    lowered = str(architecture or "").lower()
    if lowered in {"x64", "aarch64", "arm64"}:
        return 64
    if lowered in {"x86", "arm", "arm32"}:
        return 32
    return 0


def _normalize_unknown(value: object) -> str:
    text = str(value or "").strip()
    return text if text else "unknown"


def _string_list(value: object) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


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

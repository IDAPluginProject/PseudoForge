from __future__ import annotations

from typing import Any

from ida_pseudoforge.core.plan_schema import TargetContext


def infer_target_family(context: TargetContext) -> tuple[str, float, dict[str, str]]:
    evidence: dict[str, str] = {}
    if context.platform == "windows" and context.privilege_domain == "kernel":
        evidence["target_family"] = "platform+privilege_domain"
        return "windows_kernel", 0.92, evidence
    if context.platform == "windows" and context.format in {"pe", "idb"}:
        if context.privilege_domain in {"user", "unknown"}:
            evidence["target_family"] = "format+platform+privilege_domain"
            return "windows_user_pe", 0.88 if context.privilege_domain == "user" else 0.72, evidence
    if context.platform == "linux" and context.format in {"elf", "idb"}:
        evidence["target_family"] = "format+platform"
        return "linux_elf_user", 0.86, evidence
    if context.platform == "uefi" or context.privilege_domain == "firmware":
        evidence["target_family"] = "platform_or_privilege_domain"
        return "firmware_uefi", 0.82, evidence
    if context.format == "macho" or context.platform == "macos":
        evidence["target_family"] = "format_or_platform"
        return "macos_macho_user", 0.78, evidence
    if context.language_runtime == "cxx":
        evidence["target_family"] = "language_runtime"
        return "cxx_runtime", 0.62, evidence
    return "unknown", 0.0, evidence


def import_families(imports: list[str], calls: list[str] | tuple[str, ...] | None = None) -> list[str]:
    families: set[str] = set()
    for symbol in [*imports, *list(calls or [])]:
        family = _import_family(symbol)
        if family:
            families.add(family)
    return sorted(families)


def section_clues(sections: list[str]) -> list[str]:
    result: set[str] = set()
    for section in sections:
        text = str(section or "").strip().lower()
        if not text:
            continue
        if text in {".pdata", ".xdata"}:
            result.add("pe_exception_metadata")
        elif text in {".eh_frame", ".gcc_except_table"}:
            result.add("elf_exception_metadata")
        elif text in {".rdata", ".rodata"}:
            result.add("read_only_runtime_data")
        elif text in {".tls", ".tdata", ".tbss"}:
            result.add("tls")
        elif text.startswith(".debug"):
            result.add("debug_symbols")
        elif text in {".init_array", ".fini_array"}:
            result.add("elf_static_lifetime")
    return sorted(result)


def runtime_clues(
    compiler_family: str,
    abi: str,
    language_runtime: str,
    imports: list[str],
    calls: list[str] | tuple[str, ...] | None = None,
    function_name: str = "",
) -> list[str]:
    result: set[str] = set()
    for value, prefix in (
        (compiler_family, "compiler"),
        (abi, "abi"),
        (language_runtime, "runtime"),
    ):
        text = str(value or "").strip()
        if text and text != "unknown":
            result.add("%s:%s" % (prefix, text))
    symbols = [*imports, *list(calls or []), function_name]
    if any(_looks_like_msvc_cxx_symbol(symbol) for symbol in symbols):
        result.add("runtime:cxx")
        result.add("abi:msvc")
    if any(_looks_like_itanium_cxx_symbol(symbol) for symbol in symbols):
        result.add("runtime:cxx")
        result.add("abi:itanium")
    if any(str(symbol or "").startswith("__CxxFrameHandler") for symbol in symbols):
        result.add("cxx_exception:msvc")
    if any(str(symbol or "").startswith("_Unwind_") for symbol in symbols):
        result.add("cxx_exception:itanium")
    if any(str(symbol or "") in {"malloc", "free", "calloc", "realloc"} for symbol in symbols):
        result.add("allocator:libc")
    if any(str(symbol or "").startswith("pthread_") for symbol in symbols):
        result.add("threading:pthread")
    return sorted(result)


def apply_runtime_clue_defaults(context: TargetContext) -> None:
    clues = set(context.runtime_clues)
    if context.language_runtime == "unknown" and "runtime:cxx" in clues:
        context.language_runtime = "cxx"
        context.evidence["language_runtime"] = "runtime_clues"
    if context.abi == "unknown":
        if "abi:msvc" in clues:
            context.abi = "msvc"
            context.evidence["abi"] = "runtime_clues"
        elif "abi:itanium" in clues:
            context.abi = "itanium"
            context.evidence["abi"] = "runtime_clues"


def attach_domain_pack_activation(context: TargetContext, manifests: list[dict[str, Any]]) -> TargetContext:
    active_ids = set(context.active_domain_packs)
    report: list[dict[str, Any]] = []
    eligible: list[str] = []
    rejected: list[str] = []
    for manifest in manifests:
        pack_id = str(manifest.get("id", "") or "").strip()
        if not pack_id:
            continue
        if active_ids and pack_id not in active_ids:
            continue
        item = _activation_item(context, manifest)
        report.append(item)
        if item["eligible"]:
            eligible.append(pack_id)
        else:
            rejected.append(pack_id)
    context.eligible_domain_packs = sorted(eligible)
    context.rejected_domain_packs = sorted(rejected)
    context.domain_pack_activation_report = sorted(report, key=lambda item: str(item.get("id", "")))
    return context


def domain_pack_activation_report(context: TargetContext) -> list[dict[str, Any]]:
    return [dict(item) for item in context.domain_pack_activation_report]


def _activation_item(context: TargetContext, manifest: dict[str, Any]) -> dict[str, Any]:
    filters = manifest.get("target_filters", {})
    reasons: list[str] = []
    rejection_reasons: list[str] = []
    if isinstance(filters, dict) and filters:
        for field_name in sorted(filters):
            expected = _string_list(filters.get(field_name))
            actual = getattr(context, str(field_name), "")
            if _value_allowed(actual, expected):
                reasons.append("%s=%s matched %s" % (field_name, actual, _join(expected)))
            else:
                rejection_reasons.append("%s=%s not in %s" % (field_name, actual, _join(expected)))
    else:
        reasons.append("no target filters")
    if not rejection_reasons:
        reasons.extend(_abi_filter_reasons(context, manifest))
    return {
        "id": str(manifest.get("id", "") or ""),
        "domain": str(manifest.get("domain", "") or ""),
        "mode": str(manifest.get("mode", "") or ""),
        "eligible": not rejection_reasons,
        "reasons": reasons,
        "rejection_reasons": rejection_reasons,
        "target_family": context.target_family,
    }


def _abi_filter_reasons(context: TargetContext, manifest: dict[str, Any]) -> list[str]:
    abi_filters = manifest.get("abi_filters", {})
    if not isinstance(abi_filters, dict) or not abi_filters:
        return []
    abi = str(context.abi or "").strip()
    if not abi or abi == "unknown" or abi not in abi_filters:
        return []
    filters = abi_filters.get(abi, {})
    if not isinstance(filters, dict):
        return []
    reasons = []
    for field_name in sorted(filters):
        expected = _string_list(filters.get(field_name))
        actual = getattr(context, str(field_name), "")
        if _value_allowed(actual, expected):
            reasons.append("abi_filter.%s=%s matched %s" % (field_name, actual, _join(expected)))
    return reasons


def _import_family(symbol: str) -> str:
    text = str(symbol or "").strip()
    lower = text.lower()
    if not lower:
        return ""
    if lower.startswith(("nt", "rtl", "zw")):
        return "ntdll"
    if lower in {
        "createfilea",
        "createfilew",
        "closehandle",
        "virtualalloc",
        "virtualfree",
        "getlasterror",
        "setlasterror",
        "createprocessw",
        "createprocessa",
    }:
        return "kernel32"
    if lower.startswith(("reg", "openprocessToken".lower(), "crypt")):
        return "advapi32"
    if lower in {"closesocket", "wsastartup"} or lower.startswith("wsa"):
        return "ws2_32"
    if lower.startswith(("etw", "eventwrite")):
        return "etw"
    if lower.startswith(("pthread_",)):
        return "pthread"
    if lower in {"malloc", "free", "calloc", "realloc", "memcpy", "memset", "strlen", "printf"}:
        return "libc"
    if lower in {"socket", "connect", "send", "recv", "close", "epoll_wait", "epoll_ctl"}:
        return "posix_socket"
    if lower.startswith(("ue_", "aactor", "uobject", "fstring")):
        return "unreal"
    return ""


def _looks_like_msvc_cxx_symbol(symbol: str) -> bool:
    text = str(symbol or "")
    return bool(
        text.startswith("??")
        or "__RTTI" in text
        or "__CxxFrameHandler" in text
        or "operator new" in text
        or "operator delete" in text
        or "__vftable" in text
    )


def _looks_like_itanium_cxx_symbol(symbol: str) -> bool:
    text = str(symbol or "")
    return bool(text.startswith("_Z") or "_vptr" in text or text.startswith("_Unwind_"))


def _value_allowed(actual: object, expected: list[str]) -> bool:
    actual_text = str(actual or "").strip().casefold()
    expected_values = [item.casefold() for item in expected if item]
    return bool(expected_values) and actual_text in expected_values


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, tuple):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def _join(values: list[str]) -> str:
    return "[" + ", ".join(values) + "]"

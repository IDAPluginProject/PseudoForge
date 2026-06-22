from __future__ import annotations

import json
import re
from dataclasses import asdict, is_dataclass

from ida_pseudoforge.core.ioctl import decode_ioctl_code, looks_like_ioctl_dispatcher_name
from ida_pseudoforge.core.plan_schema import CleanPlan
from ida_pseudoforge.profiles.loader import profile_load_warnings


def display_warnings(plan: CleanPlan) -> list[object]:
    warnings = [
        warning
        for warning in list(plan.warnings) + profile_load_warnings()
        if not _is_routine_skipped_rename_warning(warning, plan)
        and not _is_driver_entry_routine_warning(warning, plan)
        and not _is_irp_device_control_display_warning(warning, plan)
        and not _is_callback_registration_display_warning(warning, plan)
        and not _is_registry_callback_display_warning(warning, plan)
        and not _is_zw_api_probe_display_warning(warning, plan)
        and not _is_memory_manager_probe_display_warning(warning, plan)
        and not _is_resolved_status_carrier_display_warning(warning, plan)
    ]
    return sorted(warnings, key=_warning_display_rank)


def display_warning_count(plan: CleanPlan) -> int:
    return len(display_warnings(plan))


def export_warnings(plan: CleanPlan) -> list[str]:
    result: list[str] = []
    seen = set()
    for warning in display_warnings(plan):
        text = format_warning(warning)
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def export_warning_diagnostics(plan: CleanPlan) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    seen = set()
    for item in getattr(plan, "warning_diagnostics", []) or []:
        payload = _warning_diagnostic_payload(item)
        key = json.dumps(payload, ensure_ascii=True, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        result.append(payload)
    return result


def _warning_diagnostic_payload(item: object) -> dict[str, object]:
    if is_dataclass(item):
        payload = asdict(item)
    elif isinstance(item, dict):
        payload = dict(item)
    else:
        payload = {"kind": "unknown_warning_diagnostic", "message": format_warning(item)}
    message = str(payload.get("message", "") or "").strip()
    if message:
        payload["message"] = _ascii_comment_text(message)
    return payload


def format_warning(warning: object) -> str:
    if isinstance(warning, dict):
        message = str(warning.get("message", "")).strip()
        if message:
            return _ascii_comment_text(message)
        old = str(warning.get("old", "")).strip()
        reason = str(warning.get("reason", "")).strip()
        if old and reason:
            return _ascii_comment_text("Potential bad call target %s: %s" % (old, reason))
        try:
            return _ascii_comment_text(json.dumps(warning, ensure_ascii=True, sort_keys=True))
        except TypeError:
            return _ascii_comment_text(str(warning))
    if isinstance(warning, str):
        parsed_warning = _parse_warning_json(warning)
        if parsed_warning is not None:
            return format_warning(parsed_warning)
    return _ascii_comment_text(str(warning))


def _warning_display_rank(warning: object) -> tuple[int, str]:
    text = format_warning(warning).lower()
    if "potential bad call target" in text:
        rank = 0
    elif "corrupt" in text or "failfast" in text:
        rank = 1
    elif "unsupported dispatcher rename" in text or "reused dispatcher rename" in text:
        rank = 2
    elif "weak dispatcher rename" in text or "value-invariant rename" in text or "pascalcase llm rename" in text:
        rank = 3
    elif "low confidence" in text or "skipped llm rename" in text:
        rank = 5
    else:
        rank = 4
    return (rank, text)


def _is_driver_entry_routine_warning(warning: object, plan: CleanPlan) -> bool:
    if not _has_comment_kind(plan, "driver_entry"):
        return False
    text = format_warning(warning)
    if re.match(r"^Skipped (?:PascalCase LLM|colliding|LLM) rename sub_[0-9A-Fa-f]+->", text):
        return True
    if "low confidence" in text and re.match(r"^Skipped LLM rename sub_[0-9A-Fa-f]+->", text):
        return True
    lowered = text.lower()
    return (
        "deferredcontext is ida-misnamed" in lowered
        or "field offsets into deviceextension" in lowered
        or "sub-function renames" in lowered
        or "inferred from call context only" in lowered
    )


def _is_callback_registration_display_warning(warning: object, plan: CleanPlan) -> bool:
    if not _has_comment_kind(plan, "callback_registration"):
        return False
    text = format_warning(warning)
    lowered = text.lower()
    if re.match(r"^Skipped (?:PascalCase LLM|LLM) rename sub_[0-9A-Fa-f]+->", text):
        return True
    return (
        "notifyroutine in pseudocode does not match locals list" in lowered
        or ("typed _qword[4]" in lowered and "ob_operation_registration" in lowered)
        or ("field assignments" in lowered and "ob_operation_registration" in lowered)
    )


def _is_registry_callback_display_warning(warning: object, plan: CleanPlan) -> bool:
    if not _has_comment_kind(plan, "registry_callback_registration"):
        return False
    text = format_warning(warning)
    lowered = text.lower()
    if re.match(r"^Skipped (?:PascalCase LLM|LLM) rename DestinationString->", text):
        return True
    if re.match(r"^Skipped noop rename Cookie\b", text):
        return True
    return (
        "function symbol used as callback routine is not in locals" in lowered
        or "debug/print helper on major/minor version" in lowered
        or ("v1 and v2 share the same stack slot" in lowered and "distinct logical roles" in lowered)
    )


def _is_zw_api_probe_display_warning(warning: object, plan: CleanPlan) -> bool:
    if not _has_comment_kind(plan, "zw_api_probe"):
        return False
    lowered = format_warning(warning).lower()
    return (
        "function exercises many zw" in lowered
        or "api-probing/corpus routine" in lowered
        or ("infobuffer is reused" in lowered and "heterogeneous query" in lowered)
    )


def _is_memory_manager_probe_display_warning(warning: object, plan: CleanPlan) -> bool:
    if not _has_comment_kind(plan, "memory_manager_probe"):
        return False
    text = format_warning(warning)
    lowered = text.lower()
    if re.match(r"^Skipped (?:PascalCase LLM|LLM) rename sub_[0-9A-Fa-f]+->", text):
        return True
    if re.match(r"^Skipped LLM rename v\d+->", text) and "low confidence" in lowered:
        return True
    if _is_probe_purpose_advisory(text):
        return True
    return _is_decompiler_temp_only_advisory(text) or _is_handled_rename_advisory(text, plan)


def _is_irp_device_control_display_warning(warning: object, plan: CleanPlan) -> bool:
    if not _plan_has_ioctl_dispatcher(plan):
        return False
    has_irp_dispatch_signature = _has_irp_dispatch_prototype_renames(plan)
    text = format_warning(warning)
    lowered = text.lower()
    if "deviceobject is inferred from dispatch signature" in lowered and has_irp_dispatch_signature:
        return True
    if not has_irp_dispatch_signature or not _has_device_control_stack_renames(plan):
        return False
    if "ioctl handler subfunctions" in lowered and "recommend naming" in lowered:
        return True
    if (
        "masterirp->systembuffer assumes buffered ioctl" in lowered
        or ("masterirp" in lowered and "systembuffer" in lowered and "method_buffered" in lowered)
    ):
        return _plan_recovered_ioctl_cases_are_all_method_buffered(plan)
    if (
        "input-vs-output length assignment is uncertain" in lowered
        or "field offsets do not match the standard io_stack_location layout" in lowered
    ):
        return True
    if re.match(r"^Skipped LLM rename v\d+->", text) and "low confidence" in lowered:
        return True
    return False


def _is_resolved_status_carrier_display_warning(warning: object, plan: CleanPlan) -> bool:
    text = format_warning(warning)
    conflict_match = re.match(
        r"^Downgraded status/object semantic conflict rename "
        r"(?P<old>[A-Za-z_][A-Za-z0-9_]*)->[A-Za-z_][A-Za-z0-9_]* "
        r"to (?P=old)->(?P<new>[A-Za-z_][A-Za-z0-9_]*):",
        text,
    )
    if conflict_match:
        return _has_applied_rename(plan, conflict_match.group("old"), conflict_match.group("new"))

    carrier_match = re.match(
        r"^Downgraded object-style status carrier name "
        r"(?P<old>[A-Za-z_][A-Za-z0-9_]*)->(?P<new>[A-Za-z_][A-Za-z0-9_]*):",
        text,
    )
    if carrier_match:
        return _has_applied_rename(plan, carrier_match.group("old"), carrier_match.group("new"))

    return False


def _plan_has_ioctl_dispatcher(plan: CleanPlan) -> bool:
    return any(looks_like_ioctl_dispatcher_name(flow.dispatcher) for flow in plan.flow_rewrites)


def _has_irp_dispatch_prototype_renames(plan: CleanPlan) -> bool:
    return _has_applied_rename(plan, "a1", "deviceObject", source="prototype") and _has_applied_rename(
        plan,
        "a2",
        "irp",
        source="prototype",
    )


def _has_device_control_stack_renames(plan: CleanPlan) -> bool:
    has_stack = any(
        rename.apply and rename.source == "kernel-irp-stack" and rename.new == "ioStackLocation"
        for rename in plan.renames
    )
    has_ioctl = any(
        rename.apply and rename.source == "kernel-irp-stack" and rename.new == "ioControlCode"
        for rename in plan.renames
    )
    return has_stack and has_ioctl


def _plan_recovered_ioctl_cases_are_all_method_buffered(plan: CleanPlan) -> bool:
    found = False
    for flow in plan.flow_rewrites:
        if not looks_like_ioctl_dispatcher_name(flow.dispatcher):
            continue
        for value in flow.recovered_cases:
            decoded = decode_ioctl_code(value)
            if decoded is None or decoded.method != 0:
                return False
            found = True
    return found


def _has_applied_rename(plan: CleanPlan, old: str, new: str, source: str | None = None) -> bool:
    for rename in plan.renames:
        if not rename.apply or rename.old != old or rename.new != new:
            continue
        if source is not None and rename.source != source:
            continue
        return True
    return False


def _is_handled_rename_advisory(text: str, plan: CleanPlan) -> bool:
    if _looks_actionable_warning_text(text):
        return False
    handled_by_old = {
        rename.old: rename
        for rename in plan.renames
        if rename.apply and rename.source != "llm" and rename.old
    }
    mentioned = [handled_by_old[name] for name in _code_identifiers_in_text(text) if name in handled_by_old]
    if not mentioned:
        return False
    if len(mentioned) >= 2:
        return True
    return _is_decompiler_global_name(mentioned[0].old)


def _is_probe_purpose_advisory(text: str) -> bool:
    if _looks_actionable_warning_text(text):
        return False
    lowered = (text or "").lower()
    has_probe_context = any(term in lowered for term in ("self-test", "probe", "diagnostic", "corpus"))
    has_observational_language = any(term in lowered for term in ("debug", "exercis", "scratch", "result sink"))
    return has_probe_context and has_observational_language


def _is_decompiler_temp_only_advisory(text: str) -> bool:
    if _looks_actionable_warning_text(text):
        return False
    identifiers = _code_identifiers_in_text(text)
    return bool(identifiers) and all(re.fullmatch(r"v\d+", name) for name in identifiers)


def _code_identifiers_in_text(text: str) -> set[str]:
    result: set[str] = set()
    for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text or ""):
        if re.fullmatch(r"v\d+|[A-Za-z]+_[0-9A-Fa-f]+", token):
            result.add(token)
        elif _looks_like_pascal_local_name(token):
            result.add(token)
    return result


def _looks_like_pascal_local_name(token: str) -> bool:
    return bool(re.fullmatch(r"[A-Z][A-Za-z0-9_]*", token or "")) and any(char.islower() for char in token)


def _is_decompiler_global_name(name: str) -> bool:
    return bool(re.fullmatch(r"(?:byte|word|dword|qword|xmmword|ymmword|unk|off|stru|algn)_[0-9A-Fa-f]+", name or ""))


def _looks_actionable_warning_text(text: str) -> bool:
    lowered = (text or "").lower()
    actionable_terms = {
        "bad call target",
        "bug",
        "corrupt",
        "crash",
        "danger",
        "double free",
        "failfast",
        "failure path",
        "invalid",
        "leak",
        "missing",
        "mismatch",
        "not freed",
        "not initialized",
        "overflow",
        "race",
        "truncat",
        "unchecked",
        "uninitialized",
        "unsafe",
        "use-after",
        "wrong",
    }
    return any(term in lowered for term in actionable_terms)


def _is_routine_skipped_rename_warning(warning: object, plan: CleanPlan) -> bool:
    if not _plan_looks_like_large_dispatcher(plan):
        return False
    text = format_warning(warning).lower()
    return text.startswith("skipped ") and " rename " in text


def _plan_looks_like_large_dispatcher(plan: CleanPlan) -> bool:
    return any(len(flow.recovered_cases) >= 16 for flow in plan.flow_rewrites)


def _has_comment_kind(plan: CleanPlan, kind: str) -> bool:
    return any(str(comment.get("kind", "")) == kind for comment in plan.comments)


def _ascii_comment_text(text: str) -> str:
    return text.encode("ascii", "backslashreplace").decode("ascii")


def _parse_warning_json(warning: str) -> object | None:
    stripped = warning.strip()
    if not stripped.startswith("{") or not stripped.endswith("}"):
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None

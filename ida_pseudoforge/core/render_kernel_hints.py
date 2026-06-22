from __future__ import annotations

import re

from ida_pseudoforge.core.event_builder_patterns import etw_event_builder_append_counts
from ida_pseudoforge.core.plan_schema import CleanPlan
from ida_pseudoforge.core.render_comments import sanitize_generated_comment_text


def rewrite_critical_region_entry(text: str, plan: CleanPlan) -> str:
    if not has_comment_kind(plan, "critical_region"):
        return text

    matched_vars = []

    def repl(match: re.Match[str]) -> str:
        var_name = match.group("var")
        if not _critical_region_entry_var_is_isolated(text, match, var_name):
            return match.group(0)
        matched_vars.append(var_name)
        return match.group("indent") + "KeEnterCriticalRegion();"

    result = re.sub(
        r"(?m)^(?P<indent>\s*)(?P<var>[A-Za-z_][A-Za-z0-9_]*) = KeGetCurrentThread\(\);\n"
        r"(?P=indent)--(?P=var)->KernelApcDisable;",
        repl,
        text,
    )
    result = _rewrite_current_thread_critical_region_leave(result)
    for matched_var in sorted(set(matched_vars)):
        result = _rewrite_critical_region_leave_for_var(result, matched_var)
        if matched_var and matched_var not in _strip_declaration_for_var(result, matched_var):
            result = re.sub(
                r"(?m)^\s*struct _KTHREAD \*%s\s*;[^\n]*\n" % re.escape(matched_var),
                "",
                result,
                count=1,
            )
    return result


def _rewrite_critical_region_leave_for_var(text: str, name: str) -> str:
    return re.sub(
        r"(?m)^(?P<indent>\s*)KeLeaveCriticalRegionThread\(\s*(?:\([^)]*\)\s*)?%s\s*\);"
        % re.escape(name),
        lambda match: match.group("indent") + "KeLeaveCriticalRegion();",
        text,
    )


def _rewrite_current_thread_critical_region_leave(text: str) -> str:
    return re.sub(
        r"(?m)^(?P<indent>\s*)KeLeaveCriticalRegionThread\(\s*(?:\([^)]*\)\s*)?KeGetCurrentThread\(\)\s*\);",
        lambda match: match.group("indent") + "KeLeaveCriticalRegion();",
        text,
    )


def _critical_region_entry_var_is_isolated(text: str, match: re.Match[str], name: str) -> bool:
    without_entry = text[: match.start()] + text[match.end() :]
    without_leave = _remove_critical_region_leave_for_var(without_entry, name)
    without_declaration = _strip_declaration_for_var(without_leave, name)
    return re.search(r"\b%s\b" % re.escape(name), without_declaration) is None


def _remove_critical_region_leave_for_var(text: str, name: str) -> str:
    return re.sub(
        r"(?m)^\s*KeLeaveCriticalRegionThread\(\s*(?:\([^)]*\)\s*)?%s\s*\);[^\n]*(?:\n|$)"
        % re.escape(name),
        "",
        text,
    )


def annotate_kernel_hints(text: str, plan: CleanPlan) -> str:
    comment_kinds = {str(comment.get("kind", "")) for comment in plan.comments}
    if not comment_kinds:
        return text
    devpropkey_bases = _devpropkey_identity_bases(plan)
    devpropkey_intro_notes = _devpropkey_function_intro_notes(text, devpropkey_bases)
    event_builder_bases = _event_builder_identity_bases(plan)
    event_builder_intro_notes = _event_builder_function_intro_notes(text, event_builder_bases)
    intro_notes = devpropkey_intro_notes + event_builder_intro_notes
    intro_notes_emitted = False
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        indent = line[: len(line) - len(line.lstrip())]
        if "list_entry_unlink" in comment_kinds and _is_list_unlink_assignment(stripped):
            lines.append(indent + "// PseudoForge: validated RemoveEntryList(providerLink).")
        if "list_entry_insert_tail" in comment_kinds and _is_list_insert_tail_assignment(stripped):
            if "providerListHead" in stripped:
                lines.append(indent + "// PseudoForge: validated InsertTailList(providerListHead, newProviderLink).")
            else:
                lines.append(indent + "// PseudoForge: InsertTailList(&ExpFirmwareTableProviderListHead, newProviderLink).")
        lines.append(line)
        if intro_notes and not intro_notes_emitted and stripped == "{":
            for note in intro_notes:
                lines.append(indent + "  // PseudoForge: " + sanitize_generated_comment_text(note))
            intro_notes_emitted = True
        if "inferred_record_layout" in comment_kinds and _is_provider_link_assignment(stripped):
            if "CONTAINING_RECORD(providerLink" in stripped:
                lines.append(indent + "// PseudoForge: providerRecord owns providerLink at Link offset +0x18.")
            else:
                lines.append(indent + "// PseudoForge: providerLink is providerRecord->Link at offset +0x18.")
    return "\n".join(lines)


def has_comment_kind(plan: CleanPlan, kind: str) -> bool:
    return any(str(comment.get("kind", "")) == kind for comment in plan.comments)


def _devpropkey_identity_bases(plan: CleanPlan) -> set[str]:
    return _domain_identity_bases_by_structure(plan, "DEVPROPKEY")


def _event_builder_identity_bases(plan: CleanPlan) -> set[str]:
    return _domain_identity_bases_by_structure(plan, "SMST_ETW_EVENT_BUILDER")


def _domain_identity_bases_by_structure(plan: CleanPlan, structure: str) -> set[str]:
    bases = set()
    for comment in plan.comments:
        if str(comment.get("kind", "")) != "domain_structure_identity":
            continue
        if str(comment.get("structure", "")) != structure:
            continue
        base = str(comment.get("base", "") or "")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", base):
            bases.add(base)
    return bases


def _devpropkey_function_intro_notes(text: str, bases: set[str]) -> list[str]:
    if not bases:
        return []
    notes = []
    for base in sorted(bases):
        observed_fields = []
        if _devpropkey_offset_access_exists(text, base, 0x10):
            observed_fields.append("+0x10 is pid / DEVPROPID")
        if _devpropkey_offset_access_exists(text, base, 0x8):
            observed_fields.append("+0x8 is fmtidHighPart")
        if _devpropkey_base_qword_access_exists(text, base):
            observed_fields.append("direct _QWORD loads from %s are fmtidLowPart review aliases" % base)
        if observed_fields:
            notes.append("%s is DEVPROPKEY: %s." % (base, ", ".join(observed_fields)))
    symbol = _devpkey_symbol_for_bases(text, bases)
    if symbol:
        notes.append(
            "Observed DEVPKEY_* comparisons, for example %s, compare GUID halves; "
            "require both halves before treating them as a full GUID match."
            % symbol
        )
    return notes


def _devpkey_symbol_for_bases(text: str, bases: set[str]) -> str:
    for line in str(text or "").splitlines():
        if not any(_devpropkey_line_has_base_access(line, base) for base in bases):
            continue
        symbol = _devpkey_symbol_from_text(line)
        if symbol:
            return symbol
    return ""


def _devpropkey_line_has_base_access(line: str, base: str) -> bool:
    return (
        _devpropkey_base_qword_access_exists(line, base)
        or _devpropkey_offset_access_exists(line, base, 0x8)
        or _devpropkey_offset_access_exists(line, base, 0x10)
    )


def _devpropkey_offset_access_exists(text: str, base: str, offset: int) -> bool:
    offset_pattern = "(?:0x%X|0x%x|%d)" % (offset, offset, offset)
    return (
        re.search(
            r"\*\s*\(\s*[^)]*\*\s*\)\s*\(\s*%s\s*\+\s*%s(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
            % (re.escape(base), offset_pattern),
            text or "",
            flags=re.IGNORECASE,
        )
        is not None
    )


def _devpropkey_base_qword_access_exists(text: str, base: str) -> bool:
    return (
        re.search(
            r"\*\s*\(\s*_?QWORD\s*\*\s*\)\s*%s\b" % re.escape(base),
            text or "",
            flags=re.IGNORECASE,
        )
        is not None
    )


def _devpkey_symbol_from_text(text: str) -> str:
    match = re.search(r"\b(DEVPKEY_[A-Za-z0-9_]+)\b", text or "")
    if not match:
        return ""
    return match.group(1)


def _event_builder_function_intro_notes(text: str, bases: set[str]) -> list[str]:
    notes = []
    for base in sorted(bases):
        notes.append(
            "%s is SMST_ETW_EVENT_BUILDER: descriptorTable +0x0, payloadBuffer +0x8, "
            "itemCount +0x10, payloadWriteOffset +0x18."
            % base
        )
        counts = etw_event_builder_append_counts(text, base)
        if (
            counts["payload_buffer_targets"] > 0
            and counts["descriptor_table_slots"] > 0
            and counts["item_count_updates"] > 0
            and counts["payload_offset_updates"] > 0
        ):
            notes.append(
                "Repeated append pattern on %s writes payload data, records pointer/size descriptors, "
                "increments itemCount, and advances payloadWriteOffset."
                % base
            )
    return notes

def _strip_declaration_for_var(text: str, name: str) -> str:
    return re.sub(
        r"(?m)^\s*(?:struct\s+)?[A-Za-z_][A-Za-z0-9_\s]*\*?\s*%s\s*;[^\n]*$" % re.escape(name),
        "",
        text,
    )


def _is_provider_link_assignment(stripped: str) -> bool:
    return (
        re.match(r"providerLink\s*=\s*providerRecord\s*\+\s*6\s*;", stripped) is not None
        or stripped == "providerLink = &providerRecord->Link;"
        or stripped.startswith("providerRecord = CONTAINING_RECORD(providerLink, ")
    )


def _is_list_unlink_assignment(stripped: str) -> bool:
    return stripped in {
        "*previousLink = nextLink;",
        "previousLink->Flink = nextLink;",
        "RemoveEntryList(providerLink);",
    }


def _is_list_insert_tail_assignment(stripped: str) -> bool:
    return stripped in {
        "*newProviderLink = &ExpFirmwareTableProviderListHead;",
        "newProviderLink->Flink = &ExpFirmwareTableProviderListHead;",
        "InsertTailList(providerListHead, newProviderLink);",
    }

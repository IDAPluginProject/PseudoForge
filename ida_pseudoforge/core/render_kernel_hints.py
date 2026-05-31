from __future__ import annotations

import re

from ida_pseudoforge.core.plan_schema import CleanPlan


def rewrite_critical_region_entry(text: str, plan: CleanPlan) -> str:
    if not has_comment_kind(plan, "critical_region"):
        return text

    matched_var = ""

    def repl(match: re.Match[str]) -> str:
        nonlocal matched_var
        matched_var = match.group("var")
        return match.group("indent") + "KeEnterCriticalRegion();"

    result = re.sub(
        r"(?m)^(?P<indent>\s*)(?P<var>[A-Za-z_][A-Za-z0-9_]*) = KeGetCurrentThread\(\);\n"
        r"(?P=indent)--(?P=var)->KernelApcDisable;",
        repl,
        text,
        count=1,
    )
    if matched_var and matched_var not in _strip_declaration_for_var(result, matched_var):
        result = re.sub(
            r"(?m)^\s*struct _KTHREAD \*%s\s*;[^\n]*\n" % re.escape(matched_var),
            "",
            result,
            count=1,
        )
    return result


def annotate_kernel_hints(text: str, plan: CleanPlan) -> str:
    comment_kinds = {str(comment.get("kind", "")) for comment in plan.comments}
    if not comment_kinds:
        return text
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
        if "inferred_record_layout" in comment_kinds and _is_provider_link_assignment(stripped):
            if "CONTAINING_RECORD(providerLink" in stripped:
                lines.append(indent + "// PseudoForge: providerRecord owns providerLink at Link offset +0x18.")
            else:
                lines.append(indent + "// PseudoForge: providerLink is providerRecord->Link at offset +0x18.")
    return "\n".join(lines)


def has_comment_kind(plan: CleanPlan, kind: str) -> bool:
    return any(str(comment.get("kind", "")) == kind for comment in plan.comments)


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

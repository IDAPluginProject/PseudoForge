from __future__ import annotations

import re

from ida_pseudoforge.core.event_builder_patterns import etw_event_builder_append_counts
from ida_pseudoforge.core.plan_schema import CleanPlan
from ida_pseudoforge.core.render_comments import sanitize_generated_comment_text

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_OFFSET_ACCESS_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*"
    r"\(\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
)
_DIRECT_BASE_ACCESS_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()"
)
_STRIDED_AGGREGATE_RE = re.compile(
    r"(?:(?P<stride_a>0x[0-9A-Fa-f]+|\d+)(?:LL|i64|ULL|uLL|UL|U|L)?\s*\*\s*"
    r"(?P<index_a>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<base_a>[A-Za-z_][A-Za-z0-9_]*)(?:\s*\+\s*(?P<offset_a>0x[0-9A-Fa-f]+|\d+))?|"
    r"(?P<base_b>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<stride_b>0x[0-9A-Fa-f]+|\d+)(?:LL|i64|ULL|uLL|UL|U|L)?\s*\*\s*"
    r"(?P<index_b>[A-Za-z_][A-Za-z0-9_]*)(?:\s*\+\s*(?P<offset_b>0x[0-9A-Fa-f]+|\d+))?)"
)
_LOCAL_DECLARATION_RE = re.compile(
    r"^\s*(?:const\s+)?[A-Za-z_][A-Za-z0-9_:\s\*\&<>]*\s+"
    r"[\*\&\s]*[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?\s*;"
)
_REVIEW_ONLY_ALIAS_FIELD_KINDS = {
    "domain_structure_identity",
    "inferred_offset_field_aliases",
    "inferred_offset_field_hot_cluster",
    "inferred_offset_rewrite_preview",
    "inferred_offset_rewrite_partial_opportunity",
}


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
    review_only_field_aliases = _review_only_field_aliases_by_base(plan)
    synthetic_aggregate_aliases = _synthetic_aggregate_aliases(plan)
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
        if review_only_field_aliases:
            lines[-1] = _annotate_review_only_field_alias_line(lines[-1], review_only_field_aliases)
        if synthetic_aggregate_aliases:
            lines[-1] = _annotate_synthetic_aggregate_alias_line(lines[-1], synthetic_aggregate_aliases)
    return "\n".join(lines)


def strip_review_only_aliases_from_canonical_rewrite_lines(text: str) -> str:
    lines = []
    for line in str(text or "").splitlines(keepends=True):
        marker = "// PseudoForge review-only:"
        line_body = line.rstrip("\r\n")
        line_ending = line[len(line_body) :]
        if marker not in line_body:
            lines.append(line)
            continue
        prefix, _marker, _suffix = line_body.partition(marker)
        if _line_has_canonical_layout_rewrite(prefix):
            lines.append(prefix.rstrip() + line_ending)
        else:
            lines.append(line)
    return "".join(lines)


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


def _review_only_field_aliases_by_base(plan: CleanPlan) -> dict[str, dict[int, dict[str, str]]]:
    blocked_bases = _review_only_rewrite_blocked_bases(plan)
    domain_context = _domain_identity_context_by_base(plan)
    aliases: dict[str, dict[int, dict[str, str]]] = {}
    for comment in plan.comments:
        kind = str(comment.get("kind", "") or "")
        if kind not in _REVIEW_ONLY_ALIAS_FIELD_KINDS:
            continue
        base = str(comment.get("base", "") or "")
        if not _IDENTIFIER_RE.fullmatch(base):
            continue
        context = domain_context.get(base, {})
        if not _review_only_alias_comment_is_body_visible(kind, comment, base, blocked_bases, context):
            continue
        for field in comment.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            offset = _field_offset(field.get("offset"))
            if offset is None:
                continue
            name = _field_name(field, offset)
            if not name:
                continue
            field_type = _field_type(field)
            existing = aliases.setdefault(base, {}).get(offset)
            candidate = {
                "base": base,
                "display_base": _review_only_display_base(base, context),
                "name": name,
                "type": field_type,
                "offset": str(offset),
                "structure": str(context.get("structure", "") or ""),
                "mode": str(context.get("mode", "") or ""),
                "source": _review_only_alias_source_text(comment, context),
                "kind": kind,
            }
            if existing is None or _review_only_alias_rank(candidate) > _review_only_alias_rank(existing):
                aliases[base][offset] = candidate
    return aliases


def _review_only_rewrite_blocked_bases(plan: CleanPlan) -> set[str]:
    bases = set()
    for comment in plan.comments:
        if str(comment.get("kind", "") or "") != "inferred_offset_rewrite_blockers":
            continue
        base = str(comment.get("base", "") or "")
        if _IDENTIFIER_RE.fullmatch(base):
            bases.add(base)
    return bases


def _domain_identity_context_by_base(plan: CleanPlan) -> dict[str, dict[str, str]]:
    context: dict[str, dict[str, str]] = {}
    for comment in plan.comments:
        if str(comment.get("kind", "") or "") != "domain_structure_identity":
            continue
        base = str(comment.get("base", "") or "")
        if not _IDENTIFIER_RE.fullmatch(base):
            continue
        mode = str(comment.get("effective_mode", "") or comment.get("mode", "") or "")
        role = str(comment.get("role", "") or comment.get("trusted_role", "") or "")
        structure = str(comment.get("structure", "") or comment.get("structure_name", "") or "")
        blockers = [
            str(item)
            for item in comment.get("blockers", []) or []
            if str(item)
        ]
        forced = [
            str(item)
            for item in comment.get("forced_report_only_reasons", []) or []
            if str(item)
        ]
        context[base] = {
            "mode": mode,
            "role": role,
            "structure": structure,
            "blocked": "1" if _domain_identity_is_review_only(mode, blockers, forced) else "",
        }
    return context


def _domain_identity_is_review_only(mode: str, blockers: list[str], forced: list[str]) -> bool:
    normalized_mode = str(mode or "").lower()
    if normalized_mode in {"report-only", "preview", "preview-only"}:
        return True
    if forced:
        return True
    return any(
        item in {"profile_report_only", "report_only_profile", "build_mismatch", "ambiguous_profile_match"}
        for item in blockers
    )


def _review_only_alias_comment_is_body_visible(
    kind: str,
    comment: dict[str, object],
    base: str,
    blocked_bases: set[str],
    context: dict[str, str],
) -> bool:
    if base in blocked_bases:
        return True
    if str(context.get("blocked", "") or ""):
        return True
    if kind == "inferred_offset_field_hot_cluster":
        return True
    if kind == "domain_structure_identity":
        return _domain_identity_is_review_only(
            str(comment.get("effective_mode", "") or comment.get("mode", "") or ""),
            [
                str(item)
                for item in comment.get("blockers", []) or []
                if str(item)
            ],
            [
                str(item)
                for item in comment.get("forced_report_only_reasons", []) or []
                if str(item)
            ],
        )
    return False


def _field_offset(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 16 if text.lower().startswith("0x") else 10)
        except ValueError:
            return None
    return None


def _field_name(field: dict[str, object], offset: int) -> str:
    name = str(field.get("name", "") or "")
    if _IDENTIFIER_RE.fullmatch(name):
        return name
    return "field_%X" % offset


def _field_type(field: dict[str, object]) -> str:
    value = str(field.get("type", "") or "").strip()
    if not value:
        return "unknown"
    return re.sub(r"\s+", " ", value)


def _review_only_display_base(base: str, context: dict[str, str]) -> str:
    role = str(context.get("role", "") or "")
    if _IDENTIFIER_RE.fullmatch(role):
        return role
    return base


def _review_only_alias_source_text(comment: dict[str, object], context: dict[str, str]) -> str:
    source = str(comment.get("source_identity_source", "") or comment.get("source", "") or "")
    source_provenance = str(comment.get("source_identity_source_provenance", "") or comment.get("source_provenance", "") or "")
    if source and source_provenance:
        return "%s from %s" % (source_provenance, source)
    if source:
        return source
    return ""


def _synthetic_aggregate_aliases(plan: CleanPlan) -> dict[str, object]:
    by_local: dict[str, dict[str, str]] = {}
    by_indexed_local: dict[tuple[str, int], dict[str, str]] = {}
    strided: dict[tuple[str, int, int], dict[str, str]] = {}
    for comment in plan.comments:
        if str(comment.get("kind", "") or "") != "synthetic_local_aggregate":
            continue
        display_name = str(comment.get("display_name", "") or "")
        if not _IDENTIFIER_RE.fullmatch(display_name):
            continue
        aggregate_kind = str(comment.get("aggregate_kind", "") or "")
        stride = _field_offset(comment.get("stride")) or 0
        base = str(comment.get("base", "") or "")
        for field in comment.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            offset = _field_offset(field.get("offset"))
            if offset is None:
                continue
            alias = {
                "display_name": display_name,
                "aggregate_kind": aggregate_kind,
                "base": base,
                "stride": str(stride),
                "name": _field_name(field, offset),
                "type": _field_type(field),
                "offset": str(offset),
                "source": str(field.get("source", "") or ""),
                "source_local": str(field.get("source_local", "") or ""),
            }
            source_local = alias["source_local"]
            if _IDENTIFIER_RE.fullmatch(source_local) and aggregate_kind == "stack_array":
                source_index = _synthetic_array_source_index(alias["source"])
                if source_index is not None:
                    by_indexed_local[(source_local, source_index)] = alias
            elif _IDENTIFIER_RE.fullmatch(source_local) and aggregate_kind != "strided_record":
                by_local[source_local] = alias
            if aggregate_kind == "strided_record" and _IDENTIFIER_RE.fullmatch(base) and stride > 0:
                strided[(base, stride, offset)] = alias
    return {"by_local": by_local, "by_indexed_local": by_indexed_local, "strided": strided}


def _annotate_synthetic_aggregate_alias_line(line: str, alias_state: dict[str, object]) -> str:
    if (
        "// PseudoForge review-only:" in line
        or "/*" in line
        or "*/" in line
        or _LOCAL_DECLARATION_RE.match(line or "") is not None
    ):
        return line
    aliases = _synthetic_aggregate_aliases_for_line(line, alias_state)
    if not aliases:
        return line
    parts = [_synthetic_aggregate_alias_token(alias) for alias in aliases[:2]]
    parts = [part for part in parts if part]
    if not parts:
        return line
    if len(aliases) > len(parts):
        parts.append("...")
    parts.append("no rewrite")
    return "%s // PseudoForge review-only: %s" % (
        line.rstrip(),
        sanitize_generated_comment_text("; ".join(parts)),
    )


def _synthetic_aggregate_aliases_for_line(
    line: str,
    alias_state: dict[str, object],
) -> list[dict[str, str]]:
    result: list[tuple[int, dict[str, str]]] = []
    seen = set()
    by_local = alias_state.get("by_local", {})
    if isinstance(by_local, dict):
        for local, alias in by_local.items():
            if not isinstance(local, str) or not isinstance(alias, dict):
                continue
            match = re.search(r"\b%s\b" % re.escape(local), line or "")
            if match is None:
                continue
            key = (alias.get("display_name", ""), alias.get("name", ""), alias.get("source", ""))
            if key in seen:
                continue
            seen.add(key)
            result.append((match.start(), alias))
    by_indexed_local = alias_state.get("by_indexed_local", {})
    if isinstance(by_indexed_local, dict):
        for match in re.finditer(
            r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<index>\d+)\s*\]",
            line or "",
        ):
            alias = by_indexed_local.get((match.group("name"), int(match.group("index"))))
            if not isinstance(alias, dict):
                continue
            key = (alias.get("display_name", ""), alias.get("name", ""), alias.get("source", ""))
            if key in seen:
                continue
            seen.add(key)
            result.append((match.start(), alias))
    strided = alias_state.get("strided", {})
    if isinstance(strided, dict):
        for match in _STRIDED_AGGREGATE_RE.finditer(line or ""):
            base = match.group("base_a") or match.group("base_b") or ""
            stride = _field_offset(match.group("stride_a") or match.group("stride_b") or "")
            offset = _field_offset(match.group("offset_a") or match.group("offset_b") or "0")
            if stride is None or offset is None:
                continue
            alias = strided.get((base, stride, offset))
            if not isinstance(alias, dict):
                continue
            key = (alias.get("display_name", ""), alias.get("name", ""), alias.get("source", ""))
            if key in seen:
                continue
            seen.add(key)
            result.append((match.start(), alias))
    result.sort(key=lambda item: item[0])
    return [item[1] for item in result[:3]]


def _synthetic_array_source_index(source: str) -> int | None:
    match = re.search(r"\[\s*(\d+)\s*\]\s*$", str(source or ""))
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _synthetic_aggregate_alias_token(alias: dict[str, str]) -> str:
    display_name = str(alias.get("display_name", "") or "")
    name = str(alias.get("name", "") or "")
    if not _IDENTIFIER_RE.fullmatch(display_name) or not _IDENTIFIER_RE.fullmatch(name):
        return ""
    offset = _field_offset(alias.get("offset", "")) or 0
    aggregate_kind = str(alias.get("aggregate_kind", "") or "")
    source = str(alias.get("source", "") or "")
    field_type = str(alias.get("type", "") or "unknown")
    details = []
    if source:
        details.append("source %s" % source)
    if field_type:
        details.append(field_type)
    details.append("+0x%X" % offset)
    if aggregate_kind == "strided_record":
        stride = _field_offset(alias.get("stride", "")) or 0
        if stride:
            details.append("stride 0x%X" % stride)
        label = "inferred strided record"
    else:
        label = "inferred stack aggregate"
    details.append(label)
    return "%s.%s (%s)" % (display_name, name, ", ".join(details))


def _review_only_alias_rank(alias: dict[str, str]) -> int:
    score = 0
    if alias.get("structure"):
        score += 4
    if alias.get("display_base") != alias.get("base"):
        score += 3
    if alias.get("type") and alias.get("type") != "unknown":
        score += 2
    if alias.get("source"):
        score += 1
    return score


def _annotate_review_only_field_alias_line(
    line: str,
    aliases_by_base: dict[str, dict[int, dict[str, str]]],
) -> str:
    if "// PseudoForge review-only:" in line or "/*" in line or "*/" in line:
        return line
    aliases = _review_only_aliases_for_line(line, aliases_by_base)
    if not aliases:
        return line
    comment = _review_only_alias_comment(aliases)
    if not comment:
        return line
    return "%s // PseudoForge review-only: %s" % (line.rstrip(), comment)


def _review_only_aliases_for_line(
    line: str,
    aliases_by_base: dict[str, dict[int, dict[str, str]]],
) -> list[dict[str, str]]:
    matches: list[tuple[int, dict[str, str]]] = []
    seen = set()
    for match in _OFFSET_ACCESS_RE.finditer(line or ""):
        offset = _field_offset(match.group("offset"))
        if offset is None:
            continue
        alias = aliases_by_base.get(match.group("base"), {}).get(offset)
        if not alias:
            continue
        key = (alias["base"], offset, alias["name"])
        if key in seen:
            continue
        seen.add(key)
        matches.append((match.start(), alias))
    for match in _DIRECT_BASE_ACCESS_RE.finditer(line or ""):
        alias = aliases_by_base.get(match.group("base"), {}).get(0)
        if not alias:
            continue
        key = (alias["base"], 0, alias["name"])
        if key in seen:
            continue
        seen.add(key)
        matches.append((match.start(), alias))
    matches.sort(key=lambda item: item[0])
    return [item[1] for item in matches[:3]]


def _review_only_alias_comment(aliases: list[dict[str, str]]) -> str:
    parts = [_review_only_alias_token(alias) for alias in aliases[:2]]
    parts = [item for item in parts if item]
    if not parts:
        return ""
    if len(aliases) > len(parts):
        parts.append("...")
    parts.append("no rewrite")
    return sanitize_generated_comment_text("; ".join(parts))


def _review_only_alias_token(alias: dict[str, str]) -> str:
    offset = _field_offset(alias.get("offset", ""))
    # Backward compatibility for callers that pass only the selected alias dict.
    if offset is None:
        name = str(alias.get("name", "") or "")
        if name.startswith("field_"):
            parsed = _field_offset("0x" + name[6:])
            offset = parsed if parsed is not None else 0
        else:
            offset = 0
    display_base = str(alias.get("display_base", "") or alias.get("base", "") or "")
    base = str(alias.get("base", "") or "")
    name = str(alias.get("name", "") or "")
    field_type = str(alias.get("type", "") or "unknown")
    structure = str(alias.get("structure", "") or "")
    source = str(alias.get("source", "") or "")
    if not _IDENTIFIER_RE.fullmatch(display_base) or not _IDENTIFIER_RE.fullmatch(name):
        return ""
    details = []
    if base and base != display_base:
        details.append("base %s" % base)
    if structure:
        details.append(structure)
    if field_type:
        details.append(field_type)
    details.append("+0x%X" % offset)
    if source and source != structure:
        details.append(source)
    return "%s.%s (%s)" % (display_base, name, ", ".join(details))


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


def _line_has_canonical_layout_rewrite(prefix: str) -> bool:
    return (
        re.search(r"->[A-Za-z_][A-Za-z0-9_]*\s*/\*[^*\n]*\+0x[0-9A-Fa-f]+", prefix or "") is not None
        or re.search(r"->field_[0-9A-Fa-f]+\b", prefix or "") is not None
    )

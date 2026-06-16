from __future__ import annotations

import re

from ida_pseudoforge.core.api_semantics import FUNCTION_SIGNATURE_OVERRIDES, NTSTATUS_RETURN_MAP, STATUS_ARGUMENT_INDEXES
from ida_pseudoforge.core.kernel_semantics import looks_like_driver_entry, looks_like_irp_dispatch
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture


def _replace_status_returns(text: str) -> str:
    return _replace_status_literals(text, None)


def _replace_status_literals(text: str, capture: FunctionCapture | None, plan: CleanPlan | None = None) -> str:
    result = text
    status_function = _looks_like_status_function(capture, result)
    status_zero_return = _allows_zero_status_return(capture)
    status_zero_assignment = _allows_zero_status_assignment(capture, plan)
    result = _replace_status_context(
        result,
        re.compile(
            r"(?P<prefix>\breturn\s+)(?P<cast>\([A-Za-z_][A-Za-z0-9_\s\*]*\)\s*)?"
            r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<end>\s*;)"
        ),
        allow_zero=status_zero_return,
    )
    result = _replace_status_assignments(
        result,
        allow_zero=status_function and status_zero_assignment,
    )
    result = _replace_status_comparisons(result)
    result = _replace_status_alias_comparisons(result)
    result = _replace_status_flow_comparisons(result)
    result = _replace_guard_dispatch_status_comparisons(result)
    result = _replace_guard_dispatch_status_ternary_fallbacks(result)
    result = _replace_rtl_raise_status_literals(result)
    result = _replace_status_argument_literals(result)
    result = _replace_32bit_error_status_literals(result, capture)
    result = _replace_status_ternaries(result, capture)
    result = _replace_status_carrier_literals(result)
    return result


def _replace_status_context(text: str, pattern: re.Pattern[str], allow_zero: bool) -> str:
    def repl(match: re.Match[str]) -> str:
        literal = match.group("literal")
        name = _status_name_for_literal(literal, allow_zero=allow_zero)
        if not name:
            return match.group(0)
        return match.group("prefix") + name + match.group("end")

    return pattern.sub(repl, text)


def _replace_status_assignments(text: str, allow_zero: bool) -> str:
    pattern = re.compile(
        r"(?P<prefix>\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)(?P<cast>\([^)]+\)\s*)?"
        r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<end>\s*;)"
    )

    def repl(match: re.Match[str]) -> str:
        if not _is_status_identifier(match.group("target")):
            return match.group(0)
        name = _status_name_for_literal(match.group("literal"), allow_zero=allow_zero)
        if not name:
            return match.group(0)
        return match.group("prefix") + name + match.group("end")

    return pattern.sub(repl, text)


def _replace_status_comparisons(text: str) -> str:
    identifier_first = re.compile(
        r"(?P<prefix>\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:==|!=)\s*)"
        r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?\b"
    )
    literal_first = re.compile(
        r"(?P<prefix>(?<![A-Za-z0-9_]))(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?"
        r"(?P<operator>\s*(?:==|!=)\s*)(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
    )

    def replace_identifier_first(match: re.Match[str]) -> str:
        if not _is_status_identifier(match.group("name")):
            return match.group(0)
        name = _status_name_for_literal(match.group("literal"), allow_zero=False)
        if not name:
            return match.group(0)
        return match.group("prefix") + name

    def replace_literal_first(match: re.Match[str]) -> str:
        if not _is_status_identifier(match.group("name")):
            return match.group(0)
        name = _status_name_for_literal(match.group("literal"), allow_zero=False)
        if not name:
            return match.group(0)
        return match.group("prefix") + name + match.group("operator") + match.group("name")

    return literal_first.sub(replace_literal_first, identifier_first.sub(replace_identifier_first, text))


def _replace_status_alias_comparisons(text: str) -> str:
    assignment_pattern = re.compile(
        r"\b(?P<status>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\b"
    )
    identifier_first = re.compile(
        r"(?P<prefix>\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:==|!=)\s*)"
        r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?\b"
    )
    literal_first = re.compile(
        r"(?P<prefix>(?<![A-Za-z0-9_]))(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))"
        r"(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<operator>\s*(?:==|!=)\s*)"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
    )

    def replace_line(line: str) -> str:
        aliases = {
            match.group("alias")
            for match in assignment_pattern.finditer(line)
            if _is_status_identifier(match.group("status"))
        }
        if not aliases:
            return line

        def replace_identifier_first(match: re.Match[str]) -> str:
            if match.group("name") not in aliases:
                return match.group(0)
            name = _status_name_for_literal(match.group("literal"), allow_zero=False)
            if not name:
                return match.group(0)
            return match.group("prefix") + name

        def replace_literal_first(match: re.Match[str]) -> str:
            if match.group("name") not in aliases:
                return match.group(0)
            name = _status_name_for_literal(match.group("literal"), allow_zero=False)
            if not name:
                return match.group(0)
            return match.group("prefix") + name + match.group("operator") + match.group("name")

        return literal_first.sub(replace_literal_first, identifier_first.sub(replace_identifier_first, line))

    return "".join(replace_line(line) for line in text.splitlines(keepends=True))


def _replace_status_flow_comparisons(text: str) -> str:
    candidates = _status_flow_candidate_names(text)
    return _replace_status_comparisons_for_names(text, candidates)


def _replace_guard_dispatch_status_comparisons(text: str) -> str:
    candidates = _guard_dispatch_status_candidate_names(text)
    return _replace_status_comparisons_for_names(text, candidates)


def _replace_status_comparisons_for_names(text: str, candidates: set[str]) -> str:
    if not candidates:
        return text

    identifier_first = re.compile(
        r"(?P<prefix>\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:==|!=)\s*)"
        r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?\b"
    )
    literal_first = re.compile(
        r"(?P<prefix>(?<![A-Za-z0-9_]))(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))"
        r"(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<operator>\s*(?:==|!=)\s*)"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
    )

    def replace_identifier_first(match: re.Match[str]) -> str:
        if match.group("name") not in candidates:
            return match.group(0)
        name = _status_name_for_literal(match.group("literal"), allow_zero=False)
        if not name:
            return match.group(0)
        return match.group("prefix") + name

    def replace_literal_first(match: re.Match[str]) -> str:
        if match.group("name") not in candidates:
            return match.group(0)
        name = _status_name_for_literal(match.group("literal"), allow_zero=False)
        if not name:
            return match.group(0)
        return match.group("prefix") + name + match.group("operator") + match.group("name")

    return literal_first.sub(replace_literal_first, identifier_first.sub(replace_identifier_first, text))


def _replace_status_assignments_for_names(text: str, candidates: set[str]) -> str:
    if not candidates:
        return text

    pattern = re.compile(
        r"(?P<prefix>\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)"
        r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<end>\s*;)"
    )

    def repl(match: re.Match[str]) -> str:
        if match.group("target") not in candidates:
            return match.group(0)
        name = _status_name_for_literal(match.group("literal"), allow_zero=False)
        if not name:
            return match.group(0)
        return match.group("prefix") + name + match.group("end")

    return pattern.sub(repl, text)


def _replace_guard_dispatch_status_ternary_fallbacks(text: str) -> str:
    pattern = re.compile(
        r"(?m)^(?P<prefix>[ \t]*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)"
        r"(?P<condition>[^;\n?]+?)\?\s*"
        r"(?P<true_arm>[^:\n;]+?)\s*:\s*"
        r"(?P<false_arm>[^;\n]+?)(?P<end>\s*;)"
    )

    def repl(match: re.Match[str]) -> str:
        target = match.group("target")
        if not (_is_status_identifier(target) or _has_status_carrier_use(text, target)):
            return match.group(0)
        if _target_has_bitwise_use(text, target):
            return match.group(0)

        true_arm = match.group("true_arm")
        false_arm = match.group("false_arm")
        true_has_guard = "guard_dispatch_icall_no_overrides" in true_arm
        false_has_guard = "guard_dispatch_icall_no_overrides" in false_arm
        if true_has_guard == false_has_guard:
            return match.group(0)

        if true_has_guard:
            replacement = _replace_guard_dispatch_status_literal_arm(false_arm)
            if replacement == false_arm:
                return match.group(0)
            return (
                match.group("prefix")
                + match.group("condition")
                + "? "
                + true_arm
                + " : "
                + replacement
                + match.group("end")
            )

        replacement = _replace_guard_dispatch_status_literal_arm(true_arm)
        if replacement == true_arm:
            return match.group(0)
        return (
            match.group("prefix")
            + match.group("condition")
            + "? "
            + replacement
            + " : "
            + false_arm
            + match.group("end")
        )

    return pattern.sub(repl, text)


def _replace_guard_dispatch_status_literal_arm(arm: str) -> str:
    match = re.fullmatch(
        r"(?P<prefix>\s*)(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))"
        r"(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<tail>\s*)",
        arm,
    )
    if match is None:
        return arm
    name = _error_status_name_for_literal(match.group("literal"))
    if not name:
        return arm
    return match.group("prefix") + name + match.group("tail")


def _replace_status_carrier_literals(text: str) -> str:
    candidates = _status_carrier_candidate_names(text)
    result = _replace_status_assignments_for_names(text, candidates)
    return _replace_status_comparisons_for_names(result, candidates)


def _replace_rtl_raise_status_literals(text: str) -> str:
    pattern = re.compile(
        r"\bRtlRaiseStatus\(\s*(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))"
        r"(?P<suffix>u?LL|ULL|LL|u|U|L)?\s*\)"
    )

    def repl(match: re.Match[str]) -> str:
        name = _status_name_for_literal(match.group("literal"), allow_zero=False)
        if not name:
            return match.group(0)
        return "RtlRaiseStatus(%s)" % name

    return pattern.sub(repl, text)


def _replace_status_argument_literals(text: str) -> str:
    if not STATUS_ARGUMENT_INDEXES:
        return text

    function_names = sorted(STATUS_ARGUMENT_INDEXES, key=len, reverse=True)
    pattern = re.compile(
        r"\b(?P<function>%s)\((?P<args>[^;\n]*)\)"
        % "|".join(re.escape(name) for name in function_names)
    )

    def repl(match: re.Match[str]) -> str:
        indexes = STATUS_ARGUMENT_INDEXES.get(match.group("function"), set())
        if not indexes:
            return match.group(0)
        args_text = match.group("args")
        replacements: list[tuple[int, int, str]] = []
        spans = _top_level_argument_spans(args_text)
        for index in indexes:
            if index >= len(spans):
                continue
            start, end = spans[index]
            argument = args_text[start:end]
            replacement = _replace_error_status_argument(argument)
            if replacement != argument:
                replacements.append((start, end, replacement))
        if not replacements:
            return match.group(0)
        updated_args = args_text
        for start, end, replacement in sorted(replacements, reverse=True):
            updated_args = updated_args[:start] + replacement + updated_args[end:]
        return match.group("function") + "(" + updated_args + ")"

    return pattern.sub(repl, text)


def _replace_error_status_argument(argument: str) -> str:
    match = re.fullmatch(
        r"(?P<prefix>\s*)(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))"
        r"(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<tail>\s*)",
        argument,
    )
    if match is None:
        return argument
    name = _error_status_name_for_literal(match.group("literal"))
    if not name:
        return argument
    return match.group("prefix") + name + match.group("tail")


def _replace_32bit_error_status_literals(text: str, capture: FunctionCapture | None) -> str:
    result = text
    four_byte_targets = _four_byte_scalar_names(result, capture)

    if four_byte_targets:
        assignment_pattern = re.compile(
            r"(?P<prefix>\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)"
            r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<end>\s*;)"
        )

        def replace_assignment(match: re.Match[str]) -> str:
            if match.group("target") not in four_byte_targets:
                return match.group(0)
            name = _error_status_name_for_literal(match.group("literal"))
            if not name:
                return match.group(0)
            return match.group("prefix") + name + match.group("end")

        result = assignment_pattern.sub(replace_assignment, result)

    store_pattern = re.compile(
        r"(?m)(?P<prefix>^[ \t]*(?:\*\(_DWORD\s+\*\)[^=\n]+?|\*\(\(_DWORD\s+\*\)[^=\n]+?\))\s*=\s*)"
        r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<end>\s*;)"
    )

    def replace_store(match: re.Match[str]) -> str:
        name = _error_status_name_for_literal(match.group("literal"))
        if not name:
            return match.group(0)
        return match.group("prefix") + name + match.group("end")

    return store_pattern.sub(replace_store, result)


def _replace_status_ternaries(text: str, capture: FunctionCapture | None) -> str:
    four_byte_targets = _four_byte_status_candidate_names(text, capture)

    pattern = re.compile(
        r"(?P<prefix>\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<condition>[^;\n?]+?)\?\s*)"
        r"(?P<true_literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<true_suffix>u?LL|ULL|LL|u|U|L)?"
        r"(?P<middle>\s*:\s*)"
        r"(?P<false_literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<false_suffix>u?LL|ULL|LL|u|U|L)?"
        r"(?P<end>\s*;)"
    )

    def repl(match: re.Match[str]) -> str:
        target = match.group("target")
        if target not in four_byte_targets and not _is_status_identifier(target):
            return match.group(0)

        true_literal = match.group("true_literal")
        false_literal = match.group("false_literal")
        true_name = _error_status_name_for_literal(true_literal)
        false_name = _error_status_name_for_literal(false_literal)
        true_is_zero = _is_zero_literal(true_literal)
        false_is_zero = _is_zero_literal(false_literal)
        true_original = true_literal + (match.group("true_suffix") or "")
        false_original = false_literal + (match.group("false_suffix") or "")

        if true_name and false_is_zero:
            return match.group("prefix") + true_name + match.group("middle") + false_original + match.group("end")
        if false_name and true_is_zero:
            return match.group("prefix") + true_original + match.group("middle") + false_name + match.group("end")
        return match.group(0)

    return pattern.sub(repl, text)


def _is_status_identifier(name: str) -> bool:
    lowered = str(name or "").lower()
    if lowered in {"status", "updated", "result", "returnstatus", "ntstatus"}:
        return True
    return "status" in lowered


def _status_flow_candidate_names(text: str) -> set[str]:
    call_result_names = {
        match.group("name")
        for match in re.finditer(
            r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?[A-Za-z_][A-Za-z0-9_]*\s*\(",
            text,
        )
    }
    if not call_result_names:
        return set()

    range_checked_names: set[str] = set()
    for match in re.finditer(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<|>=)\s*0\b", text):
        range_checked_names.add(match.group("name"))
    for match in re.finditer(r"\b0\s*(?:>|<=)\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b", text):
        range_checked_names.add(match.group("name"))
    return call_result_names.intersection(range_checked_names)


def _guard_dispatch_status_candidate_names(text: str) -> set[str]:
    candidates: set[str] = set()
    assignment_pattern = re.compile(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(?P<expr>[^;]*?\bguard_dispatch_icall_no_overrides\s*\([^;]*?\)[^;]*?)\s*;",
        flags=re.DOTALL,
    )
    for match in assignment_pattern.finditer(text):
        candidates.add(match.group("name"))
    return candidates


def _status_carrier_candidate_names(text: str) -> set[str]:
    status_assignment_counts: dict[str, int] = {}
    assignment_pattern = re.compile(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*STATUS_[A-Z0-9_]+\s*;"
    )
    for match in assignment_pattern.finditer(text):
        name = match.group("name")
        status_assignment_counts[name] = status_assignment_counts.get(name, 0) + 1

    candidates: set[str] = set()
    for name, count in status_assignment_counts.items():
        if count >= 2 or _is_status_identifier(name) or _has_status_carrier_use(text, name):
            candidates.add(name)
    return candidates


def _has_status_carrier_use(text: str, name: str) -> bool:
    escaped = re.escape(name)
    return any(
        re.search(pattern % escaped, text)
        for pattern in (
            r"\b%s\s*(?:<|>=)\s*0\b",
            r"\b0\s*(?:>|<=)\s*%s\b",
            r"\breturn\s+(?:\(unsigned int\)\s*)?%s\s*;",
        )
    )


def _target_has_bitwise_use(text: str, name: str) -> bool:
    escaped = re.escape(name)
    bitwise_operator = r"(?:\||\^|<<|>>|(?<!&)&(?!&))"
    return any(
        re.search(pattern % escaped, text)
        for pattern in (
            r"\b%s\s*(?:\|=|\^=|&=|<<=|>>=)",
            r"\b%s\s*%s" % ("%s", bitwise_operator),
            r"%s\s*%s\b" % (bitwise_operator, "%s"),
            r"~\s*%s\b",
        )
    )


def _top_level_argument_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            continue
        if char == "," and depth == 0:
            spans.append((start, index))
            start = index + 1
    spans.append((start, len(text)))
    return spans


def _four_byte_scalar_names(text: str, capture: FunctionCapture | None) -> set[str]:
    names: set[str] = set()
    if capture is not None:
        for local in capture.lvars:
            if _is_four_byte_scalar_type(local.type):
                names.add(local.name)

    declaration_pattern = re.compile(
        r"(?m)^\s*(?P<type>(?:const\s+)?[A-Za-z_][A-Za-z0-9_\s]*?)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=|\[)"
    )
    for match in declaration_pattern.finditer(text):
        if _is_four_byte_scalar_type(match.group("type")):
            names.add(match.group("name"))
    return names


def _is_four_byte_scalar_type(type_text: str) -> bool:
    if "*" in type_text or "&" in type_text:
        return False
    normalized = _normalize_scalar_type(type_text)
    return normalized in {
        "_DWORD",
        "INT",
        "UNSIGNED INT",
        "LONG",
        "ULONG",
        "DWORD",
        "NTSTATUS",
        "ACCESS_MASK",
        "__INT32",
        "UNSIGNED __INT32",
        "INT32_T",
        "UINT32_T",
    }


def _four_byte_status_candidate_names(text: str, capture: FunctionCapture | None) -> set[str]:
    names: set[str] = set()
    if capture is not None:
        for local in capture.lvars:
            if _is_four_byte_status_candidate_type(local.type):
                names.add(local.name)

    declaration_pattern = re.compile(
        r"(?m)^\s*(?P<type>(?:const\s+)?[A-Za-z_][A-Za-z0-9_\s]*?)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=|\[)"
    )
    for match in declaration_pattern.finditer(text):
        if _is_four_byte_status_candidate_type(match.group("type")):
            names.add(match.group("name"))
    return names


def _is_four_byte_status_candidate_type(type_text: str) -> bool:
    if not _is_four_byte_scalar_type(type_text):
        return False
    normalized = _normalize_scalar_type(type_text)
    return normalized != "ACCESS_MASK"


def _error_status_name_for_literal(literal: str) -> str:
    value = _parse_numeric_literal(literal)
    if value is None:
        return ""
    unsigned_value = value & 0xFFFFFFFF
    if (unsigned_value & 0xF0000000) != 0xC0000000:
        return ""
    return _status_name_for_literal(literal, allow_zero=False)


def _is_zero_literal(literal: str) -> bool:
    value = _parse_numeric_literal(literal)
    return value == 0


def _status_name_for_literal(literal: str, allow_zero: bool) -> str:
    value = _parse_numeric_literal(literal)
    if value is None:
        return ""
    if value == 0 and not allow_zero:
        return ""
    candidates = [str(value), literal]
    if value < 0:
        candidates.append(str(value & 0xFFFFFFFF))
    else:
        unsigned_value = value & 0xFFFFFFFF
        candidates.append(str(unsigned_value))
        if unsigned_value & 0x80000000:
            candidates.append(str(unsigned_value - 0x100000000))
        candidates.append("0x%08X" % unsigned_value)
        candidates.append("0x%X" % unsigned_value)
    for candidate in candidates:
        name = NTSTATUS_RETURN_MAP.get(candidate)
        if name:
            return name
    return ""


def _parse_numeric_literal(literal: str) -> int | None:
    try:
        if literal.lower().startswith("-0x"):
            return -int(literal[3:], 16)
        if literal.lower().startswith("0x"):
            return int(literal, 16)
        return int(literal, 10)
    except ValueError:
        return None


def _normalize_scalar_type(type_text: str) -> str:
    normalized = re.sub(r"\b(?:const|volatile|signed)\b", " ", type_text, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", normalized).strip().upper()


def _looks_like_status_function(capture: FunctionCapture | None, text: str) -> bool:
    if capture is not None and "NTSTATUS" in (capture.prototype or ""):
        return True
    return any(literal in text for literal in ("-107374", "322122", "STATUS_"))


def _allows_zero_status_return(capture: FunctionCapture | None) -> bool:
    if capture is None:
        return False
    prototype = capture.prototype or ""
    if "NTSTATUS" in prototype:
        return True
    if looks_like_driver_entry(capture):
        return True
    if looks_like_irp_dispatch(capture):
        return True
    if capture.name in FUNCTION_SIGNATURE_OVERRIDES:
        return True
    return bool(re.match(r"^(?:Nt|Zw)[A-Z_]", capture.name or ""))


def _allows_zero_status_assignment(capture: FunctionCapture | None, plan: CleanPlan | None) -> bool:
    if _allows_zero_status_return(capture):
        return True
    if plan is None:
        return False
    return any(
        item.apply and item.new == "status" and item.source == "kernel-status"
        for item in plan.renames
    )


def _upgrade_kernel_status_types(text: str, capture: FunctionCapture, plan: CleanPlan) -> str:
    if "STATUS_" not in text or not _has_status_accumulator(plan):
        return text
    result = re.sub(
        r"(?m)^__int64(\s+__fastcall\s+%s\s*\()" % re.escape(capture.name),
        r"NTSTATUS\1",
        text,
        count=1,
    )
    result = re.sub(
        r"(?m)^(\s*)(?:unsigned int|ULONG) status(\s*;[^\n]*)$",
        r"\1NTSTATUS status\2",
        result,
        count=1,
    )
    return result


def _has_status_accumulator(plan: CleanPlan) -> bool:
    return any(
        item.apply and item.new == "status" and item.source in {"kernel-status", "semantic-rule"}
        for item in plan.renames
    )

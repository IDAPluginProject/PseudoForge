from __future__ import annotations

import keyword
import re
from dataclasses import dataclass, replace

from ida_pseudoforge.core.api_semantics import NTSTATUS_RETURN_MAP
from ida_pseudoforge.core.normalize import extract_identifiers
from ida_pseudoforge.core.plan_schema import FunctionCapture, RenameSuggestion, WarningDiagnostic


IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
C_RESERVED = {
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
}

TRUE_CONSTANT_NAMES = {
    "one",
    "true",
    "truevalue",
    "booleantrue",
    "alwaystrue",
}
FALSE_CONSTANT_NAMES = {
    "zero",
    "false",
    "falsevalue",
    "booleanfalse",
    "alwaysfalse",
}
WEAK_LLM_CONTEXT_SUFFIXES = (
    "storage",
    "source",
)
SPECIFIC_CONTEXT_TOKENS = {
    "captured",
    "unicode",
    "string",
    "path",
    "image",
    "driver",
    "process",
    "thread",
    "cpu",
    "time",
    "event",
    "object",
    "session",
    "status",
    "verifier",
    "operation",
    "handle",
    "input",
    "target",
    "destination",
    "mask",
}
POINTER_BOUND_RENAME_TOKENS = {
    "destination",
    "target",
    "source",
    "input",
    "output",
    "buffer",
}
POINTER_BOUND_SAFE_TOKENS = {
    "bound",
    "boundary",
    "cursor",
    "end",
    "limit",
}
LLM_LOCAL_RENAME_KINDS = {
    "arg",
    "argument",
    "local",
    "lvar",
    "param",
    "parameter",
}
LLM_ARGUMENT_RENAME_KINDS = {
    "arg",
    "argument",
    "param",
    "parameter",
}
MIN_LLM_ARGUMENT_CONFIDENCE = 0.85
SAVED_COPY_PREFIXES = {
    "captured",
    "saved",
    "stored",
}
WEAK_COPY_NAME_WORDS = {
    "arg",
    "argument",
    "copy",
    "local",
    "param",
    "parameter",
    "temp",
    "tmp",
    "value",
}
STATUS_RENAME_TARGET = "status"
OBJECT_STYLE_RENAME_EXACT_NAMES = {
    "object",
    "referencedobject",
    "objectpointer",
    "targetobject",
    "fileobject",
    "deviceobject",
    "processobject",
    "threadobject",
}
NTSTATUS_RETURN_KEYS = {str(key) for key in NTSTATUS_RETURN_MAP}
DISAMBIGUATED_DUPLICATE_TARGET_SOURCES = {
    "kernel-list",
    "kernel-pool",
    "pattern",
}
CALL_PARSE_SKIP_NAMES = {
    "catch",
    "for",
    "if",
    "kicheckforkernelapcdelivery",
    "return",
    "sizeof",
    "switch",
    "while",
}
UNASSIGNED_LOCAL_SIZE_COUNT_WORDS = {
    "allocation",
    "bytes",
    "count",
    "counts",
    "length",
    "page",
    "pages",
    "size",
}
LIVE_IN_REGISTER_HINT_RE = re.compile(
    r"\b(?:"
    r"[er]?(?:ax|bx|cx|dx|si|di)"
    r"|[abcd][lh]"
    r"|r(?:[8-9]|1[0-5])(?:[bwd])?"
    r"|xmm(?:[0-9]|1[0-5])"
    r")\b",
    re.IGNORECASE,
)
ABI_ARGUMENT_REGISTER_HINTS = {
    "rcx",
    "ecx",
    "cx",
    "cl",
    "rdx",
    "edx",
    "dx",
    "dl",
    "r8",
    "r8d",
    "r8w",
    "r8b",
    "r9",
    "r9d",
    "r9w",
    "r9b",
} | {"xmm%d" % index for index in range(4)}
RETURN_VALUE_REGISTER_HINTS = {"rax", "eax", "ax", "al", "xmm0"}
SYSCALL_THUNK_REGISTER_HINTS = {
    "r%d%s" % (index, suffix)
    for index in (10, 11)
    for suffix in ("", "d", "w", "b")
}
NONVOLATILE_REGISTER_HINTS = {
    "rbx",
    "ebx",
    "bx",
    "bl",
    "bh",
    "rsi",
    "esi",
    "si",
    "rdi",
    "edi",
    "di",
} | {
    "r%d%s" % (index, suffix)
    for index in range(12, 16)
    for suffix in ("", "d", "w", "b")
}


@dataclass(frozen=True, slots=True)
class _UnassignedLocalUsageRisk:
    name: str
    usage: str
    evidence: str
    live_in_register: str = ""
    usage_class: str = ""
    register_class: str = ""
    candidate_action: str = ""
    confidence: float = 0.0


def is_valid_c_identifier(name: str) -> bool:
    if not IDENTIFIER_RE.match(name or ""):
        return False
    if keyword.iskeyword(name):
        return False
    if name in C_RESERVED:
        return False
    return True


def unassigned_local_usage_warnings(
    capture: FunctionCapture,
    renames: list[RenameSuggestion],
) -> list[str]:
    risks = _filtered_unassigned_local_usage_risks(capture, renames)
    if not risks:
        return []

    active_renames = {
        item.old: item
        for item in renames
        if item.old in risks and item.apply
    }
    warnings = []
    for name in sorted(risks):
        risk = risks[name]
        active = active_renames.get(name)
        if active:
            warnings.append(
                "Uninitialized local risk: %s renamed to %s by %s, but %s"
                % (name, active.new, active.source, risk.evidence)
            )
        else:
            warnings.append("Uninitialized local risk: %s" % risk.evidence)
    return warnings


def unassigned_local_usage_diagnostics(
    capture: FunctionCapture,
    renames: list[RenameSuggestion],
) -> list[WarningDiagnostic]:
    risks = _filtered_unassigned_local_usage_risks(capture, renames)
    diagnostics = []
    for name in sorted(risks):
        risk = risks[name]
        if not risk.live_in_register:
            continue
        diagnostics.append(
            WarningDiagnostic(
                kind="unassigned_local_live_in_register",
                message="Uninitialized local risk: %s" % risk.evidence,
                symbol=risk.name,
                usage=risk.usage,
                usage_class=risk.usage_class,
                register=risk.live_in_register,
                register_class=risk.register_class,
                candidate_action=risk.candidate_action,
                confidence=risk.confidence,
                source="validation.unassigned_local_usage",
            )
        )
    return diagnostics


def _filtered_unassigned_local_usage_risks(
    capture: FunctionCapture,
    renames: list[RenameSuggestion],
) -> dict[str, _UnassignedLocalUsageRisk]:
    risks = _unassigned_local_usage_risks(capture)
    if not risks:
        return {}
    suppressed_llm_names = {
        item.old
        for item in renames
        if item.old in risks and item.source == "llm" and not item.apply
    }
    return {
        name: risk
        for name, risk in risks.items()
        if name not in suppressed_llm_names
    }


def validate_renames(
    capture: FunctionCapture,
    suggestions: list[RenameSuggestion],
) -> tuple[list[RenameSuggestion], list[str]]:
    identifiers = extract_identifiers(capture.pseudocode)
    lvar_names = {var.name for var in capture.lvars}
    known_names = identifiers | lvar_names
    argument_semantics = _argument_semantic_words(suggestions)
    status_carrier_names = {item.old for item in suggestions if item.old in known_names}
    status_carrier_names.update(
        name
        for name in lvar_names
        if _is_existing_object_style_status_name(name)
    )
    status_carrier_evidence = _status_carrier_evidence_by_name(capture.pseudocode, status_carrier_names)
    reserved_status_sources = {
        item.old
        for item in suggestions
        if item.old in known_names and item.new == STATUS_RENAME_TARGET
    }
    unassigned_local_risks = _unassigned_local_usage_risks(capture)
    accepted = []
    warnings = []
    used_new_names = set()

    for suggestion in suggestions:
        item = replace(suggestion)
        if item.old == item.new:
            item.apply = False
            warnings.append(f"Skipped noop rename {item.old}")
        elif item.old not in known_names:
            item.apply = False
            warnings.append(f"Skipped missing identifier {item.old}")
        elif not is_valid_c_identifier(item.new):
            item.apply = False
            warnings.append(f"Skipped invalid identifier {item.old}->{item.new}")
        elif item.new in known_names and item.new != item.old:
            item.apply = False
            warnings.append(f"Skipped colliding rename {item.old}->{item.new}")
        elif item.apply and _is_object_style_status_conflict(item, status_carrier_evidence):
            replacement = _status_conflict_replacement(
                item,
                known_names,
                used_new_names,
                reserved_status_sources,
            )
            evidence = _format_status_carrier_evidence(status_carrier_evidence.get(item.old, []))
            if replacement:
                original_new = item.new
                item.new = replacement
                item.confidence = min(item.confidence, 0.86)
                item.evidence = _append_evidence(
                    item.evidence,
                    "status/object conflict downgraded from %s based on %s" % (original_new, evidence),
                )
                warnings.append(
                    "Downgraded status/object semantic conflict rename %s->%s to %s->%s: %s has "
                    "NTSTATUS carrier evidence (%s)"
                    % (item.old, original_new, item.old, replacement, item.old, evidence)
                )
            else:
                item.apply = False
                warnings.append(
                    "Skipped status/object semantic conflict rename %s->%s: %s has "
                    "NTSTATUS carrier evidence (%s)"
                    % (item.old, item.new, item.old, evidence)
                )
        elif item.source == "llm" and _is_untyped_subroutine_rename(item):
            item.apply = False
        elif item.source == "llm" and _is_pascal_case_llm_local_rename(item):
            item.apply = False
            warnings.append(f"Skipped PascalCase LLM rename {item.old}->{item.new}")
        elif item.source == "llm" and _is_generic_argument_rename(item):
            item.apply = False
            warnings.append(f"Skipped generic argument rename {item.old}->{item.new}")
        elif item.source == "llm" and _is_weak_llm_argument_rename(item):
            item.apply = False
            warnings.append(f"Skipped weak argument rename {item.old}->{item.new}")
        elif item.source == "llm" and _is_unsupported_saved_argument_copy_rename(
            capture.pseudocode,
            item,
            argument_semantics,
        ):
            item.apply = False
            warnings.append(f"Skipped unsupported saved-argument rename {item.old}->{item.new}")
        elif item.source == "llm" and _is_risky_unassigned_local_llm_rename(item, unassigned_local_risks):
            risk = unassigned_local_risks[item.old]
            item.apply = False
            item.confidence = min(item.confidence, 0.55)
            item.evidence = _append_evidence(item.evidence, risk.evidence)
            warnings.append(_format_unassigned_local_llm_skip_warning(item, risk))
        elif item.source == "llm" and _is_inconsistent_invariant_name(capture.pseudocode, item.old, item.new):
            item.apply = False
            warnings.append(f"Skipped value-invariant rename {item.old}->{item.new}")
        elif item.source == "llm" and _is_pointer_bound_context_rename(capture.pseudocode, item.old, item.new):
            item.apply = False
            warnings.append(f"Skipped pointer-bound rename {item.old}->{item.new}")
        elif item.source == "llm" and _is_numeric_dispatcher_context_rename(capture.pseudocode, item.new):
            item.apply = False
            warnings.append(f"Skipped numeric dispatcher rename {item.old}->{item.new}")
        elif item.source == "llm" and _is_weak_dispatcher_context_rename(capture.pseudocode, item.old, item.new):
            item.apply = False
            warnings.append(f"Skipped weak dispatcher rename {item.old}->{item.new}")
        elif item.source == "llm" and _is_unsupported_dispatcher_context_rename(capture.pseudocode, item.old, item.new):
            item.apply = False
            warnings.append(f"Skipped unsupported dispatcher rename {item.old}->{item.new}")
        elif item.source == "llm" and _is_reused_dispatcher_context_rename(capture.pseudocode, item.old, item.new):
            item.apply = False
            warnings.append(f"Skipped reused dispatcher rename {item.old}->{item.new}")
        elif item.new in used_new_names:
            replacement = _duplicate_target_replacement(item, known_names, used_new_names)
            if replacement:
                original_new = item.new
                item.new = replacement
                item.confidence = min(item.confidence, 0.86)
                item.evidence = _append_evidence(
                    item.evidence,
                    "duplicate target disambiguated from %s" % original_new,
                )
            else:
                item.apply = False
                warnings.append(f"Skipped duplicate target {item.new}")

        if item.apply:
            used_new_names.add(item.new)
        accepted.append(item)

    _append_existing_object_status_carrier_renames(
        accepted,
        warnings,
        status_carrier_evidence,
        used_new_names,
        known_names,
    )
    return accepted, warnings


def _is_risky_unassigned_local_llm_rename(
    item: RenameSuggestion,
    risks: dict[str, _UnassignedLocalUsageRisk],
) -> bool:
    if not item.apply:
        return False
    if (item.kind or "").lower() not in LLM_LOCAL_RENAME_KINDS:
        return False
    return item.old in risks


def _format_unassigned_local_llm_skip_warning(
    item: RenameSuggestion,
    risk: _UnassignedLocalUsageRisk,
) -> str:
    semantic_note = ""
    if _is_size_count_semantic_name(item.new):
        semantic_note = "; proposed name has size/count semantics"
    return (
        "Uninitialized local risk: skipped LLM rename %s->%s: %s%s"
        % (item.old, item.new, risk.evidence, semantic_note)
    )


def _is_size_count_semantic_name(name: str) -> bool:
    return bool(_split_identifier_words(name) & UNASSIGNED_LOCAL_SIZE_COUNT_WORDS)


def _unassigned_local_usage_risks(capture: FunctionCapture) -> dict[str, _UnassignedLocalUsageRisk]:
    text = capture.pseudocode or ""
    risks = {}
    for var in capture.lvars:
        name = var.name or ""
        if not _is_unassigned_local_risk_candidate(text, name, var.type, var.is_arg):
            continue
        usage = _unassigned_local_usage(text, name)
        if not usage:
            continue
        live_in_register = _live_in_register_hint(text, name, var.location)
        usage_class = _classify_unassigned_local_usage(usage)
        register_class = _classify_live_in_register(live_in_register, usage_class) if live_in_register else ""
        candidate_action = _live_in_candidate_action(register_class, usage_class) if live_in_register else ""
        risks[name] = _UnassignedLocalUsageRisk(
            name=name,
            usage=usage,
            evidence=_unassigned_local_evidence(
                name,
                usage,
                live_in_register,
                usage_class=usage_class,
                register_class=register_class,
            ),
            live_in_register=live_in_register,
            usage_class=usage_class,
            register_class=register_class,
            candidate_action=candidate_action,
            confidence=_live_in_candidate_confidence(candidate_action),
        )
    return risks


def _unassigned_local_evidence(
    name: str,
    usage: str,
    live_in_register: str,
    usage_class: str = "",
    register_class: str = "",
) -> str:
    if live_in_register:
        usage_class = usage_class or _classify_unassigned_local_usage(usage)
        register_class = register_class or _classify_live_in_register(live_in_register, usage_class)
        return (
            "%s appears to be a live-in register value (%s) classified as %s/%s with no recovered "
            "assignment before use as %s; %s"
            % (
                name,
                live_in_register,
                register_class,
                usage_class,
                usage,
                _live_in_register_evidence_note(register_class, usage_class),
            )
        )
    return "%s is declared but has no direct assignment before use as %s" % (name, usage)


def _classify_unassigned_local_usage(usage: str) -> str:
    lowered = (usage or "").lower()
    has_call = "call argument to " in lowered
    has_return = "return expression" in lowered
    has_pointer = "pointer arithmetic expression" in lowered
    if sum(1 for item in (has_call, has_return, has_pointer) if item) > 1:
        return "mixed"
    if has_call:
        return "call_argument"
    if has_return:
        return "return_expression"
    if has_pointer:
        return "pointer_arithmetic"
    return "unknown_usage"


def _classify_live_in_register(register: str, usage_class: str) -> str:
    normalized = (register or "").lower()
    if usage_class == "return_expression" and normalized in RETURN_VALUE_REGISTER_HINTS:
        return "return_value"
    if normalized in ABI_ARGUMENT_REGISTER_HINTS:
        return "abi_argument"
    if normalized in RETURN_VALUE_REGISTER_HINTS:
        return "return_value"
    if normalized in SYSCALL_THUNK_REGISTER_HINTS:
        return "syscall_thunk"
    if normalized in NONVOLATILE_REGISTER_HINTS:
        return "nonvolatile_state"
    return "unknown_register"


def _live_in_register_evidence_note(register_class: str, usage_class: str) -> str:
    if usage_class == "return_expression":
        return "Hex-Rays may have left an unrecovered return/default-path register carrier"
    if register_class == "abi_argument" and usage_class in {"call_argument", "mixed"}:
        return "Hex-Rays may have omitted a function parameter"
    if register_class == "syscall_thunk" and usage_class in {"call_argument", "mixed"}:
        return "Hex-Rays may have preserved a thunk/syscall input or scratch register"
    if register_class == "nonvolatile_state":
        return "Hex-Rays may have preserved register or trap-state context without a recovered assignment"
    if usage_class == "mixed":
        return "manual review is required before treating this as a parameter gap"
    return "treat this as report-only live-in register evidence until stronger context is available"


def _live_in_candidate_action(register_class: str, usage_class: str) -> str:
    if usage_class == "return_expression":
        return "return_carrier_candidate"
    if register_class == "abi_argument" and usage_class in {"call_argument", "mixed"}:
        return "parameter_gap_candidate"
    if register_class == "syscall_thunk" and usage_class in {"call_argument", "mixed"}:
        return "thunk_input_candidate"
    if register_class == "nonvolatile_state":
        return "state_preservation_candidate"
    if usage_class == "mixed":
        return "manual_review_candidate"
    return "live_in_register_report_only"


def _live_in_candidate_confidence(candidate_action: str) -> float:
    if candidate_action == "parameter_gap_candidate":
        return 0.78
    if candidate_action in {"thunk_input_candidate", "return_carrier_candidate"}:
        return 0.70
    if candidate_action == "state_preservation_candidate":
        return 0.62
    if candidate_action == "manual_review_candidate":
        return 0.55
    return 0.45


def _is_unassigned_local_risk_candidate(
    text: str,
    name: str,
    type_text: str,
    is_arg: bool,
) -> bool:
    if not name or is_arg:
        return False
    if _is_signature_parameter_name(text, name):
        return False
    if _is_argument_identifier(name):
        return False
    if not is_valid_c_identifier(name):
        return False
    declaration = _declaration_line_for_name(text, name)
    if not declaration:
        return False
    if _declaration_has_initializer(declaration, name):
        return False
    if _declaration_is_array_or_nonpointer_aggregate(declaration, type_text):
        return False
    if _has_local_assignment_evidence(text, name):
        return False
    if _address_taken(text, name):
        return False
    return True


def _declaration_line_for_name(text: str, name: str) -> str:
    target = re.escape(name)
    pattern = re.compile(
        r"^\s*(?:const\s+)?[A-Za-z_][A-Za-z0-9_:\s\*\&<>]*?\s+"
        r"(?:[\*\&][\*\&\s]*)?"
        + target
        + r"\b[^\n;]*(?:;|=|,|\[)",
        re.MULTILINE,
    )
    match = pattern.search(text or "")
    return match.group(0).strip() if match else ""


def _live_in_register_hint(text: str, name: str, location: str = "") -> str:
    register = _register_hint_from_location(location)
    if register:
        return register

    declaration = _declaration_source_line_for_name(text, name)
    comment_index = declaration.find("//")
    if comment_index < 0:
        return ""
    return _normalize_register_hint(declaration[comment_index + 2 :])


def _register_hint_from_location(location: str) -> str:
    lowered = (location or "").strip().lower()
    if not lowered:
        return ""
    if any(token in lowered for token in ("stk", "stack", "spoiled", "memory")):
        return ""
    return _normalize_register_hint(lowered)


def _declaration_source_line_for_name(text: str, name: str) -> str:
    target = re.escape(name)
    pattern = re.compile(r"\b%s\b[^\n;]*(?:;|=|,|\[)" % target)
    for line in (text or "").splitlines():
        if pattern.search(line):
            return line.strip()
    return ""


def _normalize_register_hint(text: str) -> str:
    match = LIVE_IN_REGISTER_HINT_RE.search(text or "")
    if not match:
        return ""
    return match.group(0).lower()


def _declaration_has_initializer(declaration: str, name: str) -> bool:
    return bool(re.search(r"\b%s\b\s*(?:\[[^\]]*\]\s*)?=" % re.escape(name), declaration or ""))


def _declaration_is_array_or_nonpointer_aggregate(declaration: str, type_text: str) -> bool:
    if "[" in (declaration or ""):
        return True
    normalized_type = (type_text or "").strip().lower()
    if not normalized_type.startswith(("struct ", "union ")):
        return False
    return "*" not in normalized_type and "&" not in normalized_type


def _address_taken(text: str, name: str) -> bool:
    return bool(re.search(r"&\s*%s\b" % re.escape(name), text or ""))


def _has_local_assignment_evidence(text: str, name: str) -> bool:
    return bool(_assigned_expressions(text, name) or _member_assignment_evidence(text, name))


def _member_assignment_evidence(text: str, name: str) -> bool:
    target = re.escape(name)
    member_chain = r"\b" + target + r"\b(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)+"
    assignment = re.compile(member_chain + r"\s*(?:(?:<<|>>|[+\-*/%&|^])?=)(?!=)")
    increment = re.compile(member_chain + r"\s*(?:\+\+|--)")
    return bool(assignment.search(text or "") or increment.search(text or ""))


def _is_signature_parameter_name(text: str, name: str) -> bool:
    header = _function_header_text(text)
    if not header:
        return False
    open_index = header.find("(")
    if open_index < 0:
        return False
    close_index = _matching_paren_index(header, open_index)
    if close_index < 0:
        return False
    parameters = header[open_index + 1 : close_index]
    return bool(re.search(r"\b%s\b" % re.escape(name), parameters))


def _function_header_text(text: str) -> str:
    source = text or ""
    body_index = source.find("{")
    if body_index < 0:
        return ""
    return source[:body_index]


def _unassigned_local_usage(text: str, name: str) -> str:
    usages = []
    call_usage = _call_argument_usage(text, name)
    if call_usage:
        usages.append(call_usage)
    if _return_expression_usage(text, name):
        usages.append("return expression")
    if _pointer_arithmetic_usage(text, name):
        usages.append("pointer arithmetic expression")
    return ", ".join(_dedupe_sequence(usages[:3]))


def _call_argument_usage(text: str, name: str) -> str:
    call_pattern = re.compile(r"\b(?P<call>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for match in call_pattern.finditer(text or ""):
        call_name = match.group("call")
        if call_name.lower() in CALL_PARSE_SKIP_NAMES:
            continue
        open_index = match.end() - 1
        close_index = _matching_paren_index(text, open_index)
        if close_index < 0:
            continue
        for argument in _split_call_arguments(text[open_index + 1 : close_index]):
            if _argument_mentions_name_by_value(argument, name):
                return "call argument to %s" % call_name
    return ""


def _matching_paren_index(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text or "")):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_call_arguments(arguments_text: str) -> list[str]:
    result = []
    start = 0
    depth = 0
    for index, char in enumerate(arguments_text or ""):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            result.append(arguments_text[start:index].strip())
            start = index + 1
    tail = (arguments_text or "")[start:].strip()
    if tail:
        result.append(tail)
    return result


def _argument_mentions_name_by_value(argument: str, name: str) -> bool:
    target = re.escape(name)
    if not re.search(r"\b%s\b" % target, argument or ""):
        return False
    return not bool(re.search(r"&\s*%s\b" % target, argument or ""))


def _return_expression_usage(text: str, name: str) -> bool:
    pattern = re.compile(r"\breturn\s+(?P<expr>[^;\n]*\b%s\b[^;\n]*);" % re.escape(name))
    for match in pattern.finditer(text or ""):
        expression = _mask_skipped_call_expressions(match.group("expr"))
        if _argument_mentions_name_by_value(expression, name):
            return True
    return False


def _mask_skipped_call_expressions(text: str) -> str:
    result = text or ""
    call_pattern = re.compile(r"\b(?P<call>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
    search_start = 0
    while search_start < len(result):
        match = call_pattern.search(result, search_start)
        if not match:
            break
        call_name = match.group("call")
        if call_name.lower() not in CALL_PARSE_SKIP_NAMES:
            search_start = match.end()
            continue
        open_index = match.end() - 1
        close_index = _matching_paren_index(result, open_index)
        if close_index < 0:
            search_start = match.end()
            continue
        result = result[: match.start()] + (" " * (close_index + 1 - match.start())) + result[close_index + 1 :]
        search_start = match.start() + 1
    return result


def _pointer_arithmetic_usage(text: str, name: str) -> bool:
    target = re.escape(name)
    return bool(
        re.search(r"\b%s\b\s*(?:\+|-)\s*[^;\n]+" % target, text or "")
        or re.search(r"[^;\n]+(?:\+|-)\s*\b%s\b" % target, text or "")
    )


def _status_carrier_evidence_by_name(text: str, names: set[str]) -> dict[str, list[str]]:
    result = {}
    for name in sorted(names):
        evidence = _status_carrier_evidence(text, name)
        if _is_strong_status_carrier_evidence(evidence):
            result[name] = evidence
    return result


def _status_carrier_evidence(text: str, name: str) -> list[str]:
    contexts = _usage_contexts(text, name)
    if not contexts:
        return []
    evidence = []
    declaration = _declared_type_for_name(text, name)
    if "NTSTATUS" in declaration.upper():
        evidence.append("declared_ntstatus")
    if any(_is_status_literal_expression(expr) for expr in _assigned_expressions(text, name)):
        evidence.append("assigned_status_constant")
    if _is_compared_with_status_constant(contexts, name):
        evidence.append("compared_status_constant")
    if _has_signed_status_branch(contexts, name):
        evidence.append("signed_status_branch")
    if _is_returned_status_value(contexts, name):
        evidence.append("returned_status_value")
    if _is_written_to_output_status_slot(contexts, name):
        evidence.append("output_status_slot")
    if _assigned_from_call(contexts, name):
        evidence.append("assigned_from_call")
    return _dedupe_sequence(evidence)


def _is_strong_status_carrier_evidence(evidence: list[str]) -> bool:
    strong = {
        "declared_ntstatus",
        "assigned_status_constant",
        "compared_status_constant",
        "output_status_slot",
    }
    if any(item in evidence for item in strong):
        return True
    if "signed_status_branch" in evidence and (
        "assigned_from_call" in evidence or "returned_status_value" in evidence
    ):
        return True
    return False


def _is_object_style_status_conflict(
    item: RenameSuggestion,
    status_carrier_evidence: dict[str, list[str]],
) -> bool:
    if item.old not in status_carrier_evidence:
        return False
    return _is_object_style_rename(item.new)


def _is_object_style_rename(name: str) -> bool:
    normalized = re.sub(r"[^A-Za-z0-9_]", "", name or "").lower()
    if normalized in OBJECT_STYLE_RENAME_EXACT_NAMES:
        return True
    words = _split_identifier_words(name)
    if "status" in words:
        return False
    return "object" in words


def _append_existing_object_status_carrier_renames(
    accepted: list[RenameSuggestion],
    warnings: list[str],
    status_carrier_evidence: dict[str, list[str]],
    used_new_names: set[str],
    known_names: set[str],
) -> None:
    applied_old_names = {item.old for item in accepted if item.apply}
    for old_name, evidence_items in sorted(status_carrier_evidence.items()):
        if old_name in applied_old_names:
            continue
        new_name = _existing_object_status_name(old_name, known_names, used_new_names)
        if not new_name:
            continue
        accepted.append(
            RenameSuggestion(
                kind="lvar",
                old=old_name,
                new=new_name,
                confidence=0.84,
                source="kernel-status",
                evidence=(
                    "object-style local has NTSTATUS carrier evidence (%s)"
                    % _format_status_carrier_evidence(evidence_items)
                ),
            )
        )
        used_new_names.add(new_name)
        warnings.append(
            "Downgraded object-style status carrier name %s->%s: %s has NTSTATUS carrier evidence (%s)"
            % (old_name, new_name, old_name, _format_status_carrier_evidence(evidence_items))
        )


def _is_existing_object_style_status_name(name: str) -> bool:
    words = _split_identifier_words(name)
    return "object" in words and "status" not in words


def _existing_object_status_name(
    old_name: str,
    known_names: set[str],
    used_new_names: set[str],
) -> str:
    words = _ordered_identifier_words(old_name)
    if not words or "object" not in words or "status" in words:
        return ""
    base = _lower_camel_words(words)
    candidates = []
    if base == "object":
        candidates.append("objectStatus")
    else:
        candidates.append("%sStatus" % base)
    candidates.extend(("statusValue", "localStatus"))
    for candidate in candidates:
        if _rename_target_available(candidate, known_names, used_new_names):
            return candidate
    return ""


def _lower_camel_words(words: list[str]) -> str:
    if not words:
        return ""
    first = words[0].lower()
    rest = [word[:1].upper() + word[1:].lower() for word in words[1:]]
    return "".join([first] + rest)


def _status_conflict_replacement(
    item: RenameSuggestion,
    known_names: set[str],
    used_new_names: set[str],
    reserved_status_sources: set[str],
) -> str:
    if _rename_target_available(STATUS_RENAME_TARGET, known_names, used_new_names) and not any(
        source != item.old for source in reserved_status_sources
    ):
        return STATUS_RENAME_TARGET
    for candidate in _status_conflict_fallback_names(item):
        if _rename_target_available(candidate, known_names, used_new_names):
            return candidate
    return ""


def _status_conflict_fallback_names(item: RenameSuggestion) -> tuple[str, ...]:
    words = _split_identifier_words(item.old) | _split_identifier_words(item.new)
    if "object" in words:
        return ("objectStatus", "statusValue", "localStatus")
    return ("statusValue", "localStatus")


def _rename_target_available(
    name: str,
    known_names: set[str],
    used_new_names: set[str],
) -> bool:
    return bool(name) and name not in known_names and name not in used_new_names


def _duplicate_target_replacement(
    item: RenameSuggestion,
    known_names: set[str],
    used_new_names: set[str],
) -> str:
    if not item.apply:
        return ""
    if (item.kind or "").lower() not in LLM_LOCAL_RENAME_KINDS:
        return ""
    if (item.source or "").lower() not in DISAMBIGUATED_DUPLICATE_TARGET_SOURCES:
        return ""
    if item.confidence < 0.84:
        return ""
    if not is_valid_c_identifier(item.new):
        return ""
    for index in range(2, 100):
        candidate = "%s%d" % (item.new, index)
        if is_valid_c_identifier(candidate) and _rename_target_available(candidate, known_names, used_new_names):
            return candidate
    return ""


def _format_status_carrier_evidence(evidence: list[str]) -> str:
    return ", ".join(evidence[:5]) if evidence else "unknown"


def _append_evidence(existing: str, detail: str) -> str:
    if not existing:
        return detail
    return "%s; %s" % (existing, detail)


def _dedupe_sequence(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _is_compared_with_status_constant(contexts: str, name: str) -> bool:
    target = re.escape(name)
    left_pattern = re.compile(
        r"\b"
        + target
        + r"\b\s*(?:==|!=|<=|>=|<|>)\s*(?P<expr>[^)&|;\n]+)"
    )
    right_pattern = re.compile(
        r"(?P<expr>[^(&|;\n]+?)\s*(?:==|!=|<=|>=|<|>)\s*\b"
        + target
        + r"\b"
    )
    for match in left_pattern.finditer(contexts):
        if _is_status_literal_expression(match.group("expr")):
            return True
    for match in right_pattern.finditer(contexts):
        if _is_status_literal_expression(match.group("expr")):
            return True
    return False


def _has_signed_status_branch(contexts: str, name: str) -> bool:
    target = re.escape(name)
    cast_prefix = r"(?:\([A-Za-z_][A-Za-z0-9_:\s\*\&]*\)\s*)*"
    operand = cast_prefix + r"\b" + target + r"\b"
    return bool(
        re.search(r"\bif\s*\([^;\n]*" + operand + r"\s*(?:<|>=)\s*0\b", contexts)
        or re.search(r"\bif\s*\([^;\n]*\b0\s*(?:>|<=)\s*" + operand, contexts)
    )


def _is_returned_status_value(contexts: str, name: str) -> bool:
    return bool(re.search(r"\breturn\s+(?:\([^)]+\)\s*)?%s\b" % re.escape(name), contexts))


def _is_written_to_output_status_slot(contexts: str, name: str) -> bool:
    target = re.escape(name)
    value = r"(?:\([^)]+\)\s*)?\b" + target + r"\b\s*;"
    status_lvalue = r"(?:\bstatus\b|\b[A-Za-z_][A-Za-z0-9_]*[Ss]tatus\b)"
    return bool(
        re.search(r"\*\s*\([^)]*NTSTATUS[^)]*\)\s*[^=;\n]+\s*=\s*" + value, contexts, re.IGNORECASE)
        or re.search(status_lvalue + r"\s*=\s*" + value, contexts)
        or re.search(r"\*\s*" + status_lvalue + r"\s*=\s*" + value, contexts)
    )


def _is_status_literal_expression(expr: str) -> bool:
    value = _strip_casts_and_suffixes(expr)
    if not value:
        return False
    if re.fullmatch(r"STATUS_[A-Za-z0-9_]+", value):
        return True
    numeric = _parse_integer_literal(value)
    if numeric is None:
        return False
    return _is_ntstatus_numeric_literal(numeric)


def _strip_casts_and_suffixes(expr: str) -> str:
    value = (expr or "").strip()
    value = re.sub(r"\s+", " ", value)
    cast_pattern = re.compile(r"^\([A-Za-z_][A-Za-z0-9_:\s\*\&]*\)\s*")
    while True:
        updated = cast_pattern.sub("", value)
        if updated == value:
            break
        value = updated.strip()
    value = re.sub(r"\s+", "", value)
    value = re.sub(r"(?i)(?:ui64|i64|ull|llu|ll|ul|lu|u|l)$", "", value)
    return value


def _parse_integer_literal(value: str) -> int | None:
    if re.fullmatch(r"[0-9A-Fa-f]+[hH]", value or ""):
        try:
            return int(value[:-1], 16)
        except ValueError:
            return None
    if not re.fullmatch(r"[+-]?(?:0x[0-9A-Fa-f]+|\d+)", value or ""):
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def _is_ntstatus_numeric_literal(value: int) -> bool:
    if value == 0:
        return False
    unsigned = value & 0xFFFFFFFF
    signed = unsigned if unsigned < 0x80000000 else unsigned - 0x100000000
    candidates = {
        str(value),
        str(unsigned),
        str(signed),
        "0x%X" % unsigned,
        "0x%x" % unsigned,
    }
    if candidates & NTSTATUS_RETURN_KEYS:
        return True
    severity = unsigned & 0xC0000000
    return unsigned > 0xFFFF and severity in {0x40000000, 0x80000000, 0xC0000000}


def _is_pascal_case_llm_local_rename(item: RenameSuggestion) -> bool:
    if (item.kind or "").lower() not in LLM_LOCAL_RENAME_KINDS:
        return False
    name = item.new or ""
    if not name or not name[0].isupper():
        return False
    if name.isupper():
        return False
    return any(char.islower() for char in name)


def _is_untyped_subroutine_rename(item: RenameSuggestion) -> bool:
    if (item.kind or "").lower() not in LLM_LOCAL_RENAME_KINDS:
        return False
    return bool(re.fullmatch(r"sub_[0-9A-Fa-f]+", item.old or ""))


def _is_generic_argument_rename(item: RenameSuggestion) -> bool:
    if (item.kind or "").lower() not in LLM_LOCAL_RENAME_KINDS:
        return False
    return bool(re.fullmatch(r"(?i)(?:arg|argument|param|parameter)\d+", item.new or ""))


def _is_weak_llm_argument_rename(item: RenameSuggestion) -> bool:
    if not _is_argument_identifier(item.old):
        return False
    kind = (item.kind or "").lower()
    if kind not in LLM_ARGUMENT_RENAME_KINDS and kind not in LLM_LOCAL_RENAME_KINDS:
        return False
    return item.confidence < MIN_LLM_ARGUMENT_CONFIDENCE


def _is_argument_identifier(name: str) -> bool:
    return bool(re.fullmatch(r"a\d+", name or ""))


def _argument_semantic_words(suggestions: list[RenameSuggestion]) -> dict[str, set[str]]:
    result = {}
    for item in suggestions:
        if not re.fullmatch(r"a\d+", item.old or ""):
            continue
        if item.source == "llm":
            if item.confidence < MIN_LLM_ARGUMENT_CONFIDENCE:
                continue
            if _is_generic_argument_rename(item) or _is_pascal_case_llm_local_rename(item):
                continue
        words = _meaningful_name_words(item.new)
        if words:
            result[item.old] = words
    return result


def _is_unsupported_saved_argument_copy_rename(
    text: str,
    item: RenameSuggestion,
    argument_semantics: dict[str, set[str]],
) -> bool:
    if (item.kind or "").lower() not in {"local", "lvar"}:
        return False
    base_words = _saved_copy_base_words(item.new)
    if not base_words:
        return False
    source_args = _direct_argument_assignment_sources(text, item.old)
    if not source_args:
        return False
    for source_arg in source_args:
        supported_words = argument_semantics.get(source_arg, set())
        if not supported_words or not base_words.issubset(supported_words):
            return True
    return False


def _saved_copy_base_words(name: str) -> set[str]:
    words = [_normalize_name_word(word) for word in _ordered_identifier_words(name)]
    words = [word for word in words if word]
    if not words or words[0] not in SAVED_COPY_PREFIXES:
        return set()
    return {word for word in words[1:] if word and word not in WEAK_COPY_NAME_WORDS and not word.isdigit()}


def _meaningful_name_words(name: str) -> set[str]:
    return {
        word
        for word in (_normalize_name_word(word) for word in _ordered_identifier_words(name))
        if word and word not in WEAK_COPY_NAME_WORDS and word not in SAVED_COPY_PREFIXES and not word.isdigit()
    }


def _direct_argument_assignment_sources(text: str, old_name: str) -> set[str]:
    target = re.escape(old_name)
    pattern = re.compile(
        r"(?:\b(?:LOBYTE|HIBYTE|BYTE\d+|LOWORD|HIWORD|WORD\d+|LODWORD|HIDWORD|DWORD\d+)\(\s*"
        + target
        + r"\s*\)|\b"
        + target
        + r"\b)\s*=\s*(?:\([^)]+\)\s*)?(?P<src>a\d+)\b\s*;",
    )
    return {match.group("src") for match in pattern.finditer(text)}


def _normalize_name_word(word: str) -> str:
    value = (word or "").lower()
    if len(value) > 3 and value.endswith("s"):
        return value[:-1]
    return value


def _is_inconsistent_invariant_name(text: str, old_name: str, new_name: str) -> bool:
    expected = _expected_invariant_values(new_name)
    if not expected:
        return False
    assignments = _assigned_expressions(text, old_name)
    if not assignments:
        return True
    return any(_normalize_expression(expr) not in expected for expr in assignments)


def _expected_invariant_values(new_name: str) -> set[str]:
    normalized = new_name.lower()
    if normalized in TRUE_CONSTANT_NAMES:
        return {"1", "true", "TRUE"}
    if normalized in FALSE_CONSTANT_NAMES:
        return {"0", "false", "FALSE"}
    return set()


def _assigned_expressions(text: str, name: str) -> list[str]:
    target = re.escape(name)
    pattern = re.compile(
        r"(?:\b(?:LOBYTE|HIBYTE|BYTE\d+|LOWORD|HIWORD|WORD\d+|LODWORD|HIDWORD|DWORD\d+)\(\s*"
        + target
        + r"\s*\)|\b"
        + target
        + r"\b)\s*=(?!=)"
    )
    result = []
    for match in pattern.finditer(text or ""):
        expression = _assignment_expression_after(text, match.end())
        if expression:
            result.append(expression)
    return result


def _assignment_expression_after(text: str, start: int) -> str:
    source = text or ""
    depth = 0
    end = start
    while end < len(source):
        char = source[end]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif char in ",;" and depth == 0:
            break
        elif char == "\n" and depth == 0:
            break
        end += 1
    return source[start:end].strip()


def _normalize_expression(expr: str) -> str:
    value = expr.strip()
    value = re.sub(r"\s+", "", value)
    value = re.sub(r"(?i)(?:u?ll|ull|ul|lu|u|l)$", "", value)
    return value


def _is_weak_dispatcher_context_rename(text: str, old_name: str, new_name: str) -> bool:
    if not _is_weak_llm_context_name(new_name):
        return False
    if not _looks_like_large_dispatcher(text):
        return False
    return bool(re.search(r"\b%s\b" % re.escape(old_name), text))


def _is_weak_llm_context_name(name: str) -> bool:
    normalized = (name or "").lower()
    if "scratch" in normalized:
        return True
    if normalized.endswith(WEAK_LLM_CONTEXT_SUFFIXES):
        return True
    if normalized.startswith("temp") or normalized.startswith("temporary"):
        return True
    if "local" in normalized and normalized.endswith("copy"):
        return True
    return False


def _is_unsupported_dispatcher_context_rename(text: str, old_name: str, new_name: str) -> bool:
    if not _looks_like_large_dispatcher(text):
        return False
    if _is_supported_dispatcher_salvage_rename(text, old_name, new_name):
        return False
    tokens = _semantic_tokens(new_name)
    if not tokens:
        return False
    contexts = _usage_contexts(text, old_name)
    if not contexts:
        return False
    return any(not _token_supported_by_context(token, contexts) for token in tokens)


def _is_pointer_bound_context_rename(text: str, old_name: str, new_name: str) -> bool:
    words = _split_identifier_words(new_name)
    if words & POINTER_BOUND_SAFE_TOKENS:
        return False
    if not words & POINTER_BOUND_RENAME_TOKENS:
        return False
    contexts = _usage_contexts(text, old_name)
    if not contexts:
        return False
    target = re.escape(old_name)
    assigned_from_addition = re.search(
        r"\b%s\b\s*=\s*(?:\([^)]+\)\s*)?[^;\n]+\+\s*[^;\n]+;" % target,
        contexts,
    )
    if not assigned_from_addition:
        return False
    compared_as_bound = re.search(r"\b%s\b\s*[<>]=?" % target, contexts) or re.search(
        r"[<>]=?\s*\b%s\b" % target,
        contexts,
    )
    return bool(compared_as_bound)


def _is_reused_dispatcher_context_rename(text: str, old_name: str, new_name: str) -> bool:
    if not _looks_like_large_dispatcher(text):
        return False
    if _is_supported_dispatcher_salvage_rename(text, old_name, new_name):
        return False
    tokens = _semantic_tokens(new_name)
    if not tokens:
        return False
    if not _usage_spans_distant_regions(text, old_name):
        return False
    contexts = _usage_contexts(text, old_name)
    if _token_supported_by_context("pool", contexts):
        return False
    return True


def _is_supported_dispatcher_salvage_rename(text: str, old_name: str, new_name: str) -> bool:
    words = _split_identifier_words(new_name)
    if "status" in words:
        return _has_stable_status_context(text, old_name, words)
    if "handle" in words:
        return _has_stable_handle_context(text, old_name, words)
    return False


def _has_stable_status_context(text: str, old_name: str, words: set[str]) -> bool:
    if words & {"byte", "bytes", "flag", "flags", "ptr", "pointer", "value"}:
        return False
    contexts = _usage_contexts(text, old_name)
    if not contexts:
        return False
    if re.search(r"\b(?:LO|HI)?(?:BYTE|WORD|DWORD)\d*\(\s*%s\s*\)" % re.escape(old_name), contexts):
        return False
    score = 0
    declaration = _declared_type_for_name(text, old_name)
    if "NTSTATUS" in declaration.upper():
        score += 2
    if re.search(r"\b%s\b\s*=\s*-?10737\d{5,}\b" % re.escape(old_name), contexts):
        score += 2
    if re.search(r"\b%s\b\s*=\s*322122\d+\b" % re.escape(old_name), contexts):
        score += 2
    if _assigned_from_call(contexts, old_name):
        score += 1
    if re.search(r"\b%s\b\s*(?:<|>=)\s*0\b" % re.escape(old_name), contexts):
        score += 2
    if re.search(r"\b(?:RtlRaiseStatus|FsRtlIsNtstatusExpected)\(\s*%s\s*\)" % re.escape(old_name), contexts):
        score += 2
    if re.search(r"\breturn\s+(?:\([^)]+\)\s*)?%s\b" % re.escape(old_name), contexts):
        score += 1
    return score >= 3


def _has_stable_handle_context(text: str, old_name: str, words: set[str]) -> bool:
    if words & {"input", "target", "source", "destination", "out", "output", "existing"}:
        return False
    declaration = _declared_type_for_name(text, old_name)
    if "HANDLE" not in declaration.upper():
        return False
    contexts = _usage_contexts(text, old_name)
    if not contexts:
        return False
    lowered = contexts.lower()
    return any(
        token in lowered
        for token in (
            "zwclose",
            "obclosehandle",
            "obreferenceobjectbyhandle",
            "obpreferenceobjectbyhandle",
            "zwsetinformationfile",
            "zwwritefile",
            "zwenumeratevaluekey",
            "iopcreatefile",
            "obopenobjectbyname",
        )
    )


def _declared_type_for_name(text: str, name: str) -> str:
    pattern = re.compile(
        r"(?m)^\s*(?P<type>(?:const\s+)?[A-Za-z_][A-Za-z0-9_:\s\*\&<>]*?)\s+"
        r"(?P<ptr>[\*\&][\*\&\s]*)?"
        r"%s\b" % re.escape(name)
    )
    match = pattern.search(text or "")
    if not match:
        return ""
    type_text = match.group("type").strip()
    ptr = (match.group("ptr") or "").strip()
    if ptr:
        type_text = "%s %s" % (type_text, ptr)
    return type_text


def _assigned_from_call(contexts: str, old_name: str) -> bool:
    return bool(
        re.search(
            r"\b%s\b\s*=\s*(?:\([^)]+\)\s*)?[A-Za-z_][A-Za-z0-9_]*\s*\("
            % re.escape(old_name),
            contexts,
        )
    )


def _is_numeric_dispatcher_context_rename(text: str, new_name: str) -> bool:
    if not _looks_like_large_dispatcher(text):
        return False
    normalized = new_name or ""
    return bool(
        re.search(
            r"(?i)\b(?:case|class|label)(?:minus|delta|value|id)?\d+[A-Za-z0-9_]*\b",
            normalized,
        )
    )


def _semantic_tokens(name: str) -> set[str]:
    normalized = _split_identifier_words(name)
    result = set()
    for token in SPECIFIC_CONTEXT_TOKENS:
        if token in normalized:
            result.add(token)
    return result


def _split_identifier_words(name: str) -> set[str]:
    return set(_ordered_identifier_words(name))


def _ordered_identifier_words(name: str) -> list[str]:
    words = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+", name or "")
    return [word.lower() for word in words]


def _usage_contexts(text: str, old_name: str) -> str:
    lines = text.splitlines()
    contexts = []
    pattern = re.compile(r"\b%s\b" % re.escape(old_name))
    for index, line in enumerate(lines):
        if not pattern.search(line):
            continue
        start = max(0, index - 2)
        end = min(len(lines), index + 3)
        contexts.append("\n".join(lines[start:end]))
    return "\n".join(contexts)


def _usage_spans_distant_regions(text: str, old_name: str) -> bool:
    lines = text.splitlines()
    pattern = re.compile(r"\b%s\b" % re.escape(old_name))
    hits = [index for index, line in enumerate(lines) if pattern.search(line)]
    if len(hits) < 4:
        return False
    if hits[-1] - hits[0] >= 80:
        return True
    label_hits = len({match.group(0) for match in re.finditer(r"\bLABEL_\d+\b", "\n".join(lines[hits[0] : hits[-1] + 1]))})
    return label_hits >= 2


def _token_supported_by_context(token: str, contexts: str) -> bool:
    lowered = contexts.lower()
    if token == "captured":
        return "capture" in lowered or "probe" in lowered or "previousmode" in lowered
    if token == "unicode":
        return "unicode" in lowered or "widechar" in lowered or "wchar" in lowered
    if token == "string":
        return "string" in lowered or "wchar" in lowered or "strlen" in lowered
    if token == "path":
        return "path" in lowered or "registry" in lowered or "systemroot" in lowered
    if token == "image":
        return "image" in lowered or "loadsystemimage" in lowered or "unloadsystemimage" in lowered
    if token == "driver":
        return "driver" in lowered or "loaddriver" in lowered or "unloaddriver" in lowered
    if token == "process":
        return "process" in lowered or "psprocess" in lowered
    if token == "thread":
        return "thread" in lowered or "kthread" in lowered
    if token == "cpu":
        return "cpu" in lowered or "processor" in lowered
    if token == "time":
        return "time" in lowered or "timer" in lowered
    if token == "event":
        return "event" in lowered
    if token == "object":
        return "object" in lowered or "obreference" in lowered
    if token == "session":
        return "session" in lowered
    if token == "pool":
        return "pool" in lowered or "exallocatepool" in lowered or "exfreepool" in lowered
    if token == "status":
        return "status" in lowered or "ntstatus" in lowered
    if token == "verifier":
        return "verifier" in lowered or "vf" in lowered
    if token == "operation":
        return "operation" in lowered or "selector" in lowered
    if token == "handle":
        return "handle" in lowered or "obreferenceobjectbyhandle" in lowered
    if token == "input":
        return "input" in lowered or "_in_" in lowered
    if token == "target":
        return "target" in lowered or "destination" in lowered
    if token == "destination":
        return "destination" in lowered or "target" in lowered
    if token == "mask":
        return "mask" in lowered or "cpuset" in lowered
    return True


def _looks_like_large_dispatcher(text: str) -> bool:
    lines = text.splitlines()
    if len(lines) >= 180:
        return True
    return_count = len(re.findall(r"\breturn\b", text))
    label_count = len(re.findall(r"\bLABEL_\d+\b", text))
    branch_count = len(re.findall(r"\bif\s*\(", text)) + len(re.findall(r"(?m)^\s*case\b", text))
    if label_count >= 8 and return_count >= 8:
        return True
    return return_count >= 16 and branch_count >= 16

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from ida_pseudoforge.core.ioctl import parse_c_integer_literal
from ida_pseudoforge.core.plan_schema import (
    BufferSizeConstraint,
    FieldAccess,
    FieldConstraint,
    HelperContractEdge,
)


_IDENT_RE = r"[A-Za-z_][A-Za-z0-9_]*"
_ABI_ARG_REGISTERS = ("rcx", "rdx", "r8", "r9")
_COND_RELATIONS = {
    "jz": "==",
    "je": "==",
    "jnz": "!=",
    "jne": "!=",
    "jb": "<",
    "jnae": "<",
    "jc": "<",
    "jbe": "<=",
    "jna": "<=",
    "ja": ">",
    "jnbe": ">",
    "jae": ">=",
    "jnb": ">=",
    "jnc": ">=",
    "jl": "<",
    "jnge": "<",
    "jle": "<=",
    "jng": "<=",
    "jg": ">",
    "jnle": ">",
    "jge": ">=",
    "jnl": ">=",
}
_TYPE_BY_WIDTH = {
    1: "UCHAR",
    2: "USHORT",
    4: "ULONG",
    8: "ULONGLONG",
}
_WIDTH_BY_PTR_TOKEN = {
    "byte": 1,
    "word": 2,
    "dword": 4,
    "qword": 8,
}


@dataclass(slots=True)
class DisasmInstruction:
    ea: int = 0
    mnemonic: str = ""
    operands: list[str] = field(default_factory=list)
    text: str = ""
    successors: list[int] = field(default_factory=list)
    call_target: str = ""
    branch_taken_reject: bool = False
    is_terminal: bool = False


@dataclass(slots=True)
class DisasmCaseSlice:
    command_value: int
    function_ea: int = 0
    function_name: str = ""
    dispatcher: str = ""
    entry_ea: int = 0
    instructions: list[DisasmInstruction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    evidence: str = ""


@dataclass(slots=True)
class DisasmCaseContractEvidence:
    command_value: int
    dispatcher: str = ""
    size_constraints: list[BufferSizeConstraint] = field(default_factory=list)
    field_accesses: list[FieldAccess] = field(default_factory=list)
    field_constraints: list[FieldConstraint] = field(default_factory=list)
    helper_edges: list[HelperContractEdge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    evidence: str = ""
    confidence: float = 0.0


@dataclass(slots=True)
class _MemoryReference:
    operand: str
    base: str
    offset: int
    width: int


@dataclass(slots=True)
class _CompareState:
    instruction: DisasmInstruction
    left: str
    right: str
    memory: _MemoryReference | None = None
    test_mask: str = ""


def normalize_disasm_slices(
    slices: Iterable[DisasmCaseSlice] | dict[int, DisasmCaseSlice] | None,
) -> dict[int, DisasmCaseSlice]:
    if slices is None:
        return {}
    if isinstance(slices, dict):
        return {
            int(value): item
            for value, item in slices.items()
            if item is not None
        }
    result: dict[int, DisasmCaseSlice] = {}
    for item in slices:
        if item is None:
            continue
        result[int(item.command_value)] = item
    return result


def recover_disasm_case_evidence(
    case_slice: DisasmCaseSlice,
    buffer_sources: dict[str, dict[str, str]],
    length_aliases: dict[str, str] | None = None,
    rename_map: dict[str, str] | None = None,
    initial_aliases: dict[str, str] | None = None,
    max_instructions: int = 512,
) -> DisasmCaseContractEvidence:
    rename_map = rename_map or {}
    known_buffers = set(buffer_sources)
    known_lengths = _known_length_names(buffer_sources)
    aliases: dict[str, str] = {}
    stack_aliases: dict[int, str] = {}
    for name in known_buffers | known_lengths:
        aliases[_canonical_value(name)] = name
    for old, new in rename_map.items():
        if old and new:
            aliases[_canonical_value(old)] = new
    for source, target in (initial_aliases or {}).items():
        if source and target:
            aliases[_canonical_value(source)] = target
            register = _canonical_register(source)
            if register:
                aliases[register] = target

    result = DisasmCaseContractEvidence(
        command_value=case_slice.command_value,
        dispatcher=case_slice.dispatcher,
        warnings=list(case_slice.warnings),
        evidence=case_slice.evidence or _slice_evidence(case_slice),
    )
    previous_compare: _CompareState | None = None
    instructions = list(case_slice.instructions)[:max(0, max_instructions)]
    for instruction in instructions:
        mnemonic = _normalize_mnemonic(instruction.mnemonic)
        operands = instruction.operands or _split_operands_from_text(instruction.text, mnemonic)
        operands = [_clean_operand_text(item) for item in operands]
        if not mnemonic:
            continue

        if mnemonic in {"mov", "movzx", "movsxd", "lea"} and len(operands) >= 2:
            _track_alias(aliases, stack_aliases, operands[0], operands[1], known_buffers, known_lengths)
        elif mnemonic in {"xor", "sub"} and len(operands) >= 2 and _same_register(operands[0], operands[1]):
            aliases[_canonical_register(operands[0])] = "0"

        field_accesses = _field_accesses_for_instruction(
            instruction,
            mnemonic,
            operands,
            aliases,
            known_buffers,
        )
        for access in field_accesses:
            _merge_field_access(result.field_accesses, access)

        if mnemonic in {"cmp", "test"} and len(operands) >= 2:
            previous_compare = _compare_state(instruction, mnemonic, operands, aliases)
            continue

        relation = _COND_RELATIONS.get(mnemonic)
        if relation and previous_compare is not None:
            reject = instruction.branch_taken_reject or _branch_text_looks_reject(instruction)
            _append_compare_evidence(
                result,
                previous_compare,
                relation,
                instruction,
                aliases,
                known_buffers,
                known_lengths,
                length_aliases or {},
                reject,
            )
            previous_compare = None
            continue

        if mnemonic.startswith("call"):
            edge = _helper_edge_for_call(
                instruction,
                operands,
                aliases,
                stack_aliases,
                known_buffers,
            )
            if edge is not None:
                result.helper_edges.append(edge)
            _clear_call_clobbered_aliases(aliases, stack_aliases)
            previous_compare = None

    result.field_constraints = _dedupe_field_constraints(result.field_constraints)
    result.size_constraints = _dedupe_size_constraints(result.size_constraints)
    result.helper_edges = _dedupe_helper_edges(result.helper_edges)
    if result.size_constraints or result.field_accesses or result.field_constraints or result.helper_edges:
        result.confidence = 0.72
    return result


def _known_length_names(buffer_sources: dict[str, dict[str, str]]) -> set[str]:
    result: set[str] = set()
    for info in buffer_sources.values():
        for item in str(info.get("length", "")).split(","):
            name = item.strip()
            if name:
                result.add(name)
    return result


def _slice_evidence(case_slice: DisasmCaseSlice) -> str:
    if case_slice.entry_ea:
        return "disasm case slice from 0x%X" % case_slice.entry_ea
    return "disasm case slice"


def _normalize_mnemonic(value: str) -> str:
    return re.sub(r"\s+", "", (value or "").lower())


def _split_operands_from_text(text: str, mnemonic: str) -> list[str]:
    stripped = (text or "").strip()
    if not stripped:
        return []
    if mnemonic and stripped.lower().startswith(mnemonic):
        stripped = stripped[len(mnemonic):].strip()
    return _split_operands(stripped)


def _split_operands(text: str) -> list[str]:
    result: list[str] = []
    current: list[str] = []
    bracket_depth = 0
    paren_depth = 0
    for char in text or "":
        if char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(0, paren_depth - 1)
        if char == "," and bracket_depth == 0 and paren_depth == 0:
            item = "".join(current).strip()
            if item:
                result.append(item)
            current = []
            continue
        current.append(char)
    item = "".join(current).strip()
    if item:
        result.append(item)
    return result


def _clean_operand_text(value: str) -> str:
    result = re.sub(r"\s+", " ", str(value or "")).strip()
    result = result.replace(";", " ;")
    return result.split(" ;", 1)[0].strip()


def _track_alias(
    aliases: dict[str, str],
    stack_aliases: dict[int, str],
    destination: str,
    source: str,
    known_buffers: set[str],
    known_lengths: set[str],
) -> None:
    source_alias = _resolve_value_alias(source, aliases)
    if not source_alias:
        source_stack_offset = _stack_offset(source)
        if source_stack_offset is not None:
            source_alias = stack_aliases.get(source_stack_offset, "")
    if not source_alias:
        direct = _direct_known_name(source, known_buffers, known_lengths)
        if direct:
            source_alias = direct
    if not source_alias and _canonical_register(destination):
        callee = _clean_symbol_alias(source)
        if callee:
            source_alias = callee
    if not source_alias:
        return
    stack_offset = _stack_offset(destination)
    if stack_offset is not None:
        stack_aliases[stack_offset] = source_alias
        return
    register = _canonical_register(destination)
    if register:
        aliases[register] = source_alias


def _direct_known_name(source: str, known_buffers: set[str], known_lengths: set[str]) -> str:
    token = _canonical_value(source)
    for name in known_buffers | known_lengths:
        if _canonical_value(name) == token:
            return name
    return ""


def _clean_symbol_alias(value: str) -> str:
    token = _strip_size_prefix(value)
    token = re.sub(r"^offset\s+", "", token, flags=re.IGNORECASE).strip()
    token = token.strip("[]")
    if token.startswith("sub_") or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@$?]*", token):
        return token
    return ""


def _resolve_value_alias(value: str, aliases: dict[str, str]) -> str:
    canonical = _canonical_value(value)
    if canonical in aliases:
        return aliases[canonical]
    register = _canonical_register(value)
    if register and register in aliases:
        return aliases[register]
    stack_offset = _stack_offset(value)
    if stack_offset is not None:
        return aliases.get("[rsp+0x%X]" % stack_offset, "")
    return ""


def _canonical_value(value: str) -> str:
    result = _strip_size_prefix(value)
    result = result.strip()
    result = re.sub(r"^offset\s+", "", result, flags=re.IGNORECASE)
    return result


def _canonical_register(value: str) -> str:
    token = _canonical_value(value).lower()
    token = token.strip("[]")
    register_aliases = {
        "ecx": "rcx",
        "cx": "rcx",
        "cl": "rcx",
        "edx": "rdx",
        "dx": "rdx",
        "dl": "rdx",
        "r8d": "r8",
        "r8w": "r8",
        "r8b": "r8",
        "r9d": "r9",
        "r9w": "r9",
        "r9b": "r9",
        "eax": "rax",
        "ax": "rax",
        "al": "rax",
        "ebx": "rbx",
        "bx": "rbx",
        "bl": "rbx",
        "esi": "rsi",
        "si": "rsi",
        "sil": "rsi",
        "edi": "rdi",
        "di": "rdi",
        "dil": "rdi",
        "r10d": "r10",
        "r11d": "r11",
        "r12d": "r12",
        "r13d": "r13",
        "r14d": "r14",
        "r15d": "r15",
    }
    if token in register_aliases:
        return register_aliases[token]
    if re.fullmatch(r"r(?:[abcd]x|[sb]p|[sd]i|[0-9]{1,2})", token):
        return token
    return ""


def _same_register(left: str, right: str) -> bool:
    return bool(_canonical_register(left) and _canonical_register(left) == _canonical_register(right))


def _stack_offset(value: str) -> int | None:
    cleaned = _strip_size_prefix(value).lower().replace(" ", "")
    match = re.search(r"\[(?:rsp|esp)(?P<sign>[+-])(?P<offset>[0-9a-f]+h|0x[0-9a-f]+|\d+)\]", cleaned)
    if not match:
        return None
    offset = _parse_int(match.group("offset"))
    if offset is None:
        return None
    return offset if match.group("sign") == "+" else -offset


def _parse_int(value: str) -> int | None:
    token = str(value or "").strip()
    if not token:
        return None
    if token.lower().endswith("h") and not token.lower().startswith("0x"):
        token = "0x" + token[:-1]
    return parse_c_integer_literal(token)


def _field_accesses_for_instruction(
    instruction: DisasmInstruction,
    mnemonic: str,
    operands: list[str],
    aliases: dict[str, str],
    known_buffers: set[str],
) -> list[FieldAccess]:
    result: list[FieldAccess] = []
    for index, operand in enumerate(operands):
        memory = _memory_reference(operand, aliases)
        if memory is None or memory.base not in known_buffers:
            continue
        access = _memory_access_kind(mnemonic, index)
        result.append(
            FieldAccess(
                buffer=memory.base,
                structure="",
                offset=memory.offset,
                type=_TYPE_BY_WIDTH.get(memory.width, "ULONG"),
                field=_field_name(memory.offset),
                access=access,
                evidence=_instruction_evidence(instruction),
                source=_instruction_source(instruction),
                confidence=0.76,
            )
        )
    return result


def _memory_access_kind(mnemonic: str, operand_index: int) -> str:
    if mnemonic in {"cmp", "test"}:
        return "read"
    if mnemonic in {"xadd", "cmpxchg", "xchg", "or", "and", "xor", "add", "sub", "inc", "dec"}:
        return "read_write"
    if mnemonic.startswith("mov") and operand_index == 0:
        return "write"
    return "read"


def _compare_state(
    instruction: DisasmInstruction,
    mnemonic: str,
    operands: list[str],
    aliases: dict[str, str],
) -> _CompareState:
    memory = _memory_reference(operands[0], aliases)
    test_mask = ""
    if mnemonic == "test" and len(operands) >= 2:
        if memory is not None:
            test_mask = _immediate_literal(operands[1])
        elif _same_register(operands[0], operands[1]):
            test_mask = "0"
    return _CompareState(
        instruction=instruction,
        left=operands[0],
        right=operands[1],
        memory=memory,
        test_mask=test_mask,
    )


def _append_compare_evidence(
    result: DisasmCaseContractEvidence,
    compare: _CompareState,
    relation: str,
    branch: DisasmInstruction,
    aliases: dict[str, str],
    known_buffers: set[str],
    known_lengths: set[str],
    length_aliases: dict[str, str],
    reject: bool,
) -> None:
    evidence = "%s; %s" % (_instruction_evidence(compare.instruction), _instruction_evidence(branch))
    if compare.test_mask:
        if compare.memory is not None and compare.memory.base in known_buffers:
            mask_relation = "mask_%s" % relation
            valid_relation = _valid_relation_for_reject_guard(mask_relation) if reject else ""
            result.field_constraints.append(
                FieldConstraint(
                    buffer=compare.memory.base,
                    structure="",
                    offset=compare.memory.offset,
                    field=_field_name(compare.memory.offset),
                    relation=mask_relation,
                    value="0",
                    mask=compare.test_mask,
                    valid_relation=valid_relation,
                    valid_value="0" if valid_relation else "",
                    evidence=evidence,
                    source=_instruction_source(compare.instruction),
                    confidence=0.78,
                )
            )
        else:
            length = _canonical_length_name(_resolve_value_alias(compare.left, aliases), length_aliases)
            if length and (length in known_lengths or _looks_like_length_name(length)):
                valid_relation = _valid_relation_for_reject_guard(relation) if reject else ""
                result.size_constraints.append(
                    BufferSizeConstraint(
                        buffer="",
                        length=length,
                        relation=relation,
                        value="0",
                        valid_relation=valid_relation,
                        valid_value="0" if valid_relation else "",
                        role=_role_from_length(length),
                        evidence=evidence,
                        source=_instruction_source(compare.instruction),
                        confidence=0.80,
                    )
                )
        return

    if compare.memory is not None and compare.memory.base in known_buffers:
        value = _immediate_literal(compare.right)
        if not value:
            return
        valid_relation = _valid_relation_for_reject_guard(relation) if reject else ""
        result.field_constraints.append(
            FieldConstraint(
                buffer=compare.memory.base,
                structure="",
                offset=compare.memory.offset,
                field=_field_name(compare.memory.offset),
                relation=relation,
                value=value,
                valid_relation=valid_relation,
                valid_value=value if valid_relation else "",
                evidence=evidence,
                source=_instruction_source(compare.instruction),
                confidence=0.80,
            )
        )
        return

    left_alias = _canonical_length_name(_resolve_value_alias(compare.left, aliases), length_aliases)
    right_alias = _canonical_length_name(_resolve_value_alias(compare.right, aliases), length_aliases)
    right_value = _immediate_literal(compare.right)
    left_value = _immediate_literal(compare.left)
    length = ""
    value = ""
    observed_relation = relation
    if left_alias and (left_alias in known_lengths or _looks_like_length_name(left_alias)) and right_value:
        length = left_alias
        value = right_value
    elif right_alias and (right_alias in known_lengths or _looks_like_length_name(right_alias)) and left_value:
        length = right_alias
        value = left_value
        observed_relation = _invert_relation(relation)
    if not length or not value:
        return
    valid_relation = _valid_relation_for_reject_guard(observed_relation) if reject else ""
    result.size_constraints.append(
        BufferSizeConstraint(
            buffer="",
            length=length,
            relation=observed_relation,
            value=value,
            valid_relation=valid_relation,
            valid_value=value if valid_relation else "",
            role=_role_from_length(length),
            evidence=evidence,
            source=_instruction_source(compare.instruction),
            confidence=0.82,
        )
    )


def _canonical_length_name(name: str, length_aliases: dict[str, str]) -> str:
    current = name
    seen: set[str] = set()
    while current in length_aliases and current not in seen:
        seen.add(current)
        current = length_aliases[current]
    return current


def _memory_reference(operand: str, aliases: dict[str, str]) -> _MemoryReference | None:
    width = _operand_width(operand)
    cleaned = _strip_size_prefix(operand)
    match = re.search(r"\[(?P<expr>[^\]]+)\]", cleaned)
    if match:
        expression = match.group("expr")
    else:
        expression = cleaned
        if "+" not in expression:
            return None
    expression = expression.replace(" ", "")
    expression = expression.replace("-", "+-")
    base = ""
    offset = 0
    for term in expression.split("+"):
        if not term:
            continue
        value = _parse_int(term)
        if value is not None:
            offset += value
            continue
        if "*" in term:
            continue
        alias = _resolve_value_alias(term, aliases)
        if alias:
            base = alias
            continue
        if not base and re.fullmatch(_IDENT_RE, term):
            base = term
    if not base:
        return None
    return _MemoryReference(
        operand=operand,
        base=base,
        offset=max(0, offset),
        width=width,
    )


def _operand_width(operand: str) -> int:
    lowered = (operand or "").lower()
    for token, width in _WIDTH_BY_PTR_TOKEN.items():
        if re.search(r"\b%s\s+ptr\b" % token, lowered):
            return width
    register = _canonical_register(operand)
    if register:
        token = _canonical_value(operand).lower()
        if token.endswith("b") or token in {"al", "bl", "cl", "dl", "sil", "dil"}:
            return 1
        if token.endswith("w") or token in {"ax", "bx", "cx", "dx", "si", "di"}:
            return 2
        if token.startswith("e") or token.endswith("d"):
            return 4
        return 8
    return 4


def _strip_size_prefix(value: str) -> str:
    result = str(value or "").strip()
    result = re.sub(
        r"^(?:byte|word|dword|qword|oword|xmmword|ymmword)\s+ptr\s+",
        "",
        result,
        flags=re.IGNORECASE,
    )
    result = re.sub(r"^(?:cs|ds|ss|es|fs|gs):", "", result, flags=re.IGNORECASE)
    return result.strip()


def _immediate_literal(operand: str) -> str:
    token = _strip_size_prefix(operand).strip()
    token = re.sub(r"^offset\s+", "", token, flags=re.IGNORECASE)
    if token.lower().endswith("h") and not token.lower().startswith("0x"):
        value = _parse_int(token)
        return "0x%X" % value if value is not None else ""
    value = parse_c_integer_literal(token)
    if value is None:
        return ""
    return "0x%X" % value if token.lower().startswith("0x") else str(value)


def _helper_edge_for_call(
    instruction: DisasmInstruction,
    operands: list[str],
    aliases: dict[str, str],
    stack_aliases: dict[int, str],
    known_buffers: set[str],
) -> HelperContractEdge | None:
    callee = _call_callee(instruction, operands, aliases)
    if not callee:
        return None
    arguments: list[str] = []
    for register in _ABI_ARG_REGISTERS:
        value = aliases.get(register, "")
        if value:
            arguments.append(value)
    for _offset, value in sorted(stack_aliases.items()):
        if value and _offset >= 0x20:
            arguments.append(value)
    passed_buffers = []
    for argument in arguments:
        if argument in known_buffers and argument not in passed_buffers:
            passed_buffers.append(argument)
    if not passed_buffers:
        return None
    return HelperContractEdge(
        callee=callee,
        arguments=arguments,
        passed_buffers=passed_buffers,
        resolved=False,
        depth=1,
        evidence=_instruction_evidence(instruction),
        warnings=["helper edge recovered from disassembly; helper capture unavailable"],
        confidence=0.55,
    )


def _clear_call_clobbered_aliases(aliases: dict[str, str], stack_aliases: dict[int, str]) -> None:
    for register in _ABI_ARG_REGISTERS + ("rax", "r10", "r11"):
        aliases.pop(register, None)
    stack_aliases.clear()


def _call_callee(
    instruction: DisasmInstruction,
    operands: list[str],
    aliases: dict[str, str],
) -> str:
    explicit = _clean_callee_name(instruction.call_target)
    if explicit:
        return explicit
    if operands:
        alias = _resolve_value_alias(operands[0], aliases)
        if alias and alias not in {"0"}:
            return _clean_callee_name(alias)
        return _clean_callee_name(operands[0])
    text = _instruction_evidence(instruction)
    match = re.search(r"\bcall\w*\s+(?P<target>.+)$", text, flags=re.IGNORECASE)
    return _clean_callee_name(match.group("target")) if match else ""


def _clean_callee_name(value: str) -> str:
    cleaned = _strip_size_prefix(value)
    cleaned = cleaned.strip()
    cleaned = cleaned.strip("[]")
    cleaned = re.sub(r"^near\s+ptr\s+", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^far\s+ptr\s+", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^__imp_", "", cleaned)
    cleaned = cleaned.split("+", 1)[0].strip()
    if cleaned.startswith("sub_") or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@$?]*", cleaned):
        return cleaned
    return ""


def _instruction_evidence(instruction: DisasmInstruction) -> str:
    if instruction.text:
        return instruction.text
    operands = ", ".join(instruction.operands)
    if operands:
        return "%s %s" % (instruction.mnemonic, operands)
    return instruction.mnemonic


def _instruction_source(instruction: DisasmInstruction) -> str:
    if instruction.ea:
        return "disasm:0x%X" % instruction.ea
    return "disasm"


def _branch_text_looks_reject(instruction: DisasmInstruction) -> bool:
    lowered = _instruction_evidence(instruction).lower()
    return any(
        marker in lowered
        for marker in (
            "reject",
            "fail",
            "error",
            "invalid",
            "mismatch",
            "too_small",
            "overflow",
            "not_supported",
        )
    )


def _valid_relation_for_reject_guard(relation: str) -> str:
    if relation.startswith("mask_"):
        suffix = relation[len("mask_"):]
        negated = _negate_relation(suffix)
        return "mask_%s" % negated if negated else ""
    return _negate_relation(relation)


def _negate_relation(relation: str) -> str:
    return {
        "<": ">=",
        ">": "<=",
        "<=": ">",
        ">=": "<",
        "==": "!=",
        "!=": "==",
    }.get(relation, "")


def _invert_relation(relation: str) -> str:
    return {
        "<": ">",
        ">": "<",
        "<=": ">=",
        ">=": "<=",
        "==": "==",
        "!=": "!=",
    }.get(relation, relation)


def _role_from_length(length: str) -> str:
    lowered = (length or "").lower()
    tokens = set(_semantic_name_tokens(length))
    if "output" in lowered or "out" in tokens:
        return "output"
    return "input"


def _looks_like_length_name(name: str) -> bool:
    compact = re.sub(r"[^A-Za-z0-9]", "", name or "").lower()
    return compact.endswith("length") or compact.endswith("size") or compact.endswith("bytes")


def _semantic_name_tokens(name: str) -> list[str]:
    if not name:
        return []
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    spaced = re.sub(r"[^A-Za-z0-9]+", " ", spaced)
    return [part.lower() for part in spaced.split() if part]


def _field_name(offset: int) -> str:
    return "field_0x%02X" % max(0, offset)


def _merge_field_access(items: list[FieldAccess], item: FieldAccess) -> None:
    for current in items:
        if (
            current.buffer == item.buffer
            and current.offset == item.offset
            and current.field == item.field
            and current.type == item.type
        ):
            if current.access != item.access:
                current.access = "read_write"
            if item.source not in current.source:
                current.source = _merge_source(current.source, item.source)
            return
    items.append(item)


def _merge_source(left: str, right: str) -> str:
    values: list[str] = []
    for value in (left, right):
        for item in str(value or "").split(","):
            item = item.strip()
            if item and item not in values:
                values.append(item)
    return ", ".join(values)


def _dedupe_field_constraints(items: list[FieldConstraint]) -> list[FieldConstraint]:
    result: list[FieldConstraint] = []
    seen = set()
    for item in items:
        key = (
            item.buffer,
            item.offset,
            item.field,
            item.relation,
            item.value,
            item.mask,
            item.valid_relation,
            item.valid_value,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _dedupe_size_constraints(items: list[BufferSizeConstraint]) -> list[BufferSizeConstraint]:
    result: list[BufferSizeConstraint] = []
    seen = set()
    for item in items:
        key = (
            item.length,
            item.relation,
            item.value,
            item.valid_relation,
            item.valid_value,
            item.role,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _dedupe_helper_edges(items: list[HelperContractEdge]) -> list[HelperContractEdge]:
    result: list[HelperContractEdge] = []
    seen = set()
    for item in items:
        key = (item.callee, tuple(item.arguments), tuple(item.passed_buffers))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result

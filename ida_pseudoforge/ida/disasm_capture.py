from __future__ import annotations

from ida_pseudoforge.core.disasm_contracts import DisasmCaseSlice, DisasmInstruction
from ida_pseudoforge.ida.thread_helpers import run_on_main_thread
from ida_pseudoforge.logging import log_checkpoint

try:
    import ida_funcs  # type: ignore
    import ida_gdl  # type: ignore
    import idaapi  # type: ignore
    import idautils  # type: ignore
    import idc  # type: ignore
except Exception:
    ida_funcs = None
    ida_gdl = None
    idaapi = None
    idautils = None
    idc = None


def capture_disasm_case_slice(
    function_ea: int,
    command_value: int,
    entry_ea: int | None = None,
    max_blocks: int = 32,
    max_instructions: int = 512,
) -> DisasmCaseSlice | None:
    if ida_funcs is None or idautils is None or idc is None:
        return None

    def do_capture() -> DisasmCaseSlice | None:
        func = ida_funcs.get_func(function_ea)
        if func is None:
            return None
        start_ea = int(entry_ea or 0)
        if not start_ea:
            start_ea = _find_case_entry_ea(func, command_value)
        if start_ea < int(func.start_ea) or start_ea >= int(func.end_ea):
            return None
        start_block = _block_containing(func, start_ea)
        if start_block is None:
            return None
        blocks = _bounded_blocks(start_block, max_blocks)
        instructions: list[DisasmInstruction] = []
        for block in blocks:
            for ea in idautils.Heads(int(block.start_ea), int(block.end_ea)):
                if len(instructions) >= max_instructions:
                    break
                instruction = _instruction_from_ea(int(ea))
                if instruction is not None:
                    instructions.append(instruction)
            if len(instructions) >= max_instructions:
                break
        if not instructions:
            return None
        function_name = ida_funcs.get_func_name(func.start_ea) or ""
        return DisasmCaseSlice(
            command_value=command_value,
            function_ea=int(func.start_ea),
            function_name=function_name,
            entry_ea=start_ea,
            instructions=instructions,
            evidence="IDA disassembly CFG slice from 0x%X" % start_ea,
        )

    try:
        return run_on_main_thread(do_capture, write=False)
    except Exception as exc:
        log_checkpoint("buffer_contract_case.disasm_capture.failed", error=str(exc))
        return None


def _block_containing(func, ea: int):
    for block in _flowchart(func):
        if int(block.start_ea) <= ea < int(block.end_ea):
            return block
    return None


def _flowchart(func):
    if ida_gdl is not None:
        flowchart = getattr(ida_gdl, "FlowChart", None)
        if callable(flowchart):
            return flowchart(func)
    flowchart = getattr(idaapi, "FlowChart", None) if idaapi is not None else None
    if callable(flowchart):
        return flowchart(func)
    return []


def _bounded_blocks(start_block, max_blocks: int) -> list[object]:
    result: list[object] = []
    queue = [start_block]
    seen: set[int] = set()
    while queue and len(result) < max(1, max_blocks):
        block = queue.pop(0)
        start = int(getattr(block, "start_ea", 0))
        if start in seen:
            continue
        seen.add(start)
        result.append(block)
        succs = getattr(block, "succs", None)
        if not callable(succs):
            continue
        try:
            for successor in succs():
                queue.append(successor)
        except Exception:
            continue
    return result


def _instruction_from_ea(ea: int) -> DisasmInstruction | None:
    mnemonic_getter = getattr(idc, "print_insn_mnem", None)
    if not callable(mnemonic_getter):
        return None
    mnemonic = str(mnemonic_getter(ea) or "")
    if not mnemonic:
        return None
    operands = _instruction_operands(ea)
    text = _disasm_line(ea, mnemonic, operands)
    successors = _code_successors(ea)
    return DisasmInstruction(
        ea=ea,
        mnemonic=mnemonic,
        operands=operands,
        text=text,
        successors=successors,
        call_target=_call_target(ea, mnemonic),
        branch_taken_reject=_target_name_looks_reject(successors),
        is_terminal=mnemonic.lower() in {"ret", "retn", "retf"},
    )


def _find_case_entry_ea(func, command_value: int) -> int:
    heads = list(idautils.Heads(int(func.start_ea), int(func.end_ea)))
    for index, ea in enumerate(heads):
        if not _instruction_mentions_value(int(ea), command_value):
            continue
        target = _nearby_conditional_target(heads, index, func)
        if target:
            return target
    return 0


def _instruction_mentions_value(ea: int, value: int) -> bool:
    operand_value_getter = getattr(idc, "get_operand_value", None)
    if callable(operand_value_getter):
        for index in range(8):
            try:
                if int(operand_value_getter(ea, index)) == int(value):
                    return True
            except Exception:
                continue
    for operand in _instruction_operands(ea):
        if _parse_operand_integer(operand) == int(value):
            return True
    return False


def _nearby_conditional_target(heads: list[int], index: int, func) -> int:
    for candidate in heads[index + 1:index + 5]:
        mnemonic = str(getattr(idc, "print_insn_mnem", lambda _ea: "")(candidate) or "").lower()
        if not mnemonic.startswith("j") or mnemonic == "jmp":
            continue
        fallthrough = _next_head(candidate, int(func.end_ea))
        for target in _code_successors(int(candidate)):
            if target == fallthrough:
                continue
            if int(func.start_ea) <= target < int(func.end_ea):
                return target
    return 0


def _next_head(ea: int, end_ea: int) -> int:
    getter = getattr(idc, "next_head", None)
    if not callable(getter):
        return 0
    try:
        return int(getter(ea, end_ea))
    except Exception:
        return 0


def _parse_operand_integer(operand: str) -> int | None:
    token = str(operand or "").strip()
    if token.lower().endswith("h") and not token.lower().startswith("0x"):
        token = "0x" + token[:-1]
    try:
        return int(token, 0)
    except Exception:
        return None


def _instruction_operands(ea: int) -> list[str]:
    result: list[str] = []
    operand_getter = getattr(idc, "print_operand", None)
    if not callable(operand_getter):
        return result
    for index in range(8):
        try:
            operand = str(operand_getter(ea, index) or "").strip()
        except Exception:
            operand = ""
        if not operand:
            continue
        result.append(operand)
    return result


def _disasm_line(ea: int, mnemonic: str, operands: list[str]) -> str:
    generator = getattr(idc, "generate_disasm_line", None)
    if callable(generator):
        try:
            line = str(generator(ea, 0) or "").strip()
            if line:
                return line
        except Exception:
            pass
    if operands:
        return "%s %s" % (mnemonic, ", ".join(operands))
    return mnemonic


def _code_successors(ea: int) -> list[int]:
    result: list[int] = []
    refs_from = getattr(idautils, "CodeRefsFrom", None)
    if not callable(refs_from):
        return result
    try:
        for target in refs_from(ea, 0):
            value = int(target)
            if value not in result:
                result.append(value)
    except Exception:
        return result
    return result


def _call_target(ea: int, mnemonic: str) -> str:
    if not str(mnemonic or "").lower().startswith("call"):
        return ""
    value_getter = getattr(idc, "get_operand_value", None)
    if not callable(value_getter):
        return ""
    try:
        target = int(value_getter(ea, 0))
    except Exception:
        return ""
    return _name_for_ea(target)


def _target_name_looks_reject(targets: list[int]) -> bool:
    for target in targets:
        lowered = _name_for_ea(target).lower()
        if any(marker in lowered for marker in ("reject", "fail", "error", "invalid", "mismatch")):
            return True
    return False


def _name_for_ea(ea: int) -> str:
    for getter_name in ("get_name", "get_func_name"):
        getter = getattr(idc, getter_name, None)
        if not callable(getter):
            continue
        try:
            name = str(getter(ea) or "").strip()
        except Exception:
            name = ""
        if name:
            return name
    if ida_funcs is not None:
        try:
            return str(ida_funcs.get_func_name(ea) or "").strip()
        except Exception:
            return ""
    return ""

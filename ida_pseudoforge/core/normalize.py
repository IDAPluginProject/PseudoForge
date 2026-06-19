from __future__ import annotations

import re


IDA_TAG_RE = re.compile(r"\x01.|\x02.|\x03.|\x04.|\x05.|\x06.|\x07.|\x08.|\x0f.")
IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def strip_ida_tags(text: str) -> str:
    return IDA_TAG_RE.sub("", text or "")


def extract_identifiers(text: str) -> set[str]:
    return set(IDENTIFIER_RE.findall(text or ""))


def extract_calls(text: str) -> list[str]:
    text = _remove_c_block_comments(text or "")
    keywords = {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "do",
        "else",
    }
    calls = []
    seen = set()
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text or ""):
        name = match.group(1)
        if name in keywords or name in seen:
            continue
        seen.add(name)
        calls.append(name)
    return calls


def extract_call_arguments(text: str, call_name: str) -> list[list[str]]:
    result: list[list[str]] = []
    pattern = re.compile(r"\b%s\s*\(" % re.escape(call_name))
    for match in pattern.finditer(text or ""):
        open_index = match.end() - 1
        close_index = find_matching_paren(text, open_index)
        if close_index < 0:
            continue
        result.append(split_parameters(text[open_index + 1:close_index]))
    return result


def find_matching_paren(text: str, open_index: int) -> int:
    if open_index < 0 or open_index >= len(text) or text[open_index] != "(":
        return -1
    depth = 0
    quote = ""
    escape = False
    index = open_index
    while index < len(text):
        char = text[index]
        if quote:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in "\"'":
            quote = char
            index += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def split_parameters(parameter_text: str) -> list[str]:
    return [item for item, _span in split_parameters_with_spans(parameter_text)]


def split_parameters_with_spans(parameter_text: str) -> list[tuple[str, tuple[int, int]]]:
    params: list[tuple[str, tuple[int, int]]] = []
    current = []
    current_start = 0
    depth = 0
    quote = ""
    escape = False
    for index, char in enumerate(parameter_text):
        if quote:
            current.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            current.append(char)
            continue
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            item = "".join(current).strip()
            if item:
                params.append((item, _trimmed_span(parameter_text, current_start, index)))
            current = []
            current_start = index + 1
            continue
        current.append(char)
    item = "".join(current).strip()
    if item:
        params.append((item, _trimmed_span(parameter_text, current_start, len(parameter_text))))
    return params


def _trimmed_span(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return (start, end)


def extract_function_signature(pseudocode: str) -> str:
    lines = [line.strip() for line in _remove_c_block_comments(pseudocode or "").splitlines()]
    candidate = []
    collecting = False
    depth = 0
    for line in lines:
        if not line:
            continue
        if not collecting:
            if line.startswith(("//", "/*", "*", "#")):
                continue
            if "(" not in line:
                continue
            if re.match(r"^(if|for|while|switch)\b", line):
                continue
            collecting = True
        candidate.append(line)
        depth += line.count("(")
        depth -= line.count(")")
        if collecting and depth <= 0 and (")" in line or line.endswith("{")):
            break
    signature = " ".join(candidate).strip()
    if signature.endswith("{"):
        signature = signature[:-1].strip()
    return signature


def _remove_c_block_comments(text: str) -> str:
    def replacement(match: re.Match[str]) -> str:
        return "\n" * match.group(0).count("\n")

    return re.sub(r"/\*.*?\*/", replacement, text or "", flags=re.DOTALL)


def extract_function_name(signature: str) -> str:
    match = re.search(r"([A-Za-z_][A-Za-z0-9_:~]*)\s*\(", signature or "")
    if not match:
        return ""
    return match.group(1).split("::")[-1]


def extract_parameters_from_signature(signature: str) -> list[tuple[str, str]]:
    if not signature:
        return []
    start = signature.find("(")
    end = signature.rfind(")")
    if start < 0 or end <= start:
        return []
    params = []
    for param in split_parameters(signature[start + 1:end]):
        if param in {"void", "..."}:
            continue
        cleaned = re.sub(r"\b__(in|out|inout|reserved)\b", "", param)
        cleaned = re.sub(r"\b__in(?:_bcount_opt)?\([^)]*\)", "", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?$", cleaned)
        if not name_match:
            continue
        name = name_match.group(1)
        type_text = cleaned[:name_match.start(1)].strip()
        params.append((name, type_text))
    return params


def safe_identifier_replace(text: str, mapping: dict[str, str]) -> str:
    result = text or ""
    for old in sorted(mapping, key=len, reverse=True):
        new = mapping[old]
        if old == new:
            continue
        result = re.sub(r"(?<![.>])\b%s\b" % re.escape(old), new, result)
    return result

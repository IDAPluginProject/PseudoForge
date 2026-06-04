from __future__ import annotations

import re


C_LIKE_HIGHLIGHT_PALETTE = {
    "plain": (212, 212, 212),
    "char": (206, 145, 120),
    "comment": (106, 153, 85),
    "constant": (197, 134, 192),
    "function": (220, 220, 170),
    "keyword": (86, 156, 214),
    "number": (181, 206, 168),
    "preprocessor": (197, 134, 192),
    "string": (206, 145, 120),
    "type": (78, 201, 176),
}

_C_KEYWORDS = {
    "break",
    "case",
    "continue",
    "default",
    "do",
    "else",
    "for",
    "goto",
    "if",
    "return",
    "sizeof",
    "switch",
    "while",
}
_C_TYPE_WORDS = {
    "BOOLEAN",
    "BYTE",
    "CHAR",
    "DWORD",
    "HANDLE",
    "INT",
    "LIST_ENTRY",
    "LONG",
    "LONGLONG",
    "NTSTATUS",
    "PCHAR",
    "PCSTR",
    "PCWSTR",
    "PVOID",
    "SIZE_T",
    "UCHAR",
    "UINT",
    "ULONG",
    "ULONGLONG",
    "USHORT",
    "VOID",
    "WCHAR",
    "WORD",
    "_BYTE",
    "_DWORD",
    "_QWORD",
    "__fastcall",
    "__int16",
    "__int32",
    "__int64",
    "__int8",
    "char",
    "const",
    "enum",
    "int",
    "long",
    "short",
    "signed",
    "static",
    "struct",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
}
_C_CONSTANT_WORDS = {
    "FALSE",
    "NULL",
    "TRUE",
    "false",
    "nullptr",
    "true",
}
_TOKEN_RE = re.compile(
    r"\"(?:\\.|[^\"\\])*\""
    r"|\'(?:\\.|[^\'\\])*\'"
    r"|0[xX][0-9A-Fa-f]+(?:[uUlL]*)"
    r"|\b\d+(?:[uUlL]*)\b"
    r"|[A-Za-z_][A-Za-z0-9_]*"
)


def c_like_highlight_spans(text: str) -> list[tuple[int, int, str]]:
    if not text:
        return []
    spans: list[tuple[int, int, str]] = []
    index = 0
    while index < len(text):
        comment_index = _find_next_comment_start(text, index)
        if comment_index < 0:
            spans.extend(_c_like_code_spans(text, index, len(text)))
            break
        if comment_index > index:
            spans.extend(_c_like_code_spans(text, index, comment_index))
        if text.startswith("//", comment_index):
            spans.append((comment_index, len(text) - comment_index, "comment"))
            break
        end_index = text.find("*/", comment_index + 2)
        if end_index < 0:
            spans.append((comment_index, len(text) - comment_index, "comment"))
            break
        spans.append((comment_index, end_index - comment_index + 2, "comment"))
        index = end_index + 2
    return spans


def _c_like_code_spans(text: str, start_index: int, end_index: int) -> list[tuple[int, int, str]]:
    segment = text[start_index:end_index]
    if not segment:
        return []
    if segment.lstrip().startswith("#"):
        return [(start_index, len(segment), "preprocessor")]

    spans: list[tuple[int, int, str]] = []
    for match in _TOKEN_RE.finditer(segment):
        token = match.group(0)
        role = _token_role(segment, match.start(), match.end(), token)
        if not role:
            continue
        spans.append((start_index + match.start(), match.end() - match.start(), role))
    return spans


def _find_next_comment_start(line: str, start_index: int) -> int:
    quote = ""
    escaped = False
    index = start_index
    while index < len(line) - 1:
        char = line[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if line.startswith("//", index) or line.startswith("/*", index):
            return index
        index += 1
    return -1


def _token_role(segment: str, start: int, end: int, token: str) -> str:
    if token.startswith('"'):
        return "string"
    if token.startswith("'"):
        return "char"
    if token[:1].isdigit() or token.lower().startswith("0x"):
        return "number"
    if token in _C_KEYWORDS:
        return "keyword"
    if token in _C_TYPE_WORDS or token.endswith("_t"):
        return "type"
    if token in _C_CONSTANT_WORDS or token.startswith(("STATUS_", "POOL_FLAG_", "FAST_FAIL_")):
        return "constant"
    if _is_function_like_identifier(segment, end):
        return "function"
    return ""


def _is_function_like_identifier(segment: str, end: int) -> bool:
    index = end
    while index < len(segment) and segment[index].isspace():
        index += 1
    return index < len(segment) and segment[index] == "("

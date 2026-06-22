from __future__ import annotations

from collections.abc import Iterable


def sanitize_generated_comment_text(value: object) -> str:
    text = "" if value is None else str(value)
    text = text.encode("ascii", "backslashreplace").decode("ascii")
    text = text.replace("\r\n", "\\n")
    text = text.replace("\r", "\\r")
    text = text.replace("\n", "\\n")
    text = text.replace("*/", "* /")
    text = text.replace("/*", "/ *")
    return text


def sanitize_generated_block_comment_lines(lines: Iterable[str]) -> list[str]:
    items = list(lines)
    result: list[str] = []
    for index, line in enumerate(items):
        if (index == 0 and line == "/*") or (index == len(items) - 1 and line == "*/"):
            result.append(line)
            continue
        result.append(sanitize_generated_comment_text(line))
    return result

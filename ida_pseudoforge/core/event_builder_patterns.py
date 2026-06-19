from __future__ import annotations

import re


def etw_event_builder_append_counts(text: str, base: str) -> dict[str, int]:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", base or ""):
        return _empty_counts()
    escaped_base = re.escape(base)
    offset_8 = _offset_pattern(0x8)
    offset_10 = _offset_pattern(0x10)
    offset_18 = _offset_pattern(0x18)
    return {
        "payload_buffer_targets": len(
            re.findall(
                r"\*\s*\(\s*[^)]*\*\s*\)\s*\(\s*%s\s*\+\s*%s(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)\s*\+"
                % (escaped_base, offset_8),
                text or "",
                flags=re.IGNORECASE,
            )
        ),
        "descriptor_table_slots": len(
            re.findall(
                r"\*\s*\(\s*[^)]*\*\s*\)\s*%s\b\s*\+\s*16(?:i64|LL|ULL|uLL|UL|U|L)?\s*\*\s*"
                r"\*\s*\(\s*unsigned\s+int\s*\*\s*\)\s*\(\s*%s\s*\+\s*%s(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
                % (escaped_base, escaped_base, offset_10),
                text or "",
                flags=re.IGNORECASE,
            )
        ),
        "item_count_updates": len(
            re.findall(
                r"\+\+\s*\*\s*\(\s*_DWORD\s*\*\s*\)\s*\(\s*%s\s*\+\s*%s(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
                r"|\*\s*\(\s*_DWORD\s*\*\s*\)\s*\(\s*%s\s*\+\s*%s(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)\s*(?:\+\+|\+=|=)"
                % (escaped_base, offset_10, escaped_base, offset_10),
                text or "",
                flags=re.IGNORECASE,
            )
        ),
        "payload_offset_updates": len(
            re.findall(
                r"\*\s*\(\s*_DWORD\s*\*\s*\)\s*\(\s*%s\s*\+\s*%s(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)\s*(?:\+=|=)"
                % (escaped_base, offset_18),
                text or "",
                flags=re.IGNORECASE,
            )
        ),
    }


def _empty_counts() -> dict[str, int]:
    return {
        "payload_buffer_targets": 0,
        "descriptor_table_slots": 0,
        "item_count_updates": 0,
        "payload_offset_updates": 0,
    }


def _offset_pattern(offset: int) -> str:
    return r"(?:0x%X|0x%x|%d)" % (offset, offset, offset)

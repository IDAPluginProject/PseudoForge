from __future__ import annotations


DEFAULT_HELPER_DEPTH = 2
MIN_HELPER_DEPTH = 2
MAX_HELPER_DEPTH = 4


def parse_helper_depth(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        depth = int(text, 10)
    except ValueError:
        return None
    if depth < MIN_HELPER_DEPTH or depth > MAX_HELPER_DEPTH:
        return None
    return depth


def normalize_helper_depth(value: object | None) -> int:
    depth = parse_helper_depth(value)
    if depth is None:
        return DEFAULT_HELPER_DEPTH
    return depth


def helper_capture_limit_for_depth(depth: int) -> int:
    normalized = normalize_helper_depth(depth)
    return {
        2: 12,
        3: 32,
        4: 64,
    }[normalized]


def helper_depth_range_text() -> str:
    return "%d-%d" % (MIN_HELPER_DEPTH, MAX_HELPER_DEPTH)

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.errors import KernelCorpusError, QueryError

CANONICAL_STORE_SCHEMA_VERSION = "kernel_corpus_canonical_store_v1"
CANONICAL_DIR_NAME = "canonical-answers"
DEFAULT_MAX_TOPICS = 20
MAX_TOPICS = 200
DEFAULT_TEXT_CHARS = 12000
MAX_TEXT_CHARS = 50000
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2}
STATUS_ORDER = {"pass": 0, "degraded": 1, "fail": 2, "missing": 3}
SAFE_TOPIC_RE = re.compile(r"^[a-z0-9][a-z0-9_]*$")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            payload = list_canonical_answers(
                args.pack_root,
                priority=args.priority,
                status=args.status,
                mode=args.mode,
                max_topics=args.max_topics,
            )
        elif args.command == "get":
            payload = get_canonical_answer(
                args.pack_root,
                args.topic,
                include_answer=not args.no_answer,
                include_quality=args.quality,
                include_gaps=args.gaps,
                max_chars=args.max_chars,
            )
        elif args.command == "report":
            payload = get_canonical_quality_report(
                args.pack_root,
                priority=args.priority,
                status=args.status,
                max_topics=args.max_topics,
                max_chars=args.max_chars,
            )
        elif args.command == "find":
            payload = find_canonical_answers(
                args.pack_root,
                args.query,
                priority=args.priority,
                status=args.status,
                max_topics=args.max_topics,
            )
        else:
            raise QueryError("Unsupported canonical store command: %s" % args.command)
    except (OSError, KernelCorpusError, ValueError, json.JSONDecodeError) as exc:
        print("Kernel canonical store failed: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def list_canonical_answers(
    pack_root: str | Path,
    *,
    priority: str | list[str] | tuple[str, ...] | None = None,
    status: str | list[str] | tuple[str, ...] | None = None,
    mode: str | None = None,
    max_topics: int = DEFAULT_MAX_TOPICS,
) -> dict[str, Any]:
    state = _load_state(pack_root)
    limit = _bounded_int(max_topics, DEFAULT_MAX_TOPICS, MAX_TOPICS)
    topics = _filter_topics(
        state["topics"],
        priority=priority,
        status=status,
        mode=mode,
    )
    return _base_payload(state) | {
        "topic_count": len(topics),
        "returned_count": min(len(topics), limit),
        "max_topics": limit,
        "topics": [topic["metadata"] for topic in topics[:limit]],
    }


def get_canonical_answer(
    pack_root: str | Path,
    topic_id: str,
    *,
    include_answer: bool = True,
    include_quality: bool = True,
    include_gaps: bool = True,
    max_chars: int = DEFAULT_TEXT_CHARS,
) -> dict[str, Any]:
    _validate_topic_id(topic_id)
    state = _load_state(pack_root)
    topic = _topic_by_id(state, topic_id)
    if topic is None:
        raise QueryError("Canonical topic was not found: %s" % topic_id)
    budget = _bounded_int(max_chars, DEFAULT_TEXT_CHARS, MAX_TEXT_CHARS)
    sections: dict[str, Any] = {}
    remaining = budget
    for key, include in (
        ("answer", include_answer),
        ("quality", include_quality),
        ("gaps", include_gaps),
    ):
        if not include:
            continue
        section = _read_bounded_section(topic, key, remaining)
        sections[key] = section
        remaining = max(0, remaining - len(section.get("text", "")))
    truncated = any(bool(item.get("truncated")) for item in sections.values())
    truncated = truncated or any(bool(item.get("omitted_due_to_limit")) for item in sections.values())
    return _base_payload(state) | {
        "metadata": topic["metadata"],
        "content": sections,
        "max_chars": budget,
        "returned_chars": sum(len(str(item.get("text", ""))) for item in sections.values()),
        "truncated": truncated,
    }


def get_canonical_quality_report(
    pack_root: str | Path,
    *,
    priority: str | list[str] | tuple[str, ...] | None = None,
    status: str | list[str] | tuple[str, ...] | None = None,
    max_topics: int = DEFAULT_MAX_TOPICS,
    max_chars: int = DEFAULT_TEXT_CHARS,
) -> dict[str, Any]:
    state = _load_state(pack_root)
    topic_limit = _bounded_int(max_topics, DEFAULT_MAX_TOPICS, MAX_TOPICS)
    text_limit = _bounded_int(max_chars, DEFAULT_TEXT_CHARS, MAX_TEXT_CHARS)
    topics = _filter_topics(state["topics"], priority=priority, status=status, mode=None)
    report_md_path = state["canonical_root"] / "quality-report.md"
    markdown = ""
    markdown_truncated = False
    if report_md_path.is_file():
        markdown = report_md_path.read_text(encoding="utf-8", errors="replace")
        markdown_truncated = len(markdown) > text_limit
        markdown = markdown[:text_limit]
    else:
        state["warnings"].append("Canonical quality report Markdown is missing: %s" % report_md_path)
    counts = _status_counts(topics)
    return _base_payload(state) | {
        "report": {
            "path": _path_payload(state["canonical_root"] / "quality-report.json"),
            "markdown_path": _path_payload(report_md_path),
            "topic_count": len(topics),
            "pass_count": counts.get("pass", 0),
            "degraded_count": counts.get("degraded", 0),
            "fail_count": counts.get("fail", 0),
            "missing_count": counts.get("missing", 0),
        },
        "topics": [topic["metadata"] for topic in topics[:topic_limit]],
        "returned_count": min(len(topics), topic_limit),
        "max_topics": topic_limit,
        "markdown": markdown,
        "max_chars": text_limit,
        "truncated": markdown_truncated,
    }


def find_canonical_answers(
    pack_root: str | Path,
    query: str,
    *,
    priority: str | list[str] | tuple[str, ...] | None = None,
    status: str | list[str] | tuple[str, ...] | None = None,
    max_topics: int = DEFAULT_MAX_TOPICS,
) -> dict[str, Any]:
    query_text = str(query or "").strip()
    if not query_text:
        raise QueryError("Canonical answer query is required")
    state = _load_state(pack_root)
    limit = _bounded_int(max_topics, DEFAULT_MAX_TOPICS, MAX_TOPICS)
    terms = _query_terms(query_text)
    candidates = []
    for topic in _filter_topics(state["topics"], priority=priority, status=status, mode=None):
        score, fields = _match_topic(topic, terms)
        if score <= 0:
            continue
        metadata = dict(topic["metadata"])
        metadata["match_score"] = score
        metadata["match_fields"] = fields
        candidates.append(metadata)
    candidates.sort(
        key=lambda item: (
            -int(item.get("match_score", 0) or 0),
            STATUS_ORDER.get(str(item.get("quality", {}).get("status", "missing")), 99),
            int(item.get("quality", {}).get("validation_warning_count", 999) or 999),
            _priority_rank(str(item.get("priority", ""))),
            str(item.get("topic_id", "")),
        )
    )
    return _base_payload(state) | {
        "query": query_text,
        "result_count": len(candidates),
        "returned_count": min(len(candidates), limit),
        "max_topics": limit,
        "results": candidates[:limit],
    }


def _load_state(pack_root: str | Path) -> dict[str, Any]:
    root = Path(pack_root)
    canonical_root = root / CANONICAL_DIR_NAME
    warnings: list[str] = []
    topics: list[dict[str, Any]] = []
    root_quality = _read_json_object(canonical_root / "quality-report.json", warnings)
    quality_by_topic = {
        str(item.get("topic_id", "") or ""): item
        for item in root_quality.get("topics", [])
        if isinstance(item, dict) and str(item.get("topic_id", "") or "")
    }
    if not canonical_root.is_dir():
        warnings.append("Canonical answer root does not exist: %s" % canonical_root)
        return {
            "pack_root": root,
            "canonical_root": canonical_root,
            "root_quality": root_quality,
            "warnings": warnings,
            "topics": topics,
        }
    for topic_dir, priority, topic_id in _discover_topic_dirs(canonical_root):
        topics.append(_load_topic(canonical_root, topic_dir, priority, topic_id, quality_by_topic, warnings))
    topics.sort(key=lambda item: (_priority_rank(item["metadata"]["priority"]), item["metadata"]["topic_id"]))
    return {
        "pack_root": root,
        "canonical_root": canonical_root,
        "root_quality": root_quality,
        "warnings": warnings,
        "topics": topics,
    }


def _discover_topic_dirs(canonical_root: Path) -> list[tuple[Path, str, str]]:
    discovered: dict[str, tuple[Path, str, str]] = {}
    index = _read_json_object(canonical_root / "index.json", [])
    for item in index.get("topics", []) if isinstance(index.get("topics"), list) else []:
        if not isinstance(item, dict):
            continue
        topic_id = str(item.get("id", "") or "")
        priority = str(item.get("priority", "") or "")
        if not _is_safe_topic_id(topic_id) or not priority:
            continue
        directory = Path(str(item.get("directory", "") or ""))
        if directory.is_dir() and not _is_inside(directory, canonical_root):
            directory = canonical_root / priority / topic_id
        elif not directory.is_dir():
            directory = canonical_root / priority / topic_id
        if directory.is_dir():
            discovered[topic_id] = (directory, priority, topic_id)
    for priority_dir in sorted(canonical_root.iterdir(), key=lambda item: item.name.lower()):
        if not priority_dir.is_dir() or not re.match(r"^P[0-9]+$", priority_dir.name):
            continue
        for topic_dir in sorted(priority_dir.iterdir(), key=lambda item: item.name.lower()):
            if topic_dir.is_dir() and _is_safe_topic_id(topic_dir.name):
                discovered.setdefault(topic_dir.name, (topic_dir, priority_dir.name, topic_dir.name))
    return sorted(discovered.values(), key=lambda item: (_priority_rank(item[1]), item[2]))


def _load_topic(
    canonical_root: Path,
    topic_dir: Path,
    fallback_priority: str,
    fallback_topic_id: str,
    quality_by_topic: dict[str, dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any]:
    manifest = _read_json_object(topic_dir / "manifest.json", warnings)
    topic_payload = manifest.get("topic", {}) if isinstance(manifest.get("topic"), dict) else {}
    topic_id = str(topic_payload.get("id", "") or fallback_topic_id)
    if not _is_safe_topic_id(topic_id):
        warnings.append("Canonical manifest topic id is not safe; using directory topic id: %s" % topic_dir)
        topic_id = fallback_topic_id
    priority = str(topic_payload.get("priority", "") or fallback_priority)
    quality = _topic_quality(topic_dir, topic_id, manifest, quality_by_topic, warnings)
    validation = _read_json_object(topic_dir / "validation.json", warnings)
    evidence = _read_json_object(topic_dir / "evidence-pack.json", warnings)
    major_functions = _major_function_names(evidence, topic_dir, warnings)
    metadata = {
        "topic_id": topic_id,
        "priority": priority,
        "mode": str(topic_payload.get("mode", "") or quality.get("mode", "")),
        "title": str(topic_payload.get("title", "") or topic_id),
        "question": str(topic_payload.get("question", "")),
        "directory": _path_payload(topic_dir),
        "paths": _topic_paths(topic_dir),
        "quality": {
            "status": str(quality.get("status", "missing") or "missing"),
            "score": quality.get("score", None),
            "validation_warning_count": _int_value(
                quality.get("validation_warning_count"),
                _int_value(validation.get("warning_count"), 0),
            ),
            "selected_function_count": _int_value(
                quality.get("selected_function_count"),
                _int_value(evidence.get("summary", {}).get("selected_function_count") if isinstance(evidence.get("summary"), dict) else None, 0),
            ),
            "edge_count": _int_value(
                quality.get("edge_count"),
                _int_value(evidence.get("summary", {}).get("edge_count") if isinstance(evidence.get("summary"), dict) else None, 0),
            ),
            "gap_count": _int_value(quality.get("gap_count"), 0),
        },
        "source_index_sha256": str(manifest.get("source_index_sha256", "")),
        "pack_generated_at": str(manifest.get("pack_generated_at", "")),
        "major_functions": major_functions[:16],
    }
    return {
        "metadata": metadata,
        "manifest": manifest,
        "quality": quality,
        "validation": validation,
        "evidence": evidence,
        "directory": topic_dir,
        "canonical_root": canonical_root,
    }


def _topic_quality(
    topic_dir: Path,
    topic_id: str,
    manifest: dict[str, Any],
    quality_by_topic: dict[str, dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any]:
    local = _read_json_object(topic_dir / "quality.json", warnings)
    if local:
        return local
    if topic_id in quality_by_topic:
        return quality_by_topic[topic_id]
    validation = manifest.get("validation", {}) if isinstance(manifest.get("validation"), dict) else {}
    status = "pass" if validation.get("passed") else "missing"
    return {
        "topic_id": topic_id,
        "status": status,
        "score": None,
        "validation_warning_count": _int_value(validation.get("warning_count"), 0),
    }


def _filter_topics(
    topics: list[dict[str, Any]],
    *,
    priority: str | list[str] | tuple[str, ...] | None,
    status: str | list[str] | tuple[str, ...] | None,
    mode: str | None,
) -> list[dict[str, Any]]:
    priority_filter = _value_filter(priority, upper=True)
    status_filter = _value_filter(status, upper=False)
    mode_text = str(mode or "").strip().lower()
    result = []
    for topic in topics:
        metadata = topic["metadata"]
        quality = metadata.get("quality", {}) if isinstance(metadata.get("quality"), dict) else {}
        if priority_filter and str(metadata.get("priority", "")).upper() not in priority_filter:
            continue
        if status_filter and str(quality.get("status", "")).lower() not in status_filter:
            continue
        if mode_text and str(metadata.get("mode", "")).lower() != mode_text:
            continue
        result.append(topic)
    return result


def _topic_by_id(state: dict[str, Any], topic_id: str) -> dict[str, Any] | None:
    for topic in state["topics"]:
        if topic["metadata"]["topic_id"] == topic_id:
            return topic
    return None


def _read_bounded_section(topic: dict[str, Any], key: str, max_chars: int) -> dict[str, Any]:
    path = _artifact_path(topic["directory"], key)
    section = {
        "path": _path_payload(path),
        "exists": path.is_file(),
        "text": "",
        "truncated": False,
        "omitted_due_to_limit": max_chars <= 0,
    }
    if not path.is_file() or max_chars <= 0:
        return section
    text = path.read_text(encoding="utf-8", errors="replace")
    section["truncated"] = len(text) > max_chars
    section["text"] = text[:max_chars]
    return section


def _artifact_path(topic_dir: Path, key: str) -> Path:
    filenames = {
        "answer": "answer.md",
        "quality": "quality.md",
        "gaps": "gaps.md",
        "source_map": "source-map.md",
        "trace": "trace.json",
        "evidence_pack": "evidence-pack.json",
        "validation": "validation.json",
        "manifest": "manifest.json",
    }
    if key not in filenames:
        raise QueryError("Unsupported canonical artifact selector: %s" % key)
    path = (topic_dir / filenames[key]).resolve()
    root = topic_dir.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise QueryError("Canonical artifact path escaped topic directory: %s" % key) from exc
    return path


def _topic_paths(topic_dir: Path) -> dict[str, str]:
    return {
        key: _path_payload(_artifact_path(topic_dir, key))
        for key in ("manifest", "answer", "quality", "gaps", "source_map", "trace", "evidence_pack", "validation")
    }


def _match_topic(topic: dict[str, Any], terms: list[str]) -> tuple[int, list[str]]:
    metadata = topic["metadata"]
    fields: dict[str, str] = {
        "topic_id": str(metadata.get("topic_id", "")),
        "title": str(metadata.get("title", "")),
        "question": str(metadata.get("question", "")),
        "priority": str(metadata.get("priority", "")),
        "status": str(metadata.get("quality", {}).get("status", "")) if isinstance(metadata.get("quality"), dict) else "",
        "major_functions": " ".join(str(item) for item in metadata.get("major_functions", [])),
        "answer_heading": _first_heading(_artifact_path(topic["directory"], "answer")),
        "source_map": _read_prefix(_artifact_path(topic["directory"], "source_map"), 6000),
    }
    score = 0
    hits = []
    for field, value in fields.items():
        lower_value = value.lower()
        matched = [term for term in terms if term in lower_value]
        if matched:
            hits.append(field)
            score += len(matched) * _field_weight(field)
    quality = metadata.get("quality", {}) if isinstance(metadata.get("quality"), dict) else {}
    if str(quality.get("status", "")).lower() == "pass":
        score += 6
    if _int_value(quality.get("validation_warning_count"), 999) == 0:
        score += 3
    return score, sorted(set(hits))


def _query_terms(query: str) -> list[str]:
    raw = re.findall(r"[a-zA-Z0-9_]+", query.lower())
    terms = [item for item in raw if len(item) >= 2]
    collapsed = query.lower().strip()
    if collapsed and collapsed not in terms:
        terms.append(collapsed)
    return terms


def _field_weight(field: str) -> int:
    return {
        "topic_id": 10,
        "title": 8,
        "question": 7,
        "major_functions": 7,
        "answer_heading": 5,
        "source_map": 3,
        "status": 2,
        "priority": 1,
    }.get(field, 1)


def _first_heading(path: Path) -> str:
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:40]:
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped
    return ""


def _read_prefix(path: Path, max_chars: int) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:max_chars]


def _major_function_names(evidence: dict[str, Any], topic_dir: Path, warnings: list[str]) -> list[str]:
    names = []
    if isinstance(evidence.get("functions"), list):
        names.extend(str(item.get("name", "")) for item in evidence["functions"] if isinstance(item, dict))
    if isinstance(evidence.get("phases"), list):
        for phase in evidence["phases"]:
            if not isinstance(phase, dict) or not isinstance(phase.get("functions"), list):
                continue
            names.extend(str(item.get("name", "")) for item in phase["functions"] if isinstance(item, dict))
    trace = _read_json_object(topic_dir / "trace.json", warnings)
    if isinstance(trace.get("selected_candidates"), list):
        names.extend(str(item.get("name", "")) for item in trace["selected_candidates"] if isinstance(item, dict))
    return _unique([name for name in names if name])[:32]


def _read_json_object(path: Path, warnings: list[str]) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append("Could not read JSON file %s: %s" % (path, exc))
        return {}
    if not isinstance(data, dict):
        warnings.append("JSON file is not an object: %s" % path)
        return {}
    return data


def _base_payload(state: dict[str, Any]) -> dict[str, Any]:
    pack_root = state["pack_root"]
    canonical_root = state["canonical_root"]
    return {
        "ok": True,
        "schema_version": CANONICAL_STORE_SCHEMA_VERSION,
        "pack_root": _path_payload(pack_root),
        "canonical_root": _path_payload(canonical_root),
        "warnings": list(state["warnings"]),
    }


def _status_counts(topics: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for topic in topics:
        quality = topic["metadata"].get("quality", {})
        status = str(quality.get("status", "missing") if isinstance(quality, dict) else "missing")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _path_payload(path: Path) -> str:
    return str(path.resolve())


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _bounded_int(value: Any, default: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    if result <= 0:
        result = default
    return min(result, maximum)


def _int_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _value_filter(value: str | list[str] | tuple[str, ...] | None, *, upper: bool) -> set[str]:
    if value in (None, ""):
        return set()
    raw_values = [value] if isinstance(value, str) else list(value)
    result = set()
    for item in raw_values:
        text = str(item or "").strip()
        if not text:
            continue
        result.add(text.upper() if upper else text.lower())
    return result


def _priority_rank(priority: str) -> int:
    return PRIORITY_ORDER.get(priority, 99)


def _is_safe_topic_id(topic_id: str) -> bool:
    return bool(SAFE_TOPIC_RE.match(str(topic_id or "")))


def _validate_topic_id(topic_id: str) -> None:
    if not _is_safe_topic_id(topic_id):
        raise QueryError("Canonical topic id must be an identifier, not a path: %s" % topic_id)


def _unique(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect generated Kernel Corpus canonical answer artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List canonical answers.")
    _add_common_filters(list_parser)

    get_parser = subparsers.add_parser("get", help="Return one bounded canonical answer artifact.")
    get_parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    get_parser.add_argument("--topic", required=True, help="Canonical topic id.")
    get_parser.add_argument("--no-answer", action="store_true", help="Do not include answer.md text.")
    get_parser.add_argument("--quality", action="store_true", help="Include quality.md text.")
    get_parser.add_argument("--gaps", action="store_true", help="Include gaps.md text.")
    get_parser.add_argument("--max-chars", type=int, default=DEFAULT_TEXT_CHARS, help="Maximum total text characters.")

    report_parser = subparsers.add_parser("report", help="Return canonical quality report metadata and bounded Markdown.")
    _add_common_filters(report_parser)
    report_parser.add_argument("--max-chars", type=int, default=DEFAULT_TEXT_CHARS, help="Maximum Markdown characters.")

    find_parser = subparsers.add_parser("find", help="Find canonical answers by query.")
    _add_common_filters(find_parser)
    find_parser.add_argument("--query", required=True, help="Search query.")
    return parser


def _add_common_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    parser.add_argument("--priority", default="", choices=("", "P0", "P1", "P2"), help="Optional priority filter.")
    parser.add_argument("--status", default="", choices=("", "pass", "degraded", "fail", "missing"), help="Optional quality status filter.")
    parser.add_argument("--mode", default="", choices=("", "focused", "lifecycle"), help="Optional topic mode filter.")
    parser.add_argument("--max-topics", type=int, default=DEFAULT_MAX_TOPICS, help="Maximum topics to return.")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())

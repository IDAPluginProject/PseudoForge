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

from tools.kernel_corpus.atlas import ATLAS_DIR_PARTS, SUBSYSTEMS
from tools.kernel_corpus.canonical_store import MAX_TOPICS as MAX_CANONICAL_TOPICS
from tools.kernel_corpus.canonical_store import list_canonical_answers
from tools.kernel_corpus.errors import KernelCorpusError, QueryError
from tools.kernel_corpus.lifecycle import load_ontology
from tools.kernel_corpus.query import corpus_status, find_functions_by_name, search_functions

ANSWER_PLAN_SCHEMA_VERSION = "kernel_corpus_answer_plan_v1"
CANONICAL_TOPICS_PATH = Path(__file__).with_name("canonical_topics.json")
DEFAULT_MAX_TOPICS = 5
MAX_TOPICS = 20
DEFAULT_FUNCTION_LIMIT = 12
MAX_FUNCTION_NAMES = 16
STATUS_ORDER = {"pass": 0, "degraded": 1, "fail": 2, "missing": 3}
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2}
FUNCTION_NAME_RE = re.compile(r"\b(?:Nt|Zw|Ps|Psp|Mm|Mi|Ob|Obp|Ke|Ki|Io|Iop|Ex|Se|Sep|Cm|Cmp|Etw|Etwp|Wmi|Wmip)[A-Za-z0-9_]{2,}\b")
SAFE_PLAN_TOPIC_RE = re.compile(r"[^A-Za-z0-9_]+")
QUERY_STOPWORDS = {
    "a",
    "an",
    "and",
    "as",
    "by",
    "explain",
    "for",
    "from",
    "how",
    "in",
    "of",
    "or",
    "the",
    "through",
    "to",
    "using",
    "with",
}

KOREAN_QUERY_MAP: tuple[dict[str, Any], ...] = (
    {
        "id": "process_lifecycle",
        "required_korean": ("프로세스",),
        "korean": ("프로세스", "생성", "종료", "삭제", "사라", "수명", "라이프사이클"),
        "terms": ("process", "process object", "process lifecycle", "create process", "exit process", "delete process", "rundown process"),
        "lifecycle_topics": ("process_object",),
        "atlas_pages": ("process",),
        "tags": ("process_thread", "object_manager"),
    },
    {
        "id": "thread_lifecycle",
        "required_korean": ("스레드", "쓰레드"),
        "korean": ("스레드", "쓰레드", "생성", "종료", "삭제", "수명", "라이프사이클"),
        "terms": ("thread", "thread object", "create thread", "exit thread", "delete thread"),
        "lifecycle_topics": ("thread_object",),
        "atlas_pages": ("process",),
        "tags": ("process_thread",),
    },
    {
        "id": "file_object",
        "required_korean": ("파일",),
        "korean": ("파일", "오브젝트", "닫기", "삭제"),
        "terms": ("file object", "create file", "close file", "delete file", "NtCreateFile"),
        "lifecycle_topics": ("file_object",),
        "atlas_pages": ("io-manager",),
        "tags": ("file", "io_manager"),
    },
    {
        "id": "driver_object",
        "required_korean": ("드라이버", "DriverEntry"),
        "korean": ("드라이버", "로드", "언로드", "DriverEntry"),
        "terms": ("driver object", "load driver", "unload driver", "DriverEntry"),
        "lifecycle_topics": ("driver_object",),
        "atlas_pages": ("driver-load-unload", "io-manager"),
        "tags": ("driver", "image_load"),
    },
    {
        "id": "device_object",
        "required_korean": ("디바이스", "장치", "device"),
        "korean": ("디바이스", "장치", "device"),
        "terms": ("device object", "IoCreateDevice", "IoDeleteDevice", "device stack"),
        "lifecycle_topics": ("device_object",),
        "atlas_pages": ("io-manager",),
        "tags": ("io_manager", "driver_framework"),
    },
    {
        "id": "memory",
        "required_korean": ("메모리", "풀", "매핑", "복사", "가상 메모리"),
        "korean": ("메모리", "풀", "매핑", "복사", "가상 메모리"),
        "terms": ("memory", "pool", "map view", "virtual memory", "copy virtual memory", "MmCopyVirtualMemory"),
        "lifecycle_topics": ("section_object",),
        "atlas_pages": ("memory",),
        "tags": ("memory",),
    },
    {
        "id": "registry",
        "required_korean": ("레지스트리", "하이브"),
        "korean": ("레지스트리", "키", "하이브"),
        "terms": ("registry", "registry key", "NtCreateKey", "ZwQueryValueKey", "ZwSetValueKey"),
        "lifecycle_topics": ("registry_key",),
        "atlas_pages": ("registry",),
        "tags": ("registry", "configuration_manager"),
    },
    {
        "id": "security",
        "required_korean": ("보안", "토큰", "권한", "접근", "핸들"),
        "korean": ("보안", "토큰", "권한", "접근", "핸들"),
        "terms": ("security", "token", "privilege", "access check", "handle", "NtOpenProcess"),
        "lifecycle_topics": (),
        "atlas_pages": ("security", "object-manager"),
        "tags": ("security", "object_manager"),
    },
    {
        "id": "callback_notify",
        "required_korean": ("콜백", "노티", "노티파이", "notify", "callback"),
        "korean": ("콜백", "노티", "노티파이", "notify", "callback"),
        "terms": ("callback", "notify", "PsSetCreateProcessNotifyRoutine", "PspCallProcessNotifyRoutines"),
        "lifecycle_topics": (),
        "atlas_pages": ("process", "driver-load-unload"),
        "tags": ("callback",),
    },
)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        payload = build_answer_plan(
            args.pack_root,
            args.question,
            max_topics=args.max_topics,
            allow_degraded=bool(args.allow_degraded),
        )
        if args.plan_out:
            payload["plan_out"] = write_plan(payload, args.plan_out, requested_format=args.format)
    except (OSError, KernelCorpusError, ValueError, json.JSONDecodeError) as exc:
        print("Kernel answer planner failed: %s" % exc, file=sys.stderr)
        return 1
    if args.format == "markdown":
        print(render_markdown_plan(payload))
    elif args.format == "text":
        print(render_text_plan(payload))
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def build_answer_plan(
    pack_root: str | Path,
    question: str,
    *,
    max_topics: int = DEFAULT_MAX_TOPICS,
    allow_degraded: bool = False,
) -> dict[str, Any]:
    question_text = str(question or "").strip()
    if not question_text:
        raise QueryError("Question is required")
    root = Path(pack_root)
    status = corpus_status(root)
    warnings = _coerce_warnings(status)
    limit = _bounded_int(max_topics, DEFAULT_MAX_TOPICS, MAX_TOPICS)
    topic_defs = _load_canonical_topic_defs(warnings)
    routing = _build_routing(question_text, warnings)
    canonical_pool = _rank_canonical_candidates(
        root,
        question_text,
        routing,
        topic_defs,
        warnings,
    )
    eligible: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for candidate in canonical_pool:
        status_text = str(candidate.get("quality", {}).get("status", "missing")).lower()
        if status_text == "pass" or (allow_degraded and status_text == "degraded"):
            candidate["selection_state"] = "selected"
            candidate["use_policy"] = "canonical_first" if status_text == "pass" else "canonical_with_caveats"
            eligible.append(candidate)
        else:
            candidate["selection_state"] = "excluded"
            candidate["use_policy"] = _excluded_policy(status_text)
            excluded.append(candidate)
            if status_text == "degraded" and not allow_degraded:
                warnings.append("Degraded canonical topic excluded by default: %s" % candidate.get("topic_id", ""))
    selected = eligible[:limit]
    excluded = excluded[:limit]
    live_steps = _build_live_steps(root, question_text, routing, selected, excluded, warnings)
    if not selected and not live_steps:
        warnings.append("No canonical or live retrieval route was found; use corpus_status and broad search before answering.")
    payload = {
        "schema": ANSWER_PLAN_SCHEMA_VERSION,
        "ok": True,
        "question": question_text,
        "pack_root": _path_payload(root),
        "allow_degraded": bool(allow_degraded),
        "max_topics": limit,
        "pack_freshness": _freshness_payload(root, status),
        "routing": routing,
        "canonical_candidate_count": len(eligible),
        "canonical_candidates": selected,
        "canonical_candidates_truncated": len(eligible) > len(selected),
        "excluded_canonical_candidates": excluded,
        "excluded_canonical_candidates_truncated": len([item for item in canonical_pool if item.get("selection_state") == "excluded"]) > len(excluded),
        "live_retrieval_steps": live_steps,
        "recommended_mcp_calls": _recommended_mcp_calls(live_steps, selected),
        "citation_contract": _citation_contract(selected, live_steps),
        "final_answer_outline": _final_answer_outline(routing, selected),
        "stop_conditions": _stop_conditions(selected, excluded, live_steps),
        "warnings": _unique(warnings),
    }
    return payload


def write_plan(payload: dict[str, Any], plan_out: str | Path, *, requested_format: str = "json") -> str:
    pack_root = Path(str(payload.get("pack_root", "") or ""))
    path = Path(plan_out)
    if not path.is_absolute():
        path = pack_root / path
    _require_inside(path, pack_root, "Answer plan output")
    path.parent.mkdir(parents=True, exist_ok=True)
    suffix = path.suffix.lower()
    if suffix == ".md":
        text = render_markdown_plan(payload)
    elif suffix == ".txt":
        text = render_text_plan(payload)
    elif suffix == ".json":
        text = json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    elif requested_format == "markdown":
        text = render_markdown_plan(payload)
    elif requested_format == "text":
        text = render_text_plan(payload)
    else:
        text = json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    return _path_payload(path)


def render_text_plan(payload: dict[str, Any]) -> str:
    lines = [
        "Kernel answer plan",
        "question: %s" % payload.get("question", ""),
        "pack_root: %s" % payload.get("pack_root", ""),
        "freshness: %s" % payload.get("pack_freshness", {}).get("recommendation", ""),
        "",
        "canonical candidates:",
    ]
    for candidate in payload.get("canonical_candidates", []):
        lines.append(
            "- %s quality=%s score=%s policy=%s"
            % (
                candidate.get("topic_id", ""),
                candidate.get("quality", {}).get("status", ""),
                candidate.get("route_score", 0),
                candidate.get("use_policy", ""),
            )
        )
    if not payload.get("canonical_candidates"):
        lines.append("- none")
    lines.append("")
    lines.append("live retrieval steps:")
    for step in payload.get("live_retrieval_steps", []):
        lines.append("- %s: %s %s" % (step.get("order", 0), step.get("mcp_tool", ""), step.get("purpose", "")))
    return "\n".join(lines).rstrip()


def render_markdown_plan(payload: dict[str, Any]) -> str:
    lines = [
        "# Kernel Answer Plan",
        "",
        "- Schema: `%s`" % payload.get("schema", ""),
        "- Question: `%s`" % payload.get("question", ""),
        "- Pack root: `%s`" % payload.get("pack_root", ""),
        "- Freshness: `%s`" % payload.get("pack_freshness", {}).get("recommendation", ""),
        "- Allow degraded canonical topics: `%s`" % payload.get("allow_degraded", False),
        "",
        "## Canonical Candidates",
        "",
    ]
    candidates = [item for item in payload.get("canonical_candidates", []) if isinstance(item, dict)]
    if not candidates:
        lines.extend(["- None", ""])
    else:
        for candidate in candidates:
            lines.append(
                "- `%s` `%s` quality=`%s` warnings=`%s` score=`%s` policy=`%s`"
                % (
                    candidate.get("priority", ""),
                    candidate.get("topic_id", ""),
                    candidate.get("quality", {}).get("status", ""),
                    candidate.get("quality", {}).get("validation_warning_count", 0),
                    candidate.get("route_score", 0),
                    candidate.get("use_policy", ""),
                )
            )
        lines.append("")
    excluded = [item for item in payload.get("excluded_canonical_candidates", []) if isinstance(item, dict)]
    lines.extend(["## Excluded Canonical Hints", ""])
    if not excluded:
        lines.extend(["- None", ""])
    else:
        for candidate in excluded:
            lines.append(
                "- `%s` quality=`%s` policy=`%s`"
                % (
                    candidate.get("topic_id", ""),
                    candidate.get("quality", {}).get("status", ""),
                    candidate.get("use_policy", ""),
                )
            )
        lines.append("")
    lines.extend(["## Live Retrieval Steps", ""])
    for step in payload.get("live_retrieval_steps", []):
        lines.append("- `%s` `%s`: %s" % (step.get("order", 0), step.get("mcp_tool", ""), step.get("purpose", "")))
        if step.get("fallback_cli"):
            lines.append("  - Fallback: `%s`" % step.get("fallback_cli"))
    if not payload.get("live_retrieval_steps"):
        lines.append("- None")
    lines.extend(["", "## Citation Contract", ""])
    for item in payload.get("citation_contract", {}).get("required", []):
        lines.append("- %s" % item)
    lines.extend(["", "## Stop Conditions", ""])
    for item in payload.get("stop_conditions", []):
        lines.append("- %s" % item)
    warnings = [str(item) for item in payload.get("warnings", []) if str(item)]
    if warnings:
        lines.extend(["", "## Warnings", ""])
        for warning in warnings[:20]:
            lines.append("- %s" % warning)
    return "\n".join(lines).rstrip() + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan evidence retrieval for a Kernel Corpus answer without drafting the answer.")
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    parser.add_argument("--question", required=True, help="Natural-language kernel question.")
    parser.add_argument("--max-topics", type=int, default=DEFAULT_MAX_TOPICS, help="Maximum selected canonical topics.")
    parser.add_argument("--allow-degraded", action="store_true", help="Allow degraded canonical topics as selected evidence with caveats.")
    parser.add_argument("--format", choices=["json", "text", "markdown"], default="json", help="Output format.")
    parser.add_argument("--plan-out", default="", help="Optional generated plan output path under the pack root.")
    return parser


def _build_routing(
    question: str,
    warnings: list[str],
) -> dict[str, Any]:
    raw_terms = _query_terms(question)
    mapped_terms: list[str] = []
    korean_mappings = []
    lifecycle_topics: list[str] = []
    atlas_pages: list[str] = []
    subsystem_tags: list[str] = []
    for mapping in KOREAN_QUERY_MAP:
        if _korean_mapping_matches(question, mapping):
            korean_mappings.append(mapping["id"])
            mapped_terms.extend(mapping.get("terms", ()))
            lifecycle_topics.extend(mapping.get("lifecycle_topics", ()))
            atlas_pages.extend(mapping.get("atlas_pages", ()))
            subsystem_tags.extend(mapping.get("tags", ()))
    for lifecycle_topic in _available_lifecycle_topics():
        try:
            ontology, _path = load_ontology(lifecycle_topic)
        except KernelCorpusError as exc:
            warnings.append(str(exc))
            continue
        labels = _string_list(ontology.get("labels", [])) + [str(ontology.get("title", "")), str(ontology.get("topic", ""))]
        if _score_text(" ".join(labels), raw_terms + mapped_terms) > 0:
            lifecycle_topics.append(lifecycle_topic)
    for subsystem in SUBSYSTEMS:
        subsystem_text = " ".join(
            [
                subsystem.filename,
                subsystem.title,
                subsystem.description,
                " ".join(subsystem.query_terms),
            ]
        )
        direct_tag_match = any(str(tag).lower() in set(raw_terms) for tag in subsystem.tags)
        if _score_text(subsystem_text, raw_terms + mapped_terms) > 0 or direct_tag_match:
            atlas_pages.append(Path(subsystem.filename).stem)
            subsystem_tags.extend(subsystem.tags)
            lifecycle_topics.extend(subsystem.lifecycle_topics)
    function_names = _extract_function_names(question)
    return {
        "raw_terms": _unique(raw_terms)[:32],
        "expanded_terms": _unique(raw_terms + mapped_terms)[:64],
        "korean_mappings": _unique(korean_mappings),
        "lifecycle_topics": _unique(lifecycle_topics)[:8],
        "atlas_pages": _unique(_normalize_atlas_page(item) for item in atlas_pages if item)[:8],
        "subsystem_tags": _unique(subsystem_tags)[:16],
        "function_names": function_names[:MAX_FUNCTION_NAMES],
    }


def _rank_canonical_candidates(
    pack_root: Path,
    question: str,
    routing: dict[str, Any],
    topic_defs: dict[str, dict[str, Any]],
    warnings: list[str],
) -> list[dict[str, Any]]:
    try:
        listed = list_canonical_answers(pack_root, max_topics=MAX_CANONICAL_TOPICS)
    except KernelCorpusError as exc:
        warnings.append("Canonical answer listing failed: %s" % exc)
        return []
    warnings.extend(_coerce_warnings(listed))
    terms = _unique(_query_terms(question) + _string_list(routing.get("expanded_terms", [])))
    lifecycle_hints = set(_string_list(routing.get("lifecycle_topics", [])))
    atlas_hints = set(_string_list(routing.get("atlas_pages", [])))
    function_hints = set(_string_list(routing.get("function_names", [])))
    candidates = []
    for metadata in listed.get("topics", []) if isinstance(listed.get("topics"), list) else []:
        if not isinstance(metadata, dict):
            continue
        topic_id = str(metadata.get("topic_id", "") or "")
        topic_def = topic_defs.get(topic_id, {})
        quality = metadata.get("quality", {}) if isinstance(metadata.get("quality"), dict) else {}
        major_functions = _unique(
            _string_list(metadata.get("major_functions", []))
            + _string_list(topic_def.get("seed_names", []))
            + _string_list(topic_def.get("extra_seed_names", []))
        )[:32]
        primary_match_text = " ".join(
            [
                topic_id,
                str(metadata.get("title", "")),
                str(metadata.get("question", "")),
                str(metadata.get("mode", "")),
                " ".join(major_functions),
                " ".join(_string_list(topic_def.get("queries", []))),
                str(topic_def.get("lifecycle_topic", "")),
            ]
        )
        score = _score_text(primary_match_text, terms)
        reasons = []
        if score > 0:
            reasons.append("text_or_term_match")
        lifecycle_topic = str(topic_def.get("lifecycle_topic", "") or "")
        if lifecycle_topic and lifecycle_topic in lifecycle_hints:
            score += 30
            reasons.append("lifecycle_topic:%s" % lifecycle_topic)
        atlas_page = _normalize_atlas_page(str(topic_def.get("atlas_page", "") or ""))
        matched_functions = [name for name in major_functions if name in function_hints]
        if matched_functions:
            score += 20 * len(matched_functions)
            reasons.append("function_name:%s" % ",".join(matched_functions[:4]))
        if topic_id in terms or topic_id.replace("_", " ") in terms:
            score += 35
            reasons.append("topic_id")
        if score <= 0:
            continue
        tag_score = _score_text(" ".join(_string_list(topic_def.get("tags", []))), terms)
        if tag_score > 0:
            score += min(6, tag_score)
            reasons.append("tag_hint")
        if atlas_page and atlas_page in atlas_hints:
            score += 4
            if "atlas_page:%s" % atlas_page not in reasons:
                reasons.append("atlas_page:%s" % atlas_page)
        status = str(quality.get("status", "missing") or "missing").lower()
        if status == "pass":
            score += 8
        if _int_value(quality.get("validation_warning_count"), 999) == 0:
            score += 4
        candidates.append(
            {
                "topic_id": topic_id,
                "priority": str(metadata.get("priority", "")),
                "mode": str(metadata.get("mode", "")),
                "title": str(metadata.get("title", "")),
                "question": str(metadata.get("question", "")),
                "route_score": int(score),
                "match_reasons": _unique(reasons),
                "quality": {
                    "status": status if status in STATUS_ORDER else "missing",
                    "score": quality.get("score", None),
                    "validation_warning_count": _int_value(quality.get("validation_warning_count"), 0),
                    "gap_count": _int_value(quality.get("gap_count"), 0),
                    "selected_function_count": _int_value(quality.get("selected_function_count"), len(major_functions)),
                    "edge_count": _int_value(quality.get("edge_count"), 0),
                },
                "paths": metadata.get("paths", {}) if isinstance(metadata.get("paths"), dict) else {},
                "major_functions": major_functions[:12],
                "lifecycle_topic": lifecycle_topic,
                "atlas_page": atlas_page,
                "source_refs": _string_list(topic_def.get("source_refs", [])),
                "recommended_mcp_calls": _canonical_mcp_calls(topic_id, status, lifecycle_topic, atlas_page),
                "fallback_cli_commands": _canonical_cli_commands(pack_root, topic_id, lifecycle_topic),
                "required_citations": _canonical_citations(topic_id, metadata),
                "expected_gap_checks": _canonical_gap_checks(status, quality),
            }
        )
    candidates.sort(key=_candidate_sort_key)
    return candidates


def _build_live_steps(
    pack_root: Path,
    question: str,
    routing: dict[str, Any],
    selected: list[dict[str, Any]],
    excluded: list[dict[str, Any]],
    warnings: list[str],
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    order = 1
    steps.append(
        _step(
            order,
            "corpus_status",
            "Confirm pack identity and table counts before drafting.",
            {},
            "python -B .\\tools\\kernel_corpus\\query.py status --pack-root \"%s\"" % _path_payload(pack_root),
        )
    )
    order += 1
    for candidate in selected:
        steps.append(
            _step(
                order,
                "get_canonical_answer",
                "Read selected canonical answer, quality, and gap files before using it.",
                {"topic_id": candidate.get("topic_id", ""), "include_answer": True, "include_quality": True, "include_gaps": True},
                "python -B .\\tools\\kernel_corpus\\canonical_store.py get --pack-root \"%s\" --topic %s --quality --gaps --max-chars 12000"
                % (_path_payload(pack_root), candidate.get("topic_id", "")),
                required_citations=candidate.get("required_citations", []),
            )
        )
        order += 1
    for candidate in excluded:
        if candidate.get("quality", {}).get("status") in {"fail", "degraded", "missing"}:
            steps.append(
                _step(
                    order,
                    "find_canonical_answers",
                    "Use excluded canonical topic only as a retrieval hint; do not cite it as final evidence.",
                    {"query": candidate.get("topic_id", ""), "max_topics": 1},
                    "python -B .\\tools\\kernel_corpus\\canonical_store.py find --pack-root \"%s\" --query \"%s\" --max-topics 1"
                    % (_path_payload(pack_root), candidate.get("topic_id", "")),
                    uncertainty_checks=["Confirm why the topic was excluded before relying on any claim."],
                )
            )
            order += 1
    lifecycle_topics = _unique(
        _string_list(routing.get("lifecycle_topics", []))
        + [str(candidate.get("lifecycle_topic", "")) for candidate in selected + excluded if candidate.get("lifecycle_topic")]
    )
    for lifecycle_topic in lifecycle_topics[:4]:
        steps.append(
            _step(
                order,
                "trace_lifecycle",
                "Build in-memory lifecycle evidence for verification and gap filling.",
                {"topic": lifecycle_topic, "max_seeds": 64, "depth": 2},
                "python -B .\\tools\\kernel_corpus\\lifecycle.py --pack-root \"%s\" --topic %s --depth 2"
                % (_path_payload(pack_root), lifecycle_topic),
                required_citations=["lifecycle topic `%s`, selected function EA/name/path, phase, and supporting edges" % lifecycle_topic],
                uncertainty_checks=["Treat lifecycle phases as hypotheses until function evidence or graph edges support them."],
            )
        )
        order += 1
    atlas_pages = _unique(
        _string_list(routing.get("atlas_pages", []))
        + [str(candidate.get("atlas_page", "")) for candidate in selected + excluded if candidate.get("atlas_page")]
    )
    for page in atlas_pages[:4]:
        filename = "%s.md" % _normalize_atlas_page(page)
        page_path = pack_root.joinpath(*ATLAS_DIR_PARTS, filename)
        step_warnings = []
        if not page_path.is_file():
            step_warnings.append("Atlas page is not generated yet; use live search steps if get_atlas_page is unavailable.")
        steps.append(
            _step(
                order,
                "get_atlas_page",
                "Inspect subsystem atlas context when the page exists.",
                {"page": filename, "max_chars": 12000},
                "python -B .\\tools\\kernel_corpus\\atlas.py --pack-root \"%s\" --output-dir \"%s\" --limit 24"
                % (_path_payload(pack_root), _path_payload(pack_root.joinpath(*ATLAS_DIR_PARTS))),
                required_citations=["atlas page `%s` path and cited function rows" % filename],
                uncertainty_checks=step_warnings,
            )
        )
        order += 1
    function_names = _function_names_for_live_search(routing, selected, excluded)
    found_eas: list[str] = []
    for function_name in function_names[:MAX_FUNCTION_NAMES]:
        found = _find_exact_functions(pack_root, function_name, warnings)
        found_eas.extend(str(item.get("ea", "")) for item in found if item.get("ea"))
        steps.append(
            _step(
                order,
                "search_functions",
                "Verify high-signal function name `%s` in the live corpus." % function_name,
                {"query": function_name, "limit": DEFAULT_FUNCTION_LIMIT},
                "python -B .\\tools\\kernel_corpus\\query.py search --pack-root \"%s\" --query \"%s\" --limit %s"
                % (_path_payload(pack_root), function_name, DEFAULT_FUNCTION_LIMIT),
                found_functions=[_compact_function(item) for item in found],
                required_citations=["EA, function name, cleaned/raw/summary artifact path for `%s`" % function_name],
                uncertainty_checks=[] if found else ["Function `%s` was not found by exact live lookup." % function_name],
            )
        )
        order += 1
    if found_eas:
        evidence_topic = _plan_topic_slug(selected, routing)
        steps.append(
            _step(
                order,
                "build_evidence_pack",
                "Build an in-memory evidence pack from the found live functions before drafting.",
                {"topic": evidence_topic, "eas": _unique(found_eas)[:32]},
                "python -B .\\tools\\kernel_corpus\\query.py build-evidence-pack --pack-root \"%s\" --topic %s %s"
                % (_path_payload(pack_root), evidence_topic, " ".join("--ea %s" % ea for ea in _unique(found_eas)[:32])),
                required_citations=["evidence-pack topic, selected function EA/name/path, edges, gaps, and warnings"],
            )
        )
        order += 1
    if not function_names:
        broad_query = " ".join(_string_list(routing.get("expanded_terms", []))[:8]) or question
        steps.append(
            _step(
                order,
                "search_functions",
                "Run a broad live search because no canonical topic or exact function name is sufficient.",
                {"query": broad_query, "tags": _string_list(routing.get("subsystem_tags", []))[:4], "limit": DEFAULT_FUNCTION_LIMIT},
                "python -B .\\tools\\kernel_corpus\\query.py search --pack-root \"%s\" --query \"%s\" --limit %s"
                % (_path_payload(pack_root), broad_query, DEFAULT_FUNCTION_LIMIT),
                uncertainty_checks=["Inspect returned function artifacts manually before drafting."],
            )
        )
    return steps


def _step(
    order: int,
    mcp_tool: str,
    purpose: str,
    arguments: dict[str, Any],
    fallback_cli: str,
    *,
    found_functions: list[dict[str, Any]] | None = None,
    required_citations: list[str] | None = None,
    uncertainty_checks: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "order": order,
        "mcp_tool": mcp_tool,
        "purpose": purpose,
        "arguments": arguments,
        "fallback_cli": fallback_cli,
        "found_functions": found_functions or [],
        "required_citations": required_citations or [],
        "uncertainty_checks": uncertainty_checks or [],
    }


def _freshness_payload(pack_root: Path, status: dict[str, Any]) -> dict[str, Any]:
    manifest = status.get("manifest", {}) if isinstance(status.get("manifest"), dict) else {}
    return {
        "recommendation": "run_validate_pack_before_answering",
        "validation_command": "python -B .\\tools\\kernel_corpus\\validate_pack.py --pack-root \"%s\"" % _path_payload(pack_root),
        "target_path": str(manifest.get("target_path", "")),
        "source_index_sha256": str(manifest.get("source_index_sha256", "")),
        "generated_at": str(manifest.get("generated_at", "")),
        "function_count": _int_value(manifest.get("function_count"), 0),
        "skipped_count": _int_value(manifest.get("skipped_count"), 0),
    }


def _canonical_mcp_calls(topic_id: str, status: str, lifecycle_topic: str, atlas_page: str) -> list[dict[str, Any]]:
    calls = [
        {
            "tool": "get_canonical_answer",
            "arguments": {"topic_id": topic_id, "include_answer": True, "include_quality": True, "include_gaps": True},
            "use": "first_evidence_layer" if status == "pass" else "quality_or_retrieval_hint",
        }
    ]
    if lifecycle_topic:
        calls.append({"tool": "trace_lifecycle", "arguments": {"topic": lifecycle_topic, "max_seeds": 64, "depth": 2}, "use": "verify_key_transitions"})
    if atlas_page:
        calls.append({"tool": "get_atlas_page", "arguments": {"page": "%s.md" % atlas_page, "max_chars": 12000}, "use": "subsystem_context"})
    return calls


def _canonical_cli_commands(pack_root: Path, topic_id: str, lifecycle_topic: str) -> list[str]:
    commands = [
        "python -B .\\tools\\kernel_corpus\\canonical_store.py get --pack-root \"%s\" --topic %s --quality --gaps --max-chars 12000"
        % (_path_payload(pack_root), topic_id)
    ]
    if lifecycle_topic:
        commands.append(
            "python -B .\\tools\\kernel_corpus\\lifecycle.py --pack-root \"%s\" --topic %s --depth 2"
            % (_path_payload(pack_root), lifecycle_topic)
        )
    return commands


def _canonical_citations(topic_id: str, metadata: dict[str, Any]) -> list[str]:
    paths = metadata.get("paths", {}) if isinstance(metadata.get("paths"), dict) else {}
    result = [
        "canonical topic id `%s`" % topic_id,
        "canonical quality status and validation warning count",
        "EA and function name for each major claim",
    ]
    for key in ("answer", "quality", "gaps", "source_map", "evidence_pack"):
        path = str(paths.get(key, "") or "")
        if path:
            result.append("%s path `%s`" % (key, path))
    return result


def _canonical_gap_checks(status: str, quality: dict[str, Any]) -> list[str]:
    checks = []
    if status == "degraded":
        checks.append("Read gaps.md and verify degraded sections with live retrieval before final answer.")
    if status in {"fail", "missing"}:
        checks.append("Do not use this canonical topic as final-answer evidence.")
    if _int_value(quality.get("validation_warning_count"), 0) > 0:
        checks.append("Resolve or explicitly cite validation warnings.")
    if _int_value(quality.get("gap_count"), 0) > 0:
        checks.append("Inspect gap count and avoid claiming missing edges as proven.")
    return checks


def _recommended_mcp_calls(live_steps: list[dict[str, Any]], selected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    calls = []
    for candidate in selected:
        calls.extend(candidate.get("recommended_mcp_calls", []))
    for step in live_steps:
        calls.append({"tool": step.get("mcp_tool", ""), "arguments": step.get("arguments", {}), "use": step.get("purpose", "")})
    result = []
    seen = set()
    for call in calls:
        key = (call.get("tool", ""), json.dumps(call.get("arguments", {}), ensure_ascii=True, sort_keys=True))
        if key in seen:
            continue
        seen.add(key)
        result.append(call)
    return result


def _citation_contract(selected: list[dict[str, Any]], live_steps: list[dict[str, Any]]) -> dict[str, Any]:
    required = [
        "Do not answer from generic Windows internals memory when corpus evidence exists.",
        "Cite canonical topic id and quality status when using canonical text.",
        "Cite EA, function name, and cleaned/raw/summary artifact path for function-level claims.",
        "Cite evidence-pack edges or explicitly mark transitions as inferred.",
        "State gaps, validation warnings, stale-source concerns, and missing exact functions.",
    ]
    for candidate in selected:
        required.extend(_string_list(candidate.get("required_citations", [])))
    for step in live_steps:
        required.extend(_string_list(step.get("required_citations", [])))
    return {
        "required": _unique(required),
        "forbidden": [
            "Do not present degraded, failed, or missing canonical topics as approved final evidence.",
            "Do not hide live retrieval contradictions to canonical artifacts.",
            "Do not generate final prose from this planner output alone.",
        ],
    }


def _final_answer_outline(routing: dict[str, Any], selected: list[dict[str, Any]]) -> list[str]:
    if routing.get("lifecycle_topics") or any(candidate.get("mode") == "lifecycle" for candidate in selected):
        return [
            "Scope and evidence status",
            "Canonical answer summary, if selected",
            "Lifecycle phases: entry, allocate, initialize, publish, notify, steady_state, exit, rundown, delete",
            "Major functions with EA/path citations",
            "Edges and uncertainty checks",
            "Gaps, degraded areas, and follow-up retrieval",
        ]
    return [
        "Scope and evidence status",
        "Canonical answer summary, if selected",
        "Live retrieval findings grouped by function/subsystem",
        "Required citations for each claim",
        "Gaps, uncertainty, and stop conditions",
    ]


def _stop_conditions(
    selected: list[dict[str, Any]],
    excluded: list[dict[str, Any]],
    live_steps: list[dict[str, Any]],
) -> list[str]:
    conditions = [
        "Stop and rebuild or validate if pack freshness checks fail.",
        "Stop before drafting if no function-level citations can be produced for the main claim.",
    ]
    if not selected:
        conditions.append("No selected passing canonical topic; use live retrieval and state that canonical coverage was unavailable.")
    if any(item.get("quality", {}).get("status") == "degraded" for item in selected):
        conditions.append("Degraded canonical topic selected; inspect gaps and verify with live retrieval before drafting.")
    if any(item.get("quality", {}).get("status") in {"fail", "missing"} for item in excluded):
        conditions.append("Failed or missing canonical candidates are hints only, not answer evidence.")
    if any(step.get("uncertainty_checks") for step in live_steps):
        conditions.append("Resolve or state uncertainty checks from live retrieval steps.")
    return _unique(conditions)


def _function_names_for_live_search(
    routing: dict[str, Any],
    selected: list[dict[str, Any]],
    excluded: list[dict[str, Any]],
) -> list[str]:
    names = _string_list(routing.get("function_names", []))
    for candidate in selected + excluded:
        names.extend(_string_list(candidate.get("major_functions", [])))
    return [name for name in _unique(names) if FUNCTION_NAME_RE.match(name)][:MAX_FUNCTION_NAMES]


def _find_exact_functions(pack_root: Path, function_name: str, warnings: list[str]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    try:
        found.extend(find_functions_by_name(pack_root, function_name, limit=DEFAULT_FUNCTION_LIMIT))
        if not found:
            found.extend(search_functions(pack_root, query=function_name, limit=DEFAULT_FUNCTION_LIMIT))
    except KernelCorpusError as exc:
        warnings.append("Live function lookup failed for %s: %s" % (function_name, exc))
    found.sort(key=lambda item: (str(item.get("name", "")), str(item.get("ea", ""))))
    return found[:DEFAULT_FUNCTION_LIMIT]


def _compact_function(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "ea": str(item.get("ea", "")),
        "name": str(item.get("name", "")),
        "tags": _string_list(item.get("tags", []))[:8],
        "artifacts": item.get("artifacts", {}) if isinstance(item.get("artifacts"), dict) else {},
    }


def _plan_topic_slug(selected: list[dict[str, Any]], routing: dict[str, Any]) -> str:
    if selected:
        return str(selected[0].get("topic_id", "answer_plan") or "answer_plan")
    lifecycle_topics = _string_list(routing.get("lifecycle_topics", []))
    if lifecycle_topics:
        return lifecycle_topics[0]
    terms = _string_list(routing.get("expanded_terms", []))
    raw = "_".join(terms[:4]) if terms else "answer_plan"
    slug = SAFE_PLAN_TOPIC_RE.sub("_", raw).strip("_").lower()
    return slug[:80] or "answer_plan"


def _load_canonical_topic_defs(warnings: list[str]) -> dict[str, dict[str, Any]]:
    if not CANONICAL_TOPICS_PATH.is_file():
        warnings.append("Canonical topic manifest is missing: %s" % CANONICAL_TOPICS_PATH)
        return {}
    try:
        data = json.loads(CANONICAL_TOPICS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append("Canonical topic manifest could not be read: %s" % exc)
        return {}
    result = {}
    for item in data.get("topics", []) if isinstance(data.get("topics"), list) else []:
        if isinstance(item, dict) and item.get("id"):
            result[str(item["id"])] = item
    return result


def _available_lifecycle_topics() -> list[str]:
    ontology_dir = Path(__file__).with_name("ontology")
    return sorted(path.stem for path in ontology_dir.glob("*.json"))


def _korean_mapping_matches(question: str, mapping: dict[str, Any]) -> bool:
    required = [str(item) for item in mapping.get("required_korean", ()) if str(item)]
    if required and not any(token in question for token in required):
        return False
    tokens = [str(item) for item in mapping.get("korean", ()) if str(item)]
    if not tokens:
        return False
    return any(token in question for token in tokens)


def _score_text(text: str, terms: list[str]) -> int:
    lower = str(text or "").lower()
    if not lower:
        return 0
    score = 0
    for term in terms:
        normalized = str(term or "").strip().lower()
        if len(normalized) < 2:
            continue
        if normalized in lower:
            score += max(2, min(12, len(normalized) // 2))
    return score


def _query_terms(question: str) -> list[str]:
    lower = str(question or "").lower()
    terms = [term for term in re.findall(r"[a-z0-9_]+", lower) if term not in QUERY_STOPWORDS]
    hangul = re.findall(r"[가-힣]{2,}", lower)
    collapsed = lower.strip()
    result = terms + hangul
    for left, right in zip(terms, terms[1:]):
        result.append("%s %s" % (left, right))
    if collapsed:
        result.append(collapsed)
    return _unique(result)


def _extract_function_names(question: str) -> list[str]:
    return _unique(FUNCTION_NAME_RE.findall(str(question or "")))


def _candidate_sort_key(candidate: dict[str, Any]) -> tuple[int, int, int, int, str]:
    quality = candidate.get("quality", {}) if isinstance(candidate.get("quality"), dict) else {}
    warnings = _int_value(quality.get("validation_warning_count"), 999)
    return (
        -int(candidate.get("route_score", 0) or 0),
        STATUS_ORDER.get(str(quality.get("status", "missing")), 99),
        _priority_rank(str(candidate.get("priority", ""))),
        warnings,
        str(candidate.get("topic_id", "")),
    )


def _excluded_policy(status: str) -> str:
    if status == "degraded":
        return "excluded_by_default_use_allow_degraded_for_caveated_selection"
    if status == "fail":
        return "retrieval_hint_only_failed_quality"
    if status == "missing":
        return "retrieval_hint_only_missing_quality"
    return "retrieval_hint_only"


def _normalize_atlas_page(value: str) -> str:
    text = str(value or "").strip()
    if text.endswith(".md"):
        text = text[:-3]
    return text.lower()


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


def _priority_rank(priority: str) -> int:
    return PRIORITY_ORDER.get(str(priority or "").upper(), 99)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item)]
    return []


def _coerce_warnings(payload: dict[str, Any]) -> list[str]:
    values = payload.get("warnings", []) if isinstance(payload, dict) else []
    if not isinstance(values, list):
        return []
    return [str(item) for item in values if str(item)]


def _unique(values: Any) -> list[Any]:
    result = []
    seen = set()
    for value in values:
        key = json.dumps(value, ensure_ascii=True, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _path_payload(path: Path) -> str:
    return str(path.resolve())


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _require_inside(path: Path, root: Path, label: str) -> None:
    if not _is_inside(path, root):
        raise QueryError("%s must stay under %s: %s" % (label, root, path))


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.config import LlmConfig, get_provider_api_key, load_config
from ida_pseudoforge.models.provider_factory import build_rename_provider
from ida_pseudoforge.models.provider_registry import PROVIDER_ORDER, normalize_provider, provider_defaults, provider_requires_api_key
from ida_pseudoforge.version import plugin_title


_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}|0x[0-9A-Fa-f]+|[가-힣]{2,}")
_KOREAN_ALIASES = {
    "프로세스": "process_thread",
    "스레드": "process_thread",
    "쓰레드": "process_thread",
    "콜백": "callback",
    "오브젝트": "object_callback",
    "핸들": "object_callback",
    "메모리": "memory",
    "풀": "memory",
    "가상": "memory",
    "물리": "memory",
    "아이오컨트롤": "ioctl",
    "장치제어": "ioctl",
    "디스패치": "dispatch",
    "드라이버엔트리": "entrypoint",
    "엔트리": "entrypoint",
    "레지스트리": "io_registry",
    "파일": "io_registry",
}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    index_path = Path(args.index)
    if not index_path.is_file():
        print("PseudoForge corpus Q&A failed: index JSON was not found: %s" % index_path, file=sys.stderr)
        return 1
    index = _read_json(index_path)
    if not isinstance(index, dict) or index.get("schema") != "pseudoforge_corpus_index_v1":
        print("PseudoForge corpus Q&A failed: index JSON is invalid", file=sys.stderr)
        return 1
    retrieved = retrieve_evidence(index, args.question, top=args.top)
    context = build_context_pack(index, args.question, retrieved, max_function_chars=args.max_function_chars)
    if args.context_out:
        Path(args.context_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.context_out).write_text(context, encoding="utf-8")
    if args.json_output:
        payload = {
            "question": args.question,
            "retrieved": retrieved,
            "context": context if args.include_context_json else "",
        }
        Path(args.json_output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_output).write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    if args.llm:
        try:
            provider = _build_text_provider(args)
            answer = provider.complete(
                _qa_system_prompt(),
                context,
                response_format={"type": "text"},
                task_name="corpus_qa",
            )
        except (OSError, RuntimeError) as exc:
            print("PseudoForge corpus Q&A failed: %s" % exc, file=sys.stderr)
            return 1
        print(answer.strip())
    else:
        print(_deterministic_answer(args.question, retrieved))
        print("")
        print("Context pack:")
        print(context)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ask evidence-backed questions over a PseudoForge corpus index.")
    parser.add_argument("--version", action="version", version=plugin_title())
    parser.add_argument("index", help="Path to pseudoforge-corpus-index.json.")
    parser.add_argument("question", help="Question to answer from corpus evidence.")
    parser.add_argument("--top", type=int, default=8, help="Number of functions to retrieve.")
    parser.add_argument("--max-function-chars", type=int, default=5000, help="Maximum cleaned text chars per function evidence.")
    parser.add_argument("--context-out", default="", help="Write the retrieved evidence context pack to this path.")
    parser.add_argument("--json-output", default="", help="Write retrieval payload JSON to this path.")
    parser.add_argument("--include-context-json", action="store_true", help="Include full context text in --json-output.")
    parser.add_argument("--llm", action="store_true", help="Use configured or overridden LLM provider to answer.")
    parser.add_argument("--llm-provider", choices=PROVIDER_ORDER, default="", help="Override saved provider.")
    parser.add_argument("--llm-api-key", default="", help="Override provider API key.")
    parser.add_argument("--llm-base-url", default="", help="Override HTTP provider base URL.")
    parser.add_argument("--llm-model", default="", help="Override model.")
    parser.add_argument("--llm-command", default="", help="Override CLI command template.")
    parser.add_argument("--llm-timeout", type=int, default=0, help="Override LLM timeout seconds.")
    return parser


def retrieve_evidence(index: dict[str, Any], question: str, top: int = 8) -> list[dict[str, Any]]:
    query_terms = _query_terms(question)
    scored = []
    for function in _function_items(index):
        score, reasons = _score_function(function, query_terms)
        if score <= 0:
            continue
        scored.append(
            {
                "score": score,
                "reasons": reasons,
                "ea": function.get("ea", ""),
                "name": function.get("name", ""),
                "tags": function.get("tags", []),
                "summary_path": function.get("summary_path", ""),
                "artifacts": function.get("artifacts", {}),
            }
        )
    scored.sort(key=lambda item: (-int(item["score"]), str(item.get("ea", ""))))
    if scored:
        return scored[: max(1, top)]
    fallback = []
    for function in _function_items(index)[: max(1, top)]:
        fallback.append(
            {
                "score": 0,
                "reasons": ["fallback"],
                "ea": function.get("ea", ""),
                "name": function.get("name", ""),
                "tags": _string_list(function.get("tags", [])),
                "summary_path": function.get("summary_path", ""),
                "artifacts": _coerce_dict(function.get("artifacts", {})),
            }
        )
    return fallback


def build_context_pack(
    index: dict[str, Any],
    question: str,
    retrieved: list[dict[str, Any]],
    max_function_chars: int = 5000,
) -> str:
    functions_by_ea = {
        str(item.get("ea", "")): item
        for item in _function_items(index)
    }
    lines = [
        "# PseudoForge Corpus Q&A Context",
        "",
        "Question: %s" % question,
        "",
        "Rules for answer:",
        "- Use only the evidence below.",
        "- Cite function EA, name, and artifact path for important claims.",
        "- Say unknown when the evidence is insufficient.",
        "",
        "Corpus overview:",
        json.dumps(index.get("overview", {}), ensure_ascii=True, sort_keys=True),
        "",
        "Retrieved functions:",
        "",
    ]
    for rank, item in enumerate(retrieved, start=1):
        function = functions_by_ea.get(str(item.get("ea", "")), {})
        artifacts = _coerce_dict(function.get("artifacts", {}) if isinstance(function, dict) else {})
        cleaned_path = Path(str(artifacts.get("cleaned_pseudocode", "") or ""))
        cleaned_text = _read_text(cleaned_path)[: max(0, max_function_chars)]
        lines.extend(
            [
                "## %d. %s %s" % (rank, item.get("ea", ""), item.get("name", "")),
                "",
                "- Score: %s" % item.get("score", 0),
                "- Reasons: %s" % ", ".join(_string_list(item.get("reasons", []))),
                "- Tags: %s" % ", ".join(_string_list(function.get("tags", []) if isinstance(function, dict) else [])),
                "- Summary: %s" % function.get("summary_path", ""),
                "- Cleaned: %s" % artifacts.get("cleaned_pseudocode", ""),
                "- Rename map: %s" % artifacts.get("rename_map", ""),
                "- Rule report: %s" % artifacts.get("rule_report", ""),
                "- Callers: %s" % ", ".join(_string_list(function.get("caller_names", []) if isinstance(function, dict) else [])[:16]),
                "- Callees: %s" % ", ".join(_string_list(function.get("callee_names", []) if isinstance(function, dict) else [])[:16]),
                "- Imports: %s" % _join_imports(function.get("imports_called", []) if isinstance(function, dict) else []),
                "- Strings: %s" % _join_strings(function.get("strings_referenced", []) if isinstance(function, dict) else []),
                "",
                "Interesting lines:",
            ]
        )
        for line in _string_list(function.get("interesting_lines", []) if isinstance(function, dict) else [])[:24]:
            lines.append("- " + str(line))
        lines.extend(["", "Cleaned excerpt:", "```cpp", cleaned_text.rstrip(), "```", ""])
    return "\n".join(lines)


def _score_function(function: dict[str, Any], query_terms: set[str]) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    name_terms = _tokens(str(function.get("name", "")))
    tag_terms = {str(item).lower() for item in function.get("tags", []) or []}
    indexed_terms = {str(item).lower() for item in function.get("terms", []) or []}
    interesting_terms = _tokens("\n".join(str(item) for item in function.get("interesting_lines", []) or []))
    haystack = name_terms | tag_terms | indexed_terms | interesting_terms
    for term in sorted(query_terms):
        if term in name_terms:
            score += 10
            reasons.append("name:%s" % term)
        if term in tag_terms:
            score += 8
            reasons.append("tag:%s" % term)
        if term in indexed_terms:
            score += 4
            reasons.append("term:%s" % term)
        if term in interesting_terms:
            score += 3
            reasons.append("line:%s" % term)
        if term not in haystack:
            for candidate in haystack:
                if len(term) >= 4 and term in candidate:
                    score += 2
                    reasons.append("partial:%s" % term)
                    break
    counts = function.get("counts", {}) if isinstance(function.get("counts", {}), dict) else {}
    if {"ioctl", "dispatch"} & query_terms and int(counts.get("buffer_contracts", 0) or 0):
        score += 6
        reasons.append("buffer_contracts")
    return score, reasons[:16]


def _query_terms(question: str) -> set[str]:
    terms = _tokens(question)
    lowered = question.lower()
    for korean, alias in _KOREAN_ALIASES.items():
        if korean in lowered or korean in question:
            terms.add(alias)
    return terms


def _tokens(text: str) -> set[str]:
    return {item.lower() for item in _TOKEN_RE.findall(text or "")}


def _build_text_provider(args: argparse.Namespace):
    saved = load_config()
    provider = normalize_provider(args.llm_provider or saved.llm.provider)
    if not args.llm_provider and not saved.llm.enabled:
        raise RuntimeError("Saved PseudoForge LLM settings are disabled; pass --llm-provider or enable plugin LLM settings")
    defaults = provider_defaults(provider)
    timeout_seconds = args.llm_timeout if args.llm_timeout > 0 else saved.llm.timeout_seconds
    config = LlmConfig(
        enabled=True,
        provider=provider,
        base_url=args.llm_base_url or saved.llm.base_url or defaults.base_url,
        model=args.llm_model or saved.llm.model or defaults.model,
        timeout_seconds=min(max(int(timeout_seconds or 60), 5), 600),
        command_template=args.llm_command or saved.llm.command_template or defaults.command_template,
        extra_headers=saved.llm.extra_headers,
    )
    if args.llm_api_key:
        api_key = args.llm_api_key
    elif provider_requires_api_key(provider):
        api_key = get_provider_api_key(saved, provider)
    else:
        api_key = ""
    provider_instance = build_rename_provider(config, api_key=api_key)
    if not hasattr(provider_instance, "complete"):
        raise RuntimeError("Configured provider does not support text completion")
    return provider_instance


def _qa_system_prompt() -> str:
    return (
        "You are a defensive reverse-engineering assistant for PseudoForge corpus artifacts. "
        "Answer only from the provided evidence. Cite function EA, name, and artifact path for important claims. "
        "Separate confirmed evidence from inference. If the evidence is insufficient, say unknown. "
        "Do not provide bypass, evasion, exploitation, persistence, or offensive operational guidance."
    )


def _deterministic_answer(question: str, retrieved: list[dict[str, Any]]) -> str:
    lines = [
        "LLM was not run. Retrieved evidence for: %s" % question,
        "",
        "Top functions:",
    ]
    for item in retrieved:
        lines.append(
            "- score=%s %s %s tags=%s reasons=%s"
            % (
                item.get("score", 0),
                item.get("ea", ""),
                item.get("name", ""),
                ",".join(_string_list(item.get("tags", []))),
                ",".join(_string_list(item.get("reasons", []))),
            )
        )
    return "\n".join(lines)


def _function_items(index: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in _coerce_list(index.get("functions", [])) if isinstance(item, dict)]


def _coerce_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _coerce_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _string_list(value: object) -> list[str]:
    return [str(item) for item in _coerce_list(value)]


def _join_imports(items: list[Any]) -> str:
    names = []
    for item in items[:32]:
        if isinstance(item, dict):
            module = str(item.get("module", ""))
            name = str(item.get("name", ""))
            names.append((module + "!" if module else "") + name)
    return ", ".join(name for name in names if name)


def _join_strings(items: list[Any]) -> str:
    values = []
    for item in items[:16]:
        if isinstance(item, dict):
            values.append(str(item.get("value", ""))[:120])
    return " | ".join(value for value in values if value)


def _read_json(path: Path) -> dict[str, Any] | list[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}


def _read_text(path: Path) -> str:
    if not str(path) or not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


if __name__ == "__main__":
    raise SystemExit(main())

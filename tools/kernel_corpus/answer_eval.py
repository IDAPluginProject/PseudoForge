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

from tools.kernel_corpus.answer_harness import validate_answer  # noqa: E402
from tools.kernel_corpus.answer_planner import build_answer_plan  # noqa: E402
from tools.kernel_corpus.canonical_store import list_canonical_answers  # noqa: E402
from tools.kernel_corpus.errors import KernelCorpusError, QueryError  # noqa: E402
from tools.kernel_corpus.query import corpus_status  # noqa: E402

ANSWER_EVAL_CASES_SCHEMA_VERSION = "kernel_corpus_answer_eval_cases_v1"
ANSWER_EVAL_REPORT_SCHEMA_VERSION = "kernel_corpus_answer_eval_report_v1"
DEFAULT_CASES_PATH = Path(__file__).with_name("answer_eval_cases.json")
DEFAULT_REPORT_DIR = "answer-eval"
SUPPORTED_FORMATS = ("json", "text", "markdown")
SAFE_CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
EA_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
CAVEAT_RE = re.compile(
    r"\b(caveat|degraded|fail(?:ed|ing)?|gap|uncertain|uncertainty|"
    r"verify|validation warning|quality|not final|retrieval hint|stale)\b",
    re.IGNORECASE,
)
GAP_SECTION_RE = re.compile(r"(?im)^\s*(?:#+\s*)?(gaps?|uncertainty|limitations?|caveats?)\b")
ARTIFACT_TEXT_RE = re.compile(r"(?i)(?:\.ida-batch-summary\.json|\.cleaned\.cpp|\.raw\.cpp|evidence-pack\.json|answer\.md|quality\.md|gaps\.md)")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        payload = run_answer_eval(
            args.pack_root,
            cases_path=args.cases,
            case_ids=args.case or [],
            plans_dir=args.plans_dir or "",
            answers_dir=args.answers_dir or "",
        )
        if args.report_out:
            payload["report_path"] = write_report(payload, args.report_out, requested_format=args.format)
    except (OSError, KernelCorpusError, ValueError, json.JSONDecodeError) as exc:
        print("Kernel answer eval failed: %s" % exc, file=sys.stderr)
        return 1

    if args.format == "markdown":
        print(render_markdown_report(payload))
    elif args.format == "text":
        print(render_text_report(payload))
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    return 0 if bool(payload.get("ok")) else 2


def run_answer_eval(
    pack_root: str | Path,
    *,
    cases_path: str | Path = DEFAULT_CASES_PATH,
    case_ids: list[str] | tuple[str, ...] | None = None,
    plans_dir: str | Path = "",
    answers_dir: str | Path = "",
) -> dict[str, Any]:
    root = Path(pack_root)
    status = corpus_status(root)
    manifest = _load_cases(cases_path)
    cases = _selected_cases(manifest, case_ids or [])
    canonical_index = _canonical_index(root)
    results = [
        _evaluate_case(
            root,
            status,
            manifest.get("defaults", {}) if isinstance(manifest.get("defaults"), dict) else {},
            case,
            canonical_index,
            Path(plans_dir) if str(plans_dir or "") else None,
            Path(answers_dir) if str(answers_dir or "") else None,
        )
        for case in cases
    ]
    counts = _status_counts(results)
    warnings = _coerce_warnings(status)
    report = {
        "schema": ANSWER_EVAL_REPORT_SCHEMA_VERSION,
        "ok": counts.get("fail", 0) == 0,
        "pack_root": _path_payload(root),
        "cases_path": _path_payload(Path(cases_path)),
        "case_count": len(results),
        "pass_count": counts.get("pass", 0),
        "degraded_count": counts.get("degraded", 0),
        "fail_count": counts.get("fail", 0),
        "pack": {
            "schema_version": status.get("schema_version", ""),
            "target_path": str(status.get("manifest", {}).get("target_path", "")) if isinstance(status.get("manifest"), dict) else "",
            "source_index_sha256": str(status.get("manifest", {}).get("source_index_sha256", "")) if isinstance(status.get("manifest"), dict) else "",
            "generated_at": str(status.get("manifest", {}).get("generated_at", "")) if isinstance(status.get("manifest"), dict) else "",
            "function_count": _int_value(status.get("manifest", {}).get("function_count"), 0) if isinstance(status.get("manifest"), dict) else 0,
            "skipped_count": _int_value(status.get("manifest", {}).get("skipped_count"), 0) if isinstance(status.get("manifest"), dict) else 0,
        },
        "warnings": warnings,
        "cases": results,
    }
    return report


def write_report(payload: dict[str, Any], report_out: str | Path, *, requested_format: str = "json") -> str:
    pack_root = Path(str(payload.get("pack_root", "") or ""))
    path = Path(report_out)
    if not path.is_absolute():
        path = pack_root / path
    _require_inside(path, pack_root, "Answer eval report output")
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = _format_from_path(path, requested_format)
    if fmt == "markdown":
        text = render_markdown_report(payload)
    elif fmt == "text":
        text = render_text_report(payload)
    else:
        text = json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    return _path_payload(path)


def render_text_report(payload: dict[str, Any]) -> str:
    lines = [
        "Kernel answer eval report",
        "schema: %s" % payload.get("schema", ""),
        "pack_root: %s" % payload.get("pack_root", ""),
        "cases: pass=%s degraded=%s fail=%s total=%s"
        % (
            payload.get("pass_count", 0),
            payload.get("degraded_count", 0),
            payload.get("fail_count", 0),
            payload.get("case_count", 0),
        ),
        "",
    ]
    for item in payload.get("cases", []):
        lines.append(
            "%s %s selected=%s failures=%s warnings=%s"
            % (
                str(item.get("status", "")).upper(),
                item.get("case_id", ""),
                ",".join(item.get("plan", {}).get("selected_canonical_topic_ids", [])),
                len(item.get("failures", [])),
                len(item.get("warnings", [])),
            )
        )
        for failure in item.get("failures", [])[:5]:
            lines.append("  fail:%s %s" % (failure.get("code", ""), failure.get("message", "")))
        for warning in item.get("warnings", [])[:3]:
            lines.append("  warn:%s %s" % (warning.get("code", ""), warning.get("message", "")))
    return "\n".join(lines).rstrip() + "\n"


def render_markdown_report(payload: dict[str, Any]) -> str:
    lines = [
        "# Kernel Answer Eval Report",
        "",
        "- Schema: `%s`" % payload.get("schema", ""),
        "- Pack root: `%s`" % payload.get("pack_root", ""),
        "- Cases: pass=`%s` degraded=`%s` fail=`%s` total=`%s`"
        % (
            payload.get("pass_count", 0),
            payload.get("degraded_count", 0),
            payload.get("fail_count", 0),
            payload.get("case_count", 0),
        ),
        "",
        "## Cases",
        "",
    ]
    for item in payload.get("cases", []):
        lines.append(
            "### `%s` `%s`"
            % (
                item.get("status", ""),
                item.get("case_id", ""),
            )
        )
        lines.append("")
        lines.append("- Question: `%s`" % item.get("question", ""))
        lines.append("- Selected topics: %s" % _inline_code_list(item.get("plan", {}).get("selected_canonical_topic_ids", [])))
        lines.append("- Excluded topics: %s" % _inline_code_list(item.get("plan", {}).get("excluded_canonical_topic_ids", [])))
        lines.append("- Live tools: %s" % _inline_code_list(item.get("plan", {}).get("live_tools", [])))
        if item.get("answer", {}).get("provided"):
            lines.append("- Answer: `%s`" % item.get("answer", {}).get("path", ""))
            lines.append("- Answer validation warnings: `%s`" % item.get("answer", {}).get("validation_warning_count", 0))
        if item.get("failures"):
            lines.append("")
            lines.append("Failures:")
            for failure in item.get("failures", [])[:10]:
                lines.append("- `%s`: %s" % (failure.get("code", ""), failure.get("message", "")))
        if item.get("warnings"):
            lines.append("")
            lines.append("Warnings:")
            for warning in item.get("warnings", [])[:10]:
                lines.append("- `%s`: %s" % (warning.get("code", ""), warning.get("message", "")))
        if item.get("recommended_fixes"):
            lines.append("")
            lines.append("Recommended fixes:")
            for fix in item.get("recommended_fixes", [])[:8]:
                lines.append("- %s" % fix)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate Kernel Corpus answer plans and optional answer Markdown without model calls.")
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    parser.add_argument("--cases", default=str(DEFAULT_CASES_PATH), help="Answer eval case manifest JSON.")
    parser.add_argument("--case", action="append", default=[], help="Evaluate only a case id. May be passed more than once.")
    parser.add_argument("--plans-dir", default="", help="Optional directory containing precomputed JSON plans named <case-id>.json.")
    parser.add_argument("--answers-dir", default="", help="Optional directory containing answer Markdown files named <case-id>.md.")
    parser.add_argument("--format", choices=SUPPORTED_FORMATS, default="json", help="Output format.")
    parser.add_argument("--report-out", default="", help="Optional report path under the pack root.")
    return parser


def _evaluate_case(
    pack_root: Path,
    pack_status: dict[str, Any],
    defaults: dict[str, Any],
    case: dict[str, Any],
    canonical_index: dict[str, dict[str, Any]],
    plans_dir: Path | None,
    answers_dir: Path | None,
) -> dict[str, Any]:
    case_id = _required_case_id(case)
    question = str(case.get("question", "") or "").strip()
    if not question:
        raise QueryError("Answer eval case is missing question: %s" % case_id)
    failures: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    fixes: list[str] = []
    plan, plan_source = _load_or_build_plan(pack_root, case, plans_dir)
    selected = _candidate_map(plan.get("canonical_candidates", []))
    excluded = _candidate_map(plan.get("excluded_canonical_candidates", []))
    selected_ids = sorted(selected)
    excluded_ids = sorted(excluded)
    live_tools = _live_tools(plan)
    expected_topics = _string_list(case.get("expected_canonical_topic_ids", []))

    _evaluate_expected_topics(expected_topics, selected, excluded, canonical_index, failures, warnings, fixes)
    _evaluate_false_canonical_match(expected_topics, selected_ids, live_tools, failures, fixes)
    _evaluate_allowed_tools(case, live_tools, failures, fixes)
    _evaluate_required_functions(case, plan, failures, fixes, answer_text="")

    stale_topics = _stale_topics(expected_topics + selected_ids + excluded_ids, canonical_index, pack_status)
    for stale_topic in stale_topics:
        warnings.append(_issue("stale_canonical_topic", "Canonical topic source identity may be stale: %s" % stale_topic))

    answer_info = _evaluate_answer(
        pack_root,
        case,
        defaults,
        expected_topics,
        selected,
        excluded,
        canonical_index,
        answers_dir,
        failures,
        warnings,
        fixes,
    )
    if answer_info.get("provided"):
        _evaluate_required_functions(case, plan, failures, fixes, answer_text=str(answer_info.get("text", "")))
        _evaluate_degraded_or_stale_answer(case, expected_topics, selected, excluded, canonical_index, stale_topics, str(answer_info.get("text", "")), failures, warnings, fixes)
    elif _answer_required(case):
        failures.append(_issue("missing_answer_file", "Case requires an answer Markdown file but none was provided: %s" % case_id))
        fixes.append("Write %s.md under --answers-dir or set answer_required to false for plan-only evaluation." % case_id)

    if failures:
        status = "fail"
    elif _case_is_degraded(warnings, answer_info):
        status = "degraded"
    else:
        status = "pass"
    return {
        "case_id": case_id,
        "question": question,
        "status": status,
        "plan": {
            "source": plan_source,
            "schema": str(plan.get("schema", "")),
            "selected_canonical_topic_ids": selected_ids,
            "excluded_canonical_topic_ids": excluded_ids,
            "live_tools": live_tools,
            "freshness_recommendation": str(plan.get("pack_freshness", {}).get("recommendation", "")) if isinstance(plan.get("pack_freshness"), dict) else "",
            "warnings": _string_list(plan.get("warnings", []))[:20],
        },
        "answer": _public_answer_info(answer_info),
        "failures": failures,
        "warnings": warnings,
        "recommended_fixes": _unique(fixes)[:20],
    }


def _evaluate_expected_topics(
    expected_topics: list[str],
    selected: dict[str, dict[str, Any]],
    excluded: dict[str, dict[str, Any]],
    canonical_index: dict[str, dict[str, Any]],
    failures: list[dict[str, str]],
    warnings: list[dict[str, str]],
    fixes: list[str],
) -> None:
    if not expected_topics:
        return
    for topic_id in expected_topics:
        selected_item = selected.get(topic_id)
        excluded_item = excluded.get(topic_id)
        metadata = selected_item or excluded_item or canonical_index.get(topic_id)
        if not metadata:
            failures.append(_issue("missing_canonical_topic", "Expected canonical topic was not routed or present: %s" % topic_id))
            fixes.append("Add or repair canonical topic routing for `%s`." % topic_id)
            continue
        quality = _quality_status(metadata)
        if quality == "pass" and topic_id not in selected:
            failures.append(_issue("expected_pass_topic_not_selected", "Passing expected canonical topic was not selected: %s" % topic_id))
            fixes.append("Tune answer planner routing so `%s` is selected for this question." % topic_id)
        elif quality in {"degraded", "fail", "missing"} and topic_id in selected:
            warnings.append(_issue("low_quality_topic_selected", "Low-quality canonical topic was selected and needs explicit caveats: %s status=%s" % (topic_id, quality)))


def _evaluate_false_canonical_match(
    expected_topics: list[str],
    selected_ids: list[str],
    live_tools: list[str],
    failures: list[dict[str, str]],
    fixes: list[str],
) -> None:
    if expected_topics:
        return
    if selected_ids:
        failures.append(_issue("unexpected_canonical_match", "Question expected no canonical topic, but planner selected: %s" % ", ".join(selected_ids)))
        fixes.append("Tighten planner routing so unknown topics fall back to live retrieval.")
    non_status_tools = [tool for tool in live_tools if tool != "corpus_status"]
    if not non_status_tools:
        failures.append(_issue("missing_live_retrieval_plan", "Unknown-topic case did not produce a live retrieval plan."))
        fixes.append("Add broad search or atlas retrieval fallback for unknown topics.")


def _evaluate_allowed_tools(
    case: dict[str, Any],
    live_tools: list[str],
    failures: list[dict[str, str]],
    fixes: list[str],
) -> None:
    allowed = set(_string_list(case.get("allowed_fallback_tools", [])))
    if not allowed:
        return
    disallowed = [tool for tool in live_tools if tool not in allowed]
    if disallowed:
        failures.append(_issue("disallowed_fallback_tool", "Planner used fallback tools outside case allowlist: %s" % ", ".join(sorted(set(disallowed)))))
        fixes.append("Update the eval case allowlist or adjust planner fallback tools.")


def _evaluate_required_functions(
    case: dict[str, Any],
    plan: dict[str, Any],
    failures: list[dict[str, str]],
    fixes: list[str],
    *,
    answer_text: str,
) -> None:
    patterns = _string_list(case.get("required_function_name_regexes", []))
    if not patterns:
        return
    haystack_names = _plan_function_names(plan)
    if answer_text:
        haystack_names.extend(_function_like_tokens(answer_text))
    haystack = "\n".join(_unique(haystack_names))
    for pattern in patterns:
        if not _regex_search(pattern, haystack):
            failures.append(_issue("missing_required_function", "No plan or answer evidence matched required function regex: %s" % pattern))
            fixes.append("Add evidence retrieval or answer coverage for function pattern `%s`." % pattern)


def _evaluate_answer(
    pack_root: Path,
    case: dict[str, Any],
    defaults: dict[str, Any],
    expected_topics: list[str],
    selected: dict[str, dict[str, Any]],
    excluded: dict[str, dict[str, Any]],
    canonical_index: dict[str, dict[str, Any]],
    answers_dir: Path | None,
    failures: list[dict[str, str]],
    warnings: list[dict[str, str]],
    fixes: list[str],
) -> dict[str, Any]:
    case_id = str(case.get("id", ""))
    answer_path = _answer_path(answers_dir, case_id)
    if answer_path is None:
        warnings.append(_issue("answer_not_provided", "No --answers-dir was provided; answer Markdown checks were skipped."))
        return {"provided": False, "path": "", "text": "", "validation_warning_count": 0, "validation_warning_codes": []}
    if not answer_path.is_file():
        warnings.append(_issue("answer_file_missing", "Answer Markdown file was not found: %s" % answer_path))
        return {"provided": False, "path": _path_payload(answer_path), "text": "", "validation_warning_count": 0, "validation_warning_codes": []}
    answer_text = answer_path.read_text(encoding="utf-8", errors="replace")
    topic_id = _evidence_topic_for_case(expected_topics, selected, excluded, canonical_index)
    evidence_pack = _read_evidence_pack_for_topic(canonical_index, topic_id, warnings)
    validation: dict[str, Any] = {}
    if evidence_pack:
        validation = validate_answer(evidence_pack, answer_text, answer_path=answer_path)
        if not validation.get("passed", False):
            failures.append(_issue("answer_harness_warnings", "Answer harness emitted %d citation/gap warnings." % _int_value(validation.get("warning_count"), 0)))
            fixes.append("Fix answer Markdown so answer_harness validates EA, function name, artifact path, and gap discipline.")
    else:
        warnings.append(_issue("missing_evidence_pack", "Could not load canonical evidence pack for answer validation."))
    _evaluate_required_citation_fields(case, defaults, answer_text, evidence_pack, failures, fixes)
    _evaluate_forbidden_patterns(case, defaults, answer_text, failures, fixes)
    _evaluate_gap_behavior(case, defaults, answer_text, evidence_pack, selected, excluded, failures, warnings, fixes)
    warning_codes = []
    if isinstance(validation.get("warnings"), list):
        warning_codes = [str(item.get("code", "")) for item in validation["warnings"] if isinstance(item, dict)]
    return {
        "provided": True,
        "path": _path_payload(answer_path),
        "text": answer_text,
        "validation_warning_count": _int_value(validation.get("warning_count"), 0),
        "validation_warning_codes": _unique(warning_codes),
        "harness_passed": bool(validation.get("passed", False)) if validation else False,
    }


def _evaluate_required_citation_fields(
    case: dict[str, Any],
    defaults: dict[str, Any],
    answer_text: str,
    evidence_pack: dict[str, Any],
    failures: list[dict[str, str]],
    fixes: list[str],
) -> None:
    fields = _string_list(case.get("required_citation_fields", defaults.get("required_citation_fields", [])))
    for field in fields:
        if field == "ea" and not EA_RE.search(answer_text):
            failures.append(_issue("missing_answer_ea", "Answer lacks an EA citation."))
            fixes.append("Cite at least one evidence EA such as `0x...` in answer Markdown.")
        elif field == "function_name" and not _answer_has_function_name(answer_text, evidence_pack, case):
            failures.append(_issue("missing_answer_function_name", "Answer lacks a required function-name citation."))
            fixes.append("Cite the function name beside each major claim.")
        elif field == "artifact_path" and not _answer_has_artifact_path(answer_text, evidence_pack):
            failures.append(_issue("missing_answer_artifact_path", "Answer lacks an artifact path citation."))
            fixes.append("Cite a summary, cleaned, raw, canonical answer, or evidence-pack path near major claims.")


def _evaluate_forbidden_patterns(
    case: dict[str, Any],
    defaults: dict[str, Any],
    answer_text: str,
    failures: list[dict[str, str]],
    fixes: list[str],
) -> None:
    for pattern in _string_list(case.get("forbidden_answer_patterns", defaults.get("forbidden_answer_patterns", []))):
        if _regex_search(pattern, answer_text):
            failures.append(_issue("forbidden_answer_pattern", "Answer matched forbidden pattern: %s" % pattern))
            fixes.append("Remove or qualify unsupported answer language matching `%s`." % pattern)


def _evaluate_gap_behavior(
    case: dict[str, Any],
    defaults: dict[str, Any],
    answer_text: str,
    evidence_pack: dict[str, Any],
    selected: dict[str, dict[str, Any]],
    excluded: dict[str, dict[str, Any]],
    failures: list[dict[str, str]],
    warnings: list[dict[str, str]],
    fixes: list[str],
) -> None:
    behavior = str(case.get("expected_gap_behavior", defaults.get("expected_gap_behavior", "")) or "")
    if behavior != "require_gap_section_when_gaps_present":
        return
    gaps_present = _evidence_has_gaps(evidence_pack) or any(_quality_gap_count(item) > 0 for item in list(selected.values()) + list(excluded.values()))
    if gaps_present and not GAP_SECTION_RE.search(answer_text):
        failures.append(_issue("missing_gap_or_uncertainty_section", "Evidence has gaps or uncertainty but answer lacks a gaps/uncertainty section."))
        fixes.append("Add a Gaps or Uncertainty section and carry forward evidence-pack gaps.")
    elif not evidence_pack and not selected and not excluded:
        warnings.append(_issue("gap_behavior_unverified", "No evidence pack or canonical quality metadata was available for gap behavior verification."))


def _evaluate_degraded_or_stale_answer(
    case: dict[str, Any],
    expected_topics: list[str],
    selected: dict[str, dict[str, Any]],
    excluded: dict[str, dict[str, Any]],
    canonical_index: dict[str, dict[str, Any]],
    stale_topics: list[str],
    answer_text: str,
    failures: list[dict[str, str]],
    warnings: list[dict[str, str]],
    fixes: list[str],
) -> None:
    expectation = str(case.get("stale_degraded_handling_expectation", "") or "")
    if expectation not in {"exclude_or_caveat", "must_caveat"}:
        return
    low_quality = []
    for topic_id in _unique(expected_topics + list(selected) + list(excluded)):
        metadata = selected.get(topic_id) or excluded.get(topic_id) or canonical_index.get(topic_id) or {}
        if _quality_status(metadata) in {"degraded", "fail", "missing"}:
            low_quality.append(topic_id)
    needs_caveat = _unique(low_quality + stale_topics)
    if not needs_caveat:
        return
    if CAVEAT_RE.search(answer_text):
        warnings.append(_issue("low_quality_or_stale_caveated", "Answer includes caveat language for low-quality or stale topics: %s" % ", ".join(needs_caveat)))
        return
    failures.append(_issue("low_quality_or_stale_without_caveat", "Answer uses low-quality or stale canonical context without an explicit caveat: %s" % ", ".join(needs_caveat)))
    fixes.append("Add degraded/stale/quality caveats or use live retrieval before final answer claims.")


def _load_cases(cases_path: str | Path) -> dict[str, Any]:
    path = Path(cases_path)
    payload = _read_json_object(path, "answer eval cases")
    if payload.get("schema") != ANSWER_EVAL_CASES_SCHEMA_VERSION:
        raise QueryError("Unsupported answer eval case schema: %s" % payload.get("schema", ""))
    cases = payload.get("cases", [])
    if not isinstance(cases, list) or not cases:
        raise QueryError("Answer eval case manifest has no cases: %s" % path)
    seen = set()
    for case in cases:
        if not isinstance(case, dict):
            raise QueryError("Answer eval case must be an object")
        case_id = _required_case_id(case)
        if case_id in seen:
            raise QueryError("Duplicate answer eval case id: %s" % case_id)
        seen.add(case_id)
    return payload


def _selected_cases(manifest: dict[str, Any], case_ids: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    cases = [item for item in manifest.get("cases", []) if isinstance(item, dict)]
    if not case_ids:
        return sorted(cases, key=lambda item: str(item.get("id", "")))
    selected = set()
    for case_id in case_ids:
        if not SAFE_CASE_ID_RE.match(str(case_id)):
            raise QueryError("Unsafe answer eval case id: %s" % case_id)
        selected.add(str(case_id))
    result = [case for case in cases if str(case.get("id", "")) in selected]
    found = {str(case.get("id", "")) for case in result}
    missing = sorted(selected - found)
    if missing:
        raise QueryError("Answer eval case id was not found: %s" % ", ".join(missing))
    return sorted(result, key=lambda item: str(item.get("id", "")))


def _load_or_build_plan(pack_root: Path, case: dict[str, Any], plans_dir: Path | None) -> tuple[dict[str, Any], str]:
    case_id = str(case.get("id", ""))
    if plans_dir is not None:
        plan_path = plans_dir / ("%s.json" % case_id)
        if plan_path.is_file():
            payload = _read_json_object(plan_path, "answer plan")
            return payload, _path_payload(plan_path)
    payload = build_answer_plan(
        pack_root,
        str(case.get("question", "")),
        allow_degraded=bool(case.get("allow_degraded_canonical", False)),
    )
    return payload, "generated"


def _canonical_index(pack_root: Path) -> dict[str, dict[str, Any]]:
    try:
        payload = list_canonical_answers(pack_root, max_topics=200)
    except KernelCorpusError:
        return {}
    result = {}
    for item in payload.get("topics", []) if isinstance(payload.get("topics"), list) else []:
        if isinstance(item, dict):
            result[str(item.get("topic_id", ""))] = item
    return result


def _candidate_map(values: Any) -> dict[str, dict[str, Any]]:
    result = {}
    for item in values if isinstance(values, list) else []:
        if isinstance(item, dict):
            topic_id = str(item.get("topic_id", "") or "")
            if topic_id:
                result[topic_id] = item
    return result


def _live_tools(plan: dict[str, Any]) -> list[str]:
    tools = []
    for step in plan.get("live_retrieval_steps", []) if isinstance(plan.get("live_retrieval_steps"), list) else []:
        if isinstance(step, dict):
            tool = str(step.get("mcp_tool", "") or "")
            if tool:
                tools.append(tool)
    return _unique(tools)


def _plan_function_names(plan: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ("canonical_candidates", "excluded_canonical_candidates"):
        for candidate in plan.get(key, []) if isinstance(plan.get(key), list) else []:
            if isinstance(candidate, dict):
                names.extend(_string_list(candidate.get("major_functions", [])))
    for step in plan.get("live_retrieval_steps", []) if isinstance(plan.get("live_retrieval_steps"), list) else []:
        if not isinstance(step, dict):
            continue
        for function in step.get("found_functions", []) if isinstance(step.get("found_functions"), list) else []:
            if isinstance(function, dict) and function.get("name"):
                names.append(str(function.get("name", "")))
    return names


def _function_like_tokens(text: str) -> list[str]:
    return re.findall(r"\b(?:Nt|Zw|Ps|Psp|Mm|Mi|Ob|Obp|Io|Iop|Ex|Se|Sep|Cm|Cmp|Ke|Ki)[A-Za-z0-9_]{2,}\b", text)


def _answer_path(answers_dir: Path | None, case_id: str) -> Path | None:
    if answers_dir is None:
        return None
    return answers_dir / ("%s.md" % case_id)


def _answer_required(case: dict[str, Any]) -> bool:
    return bool(case.get("answer_required", False))


def _evidence_topic_for_case(
    expected_topics: list[str],
    selected: dict[str, dict[str, Any]],
    excluded: dict[str, dict[str, Any]],
    canonical_index: dict[str, dict[str, Any]],
) -> str:
    for topic_id in expected_topics + sorted(selected) + sorted(excluded):
        if topic_id in canonical_index or topic_id in selected or topic_id in excluded:
            return topic_id
    return ""


def _read_evidence_pack_for_topic(
    canonical_index: dict[str, dict[str, Any]],
    topic_id: str,
    warnings: list[dict[str, str]],
) -> dict[str, Any]:
    metadata = canonical_index.get(topic_id, {})
    paths = metadata.get("paths", {}) if isinstance(metadata.get("paths"), dict) else {}
    path = Path(str(paths.get("evidence_pack", "") or ""))
    if not topic_id or not path.is_file():
        return {}
    try:
        return _read_json_object(path, "canonical evidence pack")
    except (OSError, json.JSONDecodeError, QueryError) as exc:
        warnings.append(_issue("evidence_pack_load_failed", "Could not load evidence pack for %s: %s" % (topic_id, exc)))
        return {}


def _answer_has_function_name(answer_text: str, evidence_pack: dict[str, Any], case: dict[str, Any]) -> bool:
    for pattern in _string_list(case.get("required_function_name_regexes", [])):
        if _regex_search(pattern, answer_text):
            return True
    for function in _evidence_functions(evidence_pack):
        name = str(function.get("name", "") or "")
        if name and name in answer_text:
            return True
    return False


def _answer_has_artifact_path(answer_text: str, evidence_pack: dict[str, Any]) -> bool:
    for path in _artifact_paths_from_evidence(evidence_pack):
        if path and path in answer_text:
            return True
        if path and Path(path).name and Path(path).name in answer_text:
            return True
    return bool(ARTIFACT_TEXT_RE.search(answer_text))


def _evidence_functions(evidence_pack: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in evidence_pack.get("functions", []) if isinstance(evidence_pack.get("functions"), list) else []:
        if isinstance(item, dict):
            result.append(item)
    for phase in evidence_pack.get("phases", []) if isinstance(evidence_pack.get("phases"), list) else []:
        if not isinstance(phase, dict):
            continue
        for item in phase.get("functions", []) if isinstance(phase.get("functions"), list) else []:
            if isinstance(item, dict):
                result.append(item)
    return result


def _artifact_paths_from_evidence(evidence_pack: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for function in _evidence_functions(evidence_pack):
        artifacts = function.get("artifacts", {}) if isinstance(function.get("artifacts"), dict) else {}
        paths.extend(str(value) for value in artifacts.values() if str(value))
        artifact_paths = function.get("artifact_paths", [])
        if isinstance(artifact_paths, list):
            paths.extend(str(value) for value in artifact_paths if str(value))
    return _unique(paths)


def _evidence_has_gaps(evidence_pack: dict[str, Any]) -> bool:
    return bool(_string_list(evidence_pack.get("gaps", [])) or _string_list(evidence_pack.get("uncertainty_notes", [])))


def _quality_gap_count(metadata: dict[str, Any]) -> int:
    quality = metadata.get("quality", {}) if isinstance(metadata.get("quality"), dict) else {}
    return _int_value(quality.get("gap_count"), 0)


def _quality_status(metadata: dict[str, Any]) -> str:
    quality = metadata.get("quality", {}) if isinstance(metadata.get("quality"), dict) else {}
    return str(quality.get("status", "missing") or "missing").lower()


def _stale_topics(
    topic_ids: list[str],
    canonical_index: dict[str, dict[str, Any]],
    pack_status: dict[str, Any],
) -> list[str]:
    manifest = pack_status.get("manifest", {}) if isinstance(pack_status.get("manifest"), dict) else {}
    pack_hash = str(manifest.get("source_index_sha256", "") or "")
    pack_generated_at = str(manifest.get("generated_at", "") or "")
    stale = []
    for topic_id in _unique(topic_ids):
        metadata = canonical_index.get(topic_id, {})
        topic_hash = str(metadata.get("source_index_sha256", "") or "")
        topic_generated_at = str(metadata.get("pack_generated_at", "") or "")
        if topic_hash and pack_hash and topic_hash != pack_hash:
            stale.append(topic_id)
        elif topic_generated_at and pack_generated_at and topic_generated_at != pack_generated_at:
            stale.append(topic_id)
    return sorted(set(stale))


def _case_is_degraded(warnings: list[dict[str, str]], answer_info: dict[str, Any]) -> bool:
    if answer_info.get("provided") is False:
        return True
    warning_codes = {item.get("code", "") for item in warnings}
    return bool(warning_codes.intersection({"stale_canonical_topic", "low_quality_topic_selected", "answer_file_missing"}))


def _public_answer_info(answer_info: dict[str, Any]) -> dict[str, Any]:
    return {
        "provided": bool(answer_info.get("provided", False)),
        "path": str(answer_info.get("path", "")),
        "harness_passed": bool(answer_info.get("harness_passed", False)),
        "validation_warning_count": _int_value(answer_info.get("validation_warning_count"), 0),
        "validation_warning_codes": _string_list(answer_info.get("validation_warning_codes", [])),
    }


def _required_case_id(case: dict[str, Any]) -> str:
    case_id = str(case.get("id", "") or "")
    if not SAFE_CASE_ID_RE.match(case_id):
        raise QueryError("Unsafe or missing answer eval case id: %s" % case_id)
    return case_id


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise QueryError("%s must be a JSON object: %s" % (label, path))
    return data


def _require_inside(path: Path, root: Path, label: str) -> None:
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise QueryError("%s must stay under pack_root: %s" % (label, path)) from exc


def _format_from_path(path: Path, requested_format: str) -> str:
    suffix = path.suffix.lower()
    if suffix == ".md":
        return "markdown"
    if suffix == ".txt":
        return "text"
    if suffix == ".json":
        return "json"
    if requested_format not in SUPPORTED_FORMATS:
        return "json"
    return requested_format


def _status_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("status", ""))
        counts[status] = counts.get(status, 0) + 1
    return counts


def _coerce_warnings(payload: dict[str, Any]) -> list[str]:
    values = payload.get("warnings", []) if isinstance(payload, dict) else []
    if not isinstance(values, list):
        return []
    return [str(item) for item in values]


def _issue(code: str, message: str) -> dict[str, str]:
    return {
        "code": code,
        "message": message,
    }


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item)]
    return []


def _unique(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        text = str(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _regex_search(pattern: str, text: str) -> bool:
    try:
        return re.search(pattern, text, re.IGNORECASE | re.MULTILINE) is not None
    except re.error:
        return pattern.lower() in text.lower()


def _int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _path_payload(path: Path) -> str:
    return str(path.resolve()) if path.exists() else str(path)


def _inline_code_list(values: Any) -> str:
    items = _string_list(values)
    if not items:
        return "`none`"
    return ", ".join("`%s`" % item for item in items[:12])


if __name__ == "__main__":
    raise SystemExit(main())

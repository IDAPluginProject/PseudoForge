from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.version import plugin_title


SCHEMA = "pseudoforge_cleanup_integrity_v1"
ARTIFACT_SUFFIXES = {
    "cleaned_pseudocode": ".cleaned.cpp",
    "warnings": ".warnings.json",
    "summary": ".ida-batch-summary.json",
}
LOCAL_ALLOCATION_FAILED_RE = re.compile(r"local\s+variable\s+allocation\s+failed", re.IGNORECASE)
UNASSIGNED_RENAME_RE = re.compile(
    r"(?:declared[-\s]+but[-\s]+never[-\s]+assigned.*rename|"
    r"rename.*declared[-\s]+but[-\s]+never[-\s]+assigned|"
    r"uninitialized\s+local\s+risk:.*(?:rename|renamed))",
    re.IGNORECASE,
)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    report = analyze_cleanup_integrity(
        args.corpus_root,
        sample_limit=max(0, args.sample_limit),
        top=max(1, args.top),
    )
    outputs = []
    if args.out:
        output_dir = Path(args.out)
        output_dir.mkdir(parents=True, exist_ok=True)
        if args.format in {"json", "both"}:
            json_path = output_dir / "cleanup-integrity.json"
            json_path.write_text(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
            outputs.append(str(json_path))
        if args.format in {"markdown", "both"}:
            markdown_path = output_dir / "cleanup-integrity.md"
            markdown_path.write_text(render_integrity_markdown(report), encoding="utf-8")
            outputs.append(str(markdown_path))
        print("Wrote cleanup integrity report: %s" % ", ".join(outputs))
    elif args.format == "markdown":
        print(render_integrity_markdown(report))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True))
    if args.fail_on_issues and int(report.get("issue_count", 0) or 0) > 0:
        return 1
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scan PseudoForge cleaned batch output for lightweight syntactic and artifact "
            "integrity regressions. This is intentionally narrower than corpus quality metrics."
        )
    )
    parser.add_argument("--version", action="version", version=plugin_title())
    parser.add_argument("--corpus-root", required=True, help="PseudoForge IDA batch output or functions directory.")
    parser.add_argument("--out", default="", help="Optional output directory for cleanup-integrity.json/md.")
    parser.add_argument(
        "--format",
        choices=("json", "markdown", "both"),
        default="json",
        help="Output format. With --out, both writes JSON and Markdown.",
    )
    parser.add_argument("--sample-limit", type=int, default=0, help="Analyze only the first N function summaries/files.")
    parser.add_argument("--top", type=int, default=50, help="Number of issue rows to include in Markdown.")
    parser.add_argument("--fail-on-issues", action="store_true", help="Return exit code 1 when any issue is found.")
    return parser


def analyze_cleanup_integrity(
    corpus_root: str | Path,
    *,
    sample_limit: int = 0,
    top: int = 50,
) -> dict[str, Any]:
    root = Path(corpus_root)
    functions_root = root / "functions" if (root / "functions").exists() else root
    summary_paths = _selected_summary_paths(functions_root, sample_limit=sample_limit)
    issues: list[dict[str, Any]] = []
    scanned_cleaned_paths: set[Path] = set()
    function_count = 0

    for summary_path in summary_paths:
        summary = _coerce_dict(_read_json(summary_path))
        artifacts = _coerce_dict(summary.get("artifacts", {}))
        context = _context_from_summary(summary_path, summary)
        cleaned_path = _artifact_path(summary_path, artifacts, "cleaned_pseudocode")
        if cleaned_path and cleaned_path.exists():
            scanned_cleaned_paths.add(cleaned_path.resolve())
            function_count += 1
            issues.extend(_scan_cleaned_text(cleaned_path, _read_text(cleaned_path), context))
        issues.extend(_scan_summary_artifacts(summary_path, summary, artifacts, context))

    if not summary_paths:
        for cleaned_path in _selected_cleaned_paths(functions_root, sample_limit=sample_limit):
            scanned_cleaned_paths.add(cleaned_path.resolve())
            function_count += 1
            context = {
                "function": cleaned_path.parent.name,
                "ea": "",
                "summary_path": "",
            }
            issues.extend(_scan_cleaned_text(cleaned_path, _read_text(cleaned_path), context))

    issue_counts = Counter(str(item.get("kind", "")) for item in issues)
    severity_counts = Counter(str(item.get("severity", "")) for item in issues)
    return {
        "schema": SCHEMA,
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "corpus_root": str(root),
        "functions_root": str(functions_root),
        "summary_count": len(summary_paths),
        "cleaned_file_count": len(scanned_cleaned_paths),
        "function_count": function_count,
        "issue_count": len(issues),
        "issue_counts": dict(sorted(issue_counts.items())),
        "severity_counts": dict(sorted(severity_counts.items())),
        "issues": issues,
        "top_issues": _top_issues(issues, top=max(1, top)),
    }


def render_integrity_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# PseudoForge Cleanup Integrity QA",
        "",
        "- Schema: `%s`" % report.get("schema", ""),
        "- Corpus root: `%s`" % report.get("corpus_root", ""),
        "- Summaries scanned: `%s`" % report.get("summary_count", 0),
        "- Cleaned files scanned: `%s`" % report.get("cleaned_file_count", 0),
        "- Issues: `%s`" % report.get("issue_count", 0),
        "",
        "This report is limited to syntactic and artifact integrity checks. Use `pseudoforge_corpus_quality.py` for cleanup-quality metrics.",
        "",
        "## Issue Counts",
        "",
        "| Kind | Count |",
        "| --- | ---: |",
    ]
    issue_counts = _coerce_dict(report.get("issue_counts", {}))
    if issue_counts:
        for kind, count in issue_counts.items():
            lines.append("| `%s` | %s |" % (_markdown_escape(str(kind)), int(count or 0)))
    else:
        lines.append("| none | 0 |")
    lines.extend(
        [
            "",
            "## Severity Counts",
            "",
            "| Severity | Count |",
            "| --- | ---: |",
        ]
    )
    severity_counts = _coerce_dict(report.get("severity_counts", {}))
    if severity_counts:
        for severity, count in severity_counts.items():
            lines.append("| `%s` | %s |" % (_markdown_escape(str(severity)), int(count or 0)))
    else:
        lines.append("| none | 0 |")
    lines.extend(
        [
            "",
            "## Top Issues",
            "",
            "| Severity | Kind | Function | EA | Line | Path | Evidence |",
            "| --- | --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for item in report.get("top_issues", []) or []:
        if not isinstance(item, dict):
            continue
        lines.append(
            "| `%s` | `%s` | `%s` | `%s` | %s | `%s` | %s |"
            % (
                _markdown_escape(str(item.get("severity", ""))),
                _markdown_escape(str(item.get("kind", ""))),
                _markdown_escape(str(item.get("function", ""))),
                _markdown_escape(str(item.get("ea", ""))),
                int(item.get("line", 0) or 0),
                _markdown_escape(str(item.get("path", ""))),
                _markdown_escape(str(item.get("evidence", ""))),
            )
        )
    if not report.get("top_issues"):
        lines.append("| none | none | none | none | 0 | none | none |")
    lines.append("")
    return "\n".join(lines)


def _scan_cleaned_text(path: Path, text: str, context: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    masked_lines = _mask_comments_and_strings(text).splitlines()
    raw_lines = text.splitlines()
    brace_depth = 0
    paren_depth = 0
    first_unmatched_brace_line = 0
    first_unmatched_paren_line = 0

    for index, line in enumerate(masked_lines, start=1):
        stripped = line.strip()
        raw_line = raw_lines[index - 1] if index - 1 < len(raw_lines) else line
        if stripped in {"{", "}"} and paren_depth > 0:
            issues.append(
                _issue(
                    "standalone_brace_in_multiline_call",
                    "error",
                    "Standalone brace appears while a call/expression parenthesis is still open.",
                    path,
                    context,
                    line=index,
                    evidence=raw_line.strip(),
                )
            )
        for char in line:
            if char == "(":
                paren_depth += 1
            elif char == ")":
                paren_depth -= 1
                if paren_depth < 0 and not first_unmatched_paren_line:
                    first_unmatched_paren_line = index
                if paren_depth < 0:
                    paren_depth = 0
            elif char == "{":
                brace_depth += 1
            elif char == "}":
                brace_depth -= 1
                if brace_depth < 0 and not first_unmatched_brace_line:
                    first_unmatched_brace_line = index
                if brace_depth < 0:
                    brace_depth = 0

    if first_unmatched_brace_line:
        issues.append(
            _issue(
                "unmatched_brace",
                "error",
                "Brace depth closed before an opening brace was available.",
                path,
                context,
                line=first_unmatched_brace_line,
                evidence=_line_text(raw_lines, first_unmatched_brace_line),
            )
        )
    if brace_depth:
        issues.append(
            _issue(
                "unmatched_brace",
                "error",
                "Brace depth did not return to zero at end of cleaned output.",
                path,
                context,
                line=len(raw_lines),
                evidence="final_brace_depth=%d" % brace_depth,
            )
        )
    if first_unmatched_paren_line:
        issues.append(
            _issue(
                "unmatched_paren",
                "error",
                "Parenthesis depth closed before an opening parenthesis was available.",
                path,
                context,
                line=first_unmatched_paren_line,
                evidence=_line_text(raw_lines, first_unmatched_paren_line),
            )
        )
    if paren_depth:
        issues.append(
            _issue(
                "unmatched_paren",
                "error",
                "Parenthesis depth did not return to zero at end of cleaned output.",
                path,
                context,
                line=len(raw_lines),
                evidence="final_paren_depth=%d" % paren_depth,
            )
        )

    for index, raw_line in enumerate(raw_lines, start=1):
        if LOCAL_ALLOCATION_FAILED_RE.search(raw_line):
            issues.append(
                _issue(
                    "local_variable_allocation_failed_comment",
                    "error",
                    "Cleaned output still contains a local variable allocation failed comment.",
                    path,
                    context,
                    line=index,
                    evidence=raw_line.strip(),
                )
            )
        if UNASSIGNED_RENAME_RE.search(raw_line):
            issues.append(
                _issue(
                    "declared_but_never_assigned_local_rename_warning",
                    "warning",
                    "Cleaned output contains a local rename warning for a declared-but-never-assigned local.",
                    path,
                    context,
                    line=index,
                    evidence=raw_line.strip(),
                )
            )
    return issues


def _scan_summary_artifacts(
    summary_path: Path,
    summary: dict[str, Any],
    artifacts: dict[str, Any],
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    warnings_path = _artifact_path(summary_path, artifacts, "warnings")
    warning_issue_path = warnings_path if str(warnings_path) and warnings_path.exists() else summary_path
    for warning in _warning_texts(summary, warnings_path):
        if UNASSIGNED_RENAME_RE.search(warning):
            issues.append(
                _issue(
                    "declared_but_never_assigned_local_rename_warning",
                    "warning",
                    "Warning artifact contains a local rename warning for a declared-but-never-assigned local.",
                    warning_issue_path,
                    context,
                    line=0,
                    evidence=warning,
                )
            )

    if str(summary.get("llm_status", "") or "").strip().lower() == "fallback":
        cache_refs = _llm_candidate_cache_refs(summary, artifacts)
        if cache_refs:
            issues.append(
                _issue(
                    "stale_llm_candidate_cache_on_fallback",
                    "error",
                    "Function summary reports llm_status=fallback but still references an LLM candidate cache.",
                    summary_path,
                    context,
                    line=0,
                    evidence=", ".join(cache_refs),
                )
            )
    return issues


def _warning_texts(summary: dict[str, Any], warnings_path: Path) -> list[str]:
    result: list[str] = []
    warnings = _read_json(warnings_path)
    if isinstance(warnings, list):
        result.extend(str(item) for item in warnings)
    elif isinstance(warnings, dict) and isinstance(warnings.get("warnings"), list):
        result.extend(str(item) for item in warnings.get("warnings", []))
    samples = summary.get("warning_samples", [])
    if isinstance(samples, list):
        result.extend(str(item) for item in samples)
    return _dedupe(result)


def _llm_candidate_cache_refs(summary: dict[str, Any], artifacts: dict[str, Any]) -> list[str]:
    refs = []
    for value in (
        summary.get("llm_candidate_cache"),
        _coerce_dict(summary.get("llm_candidate_artifacts", {})).get("llm_candidate_cache"),
        artifacts.get("llm_candidate_cache"),
    ):
        text = str(value or "").strip()
        if text:
            refs.append(text)
    return _dedupe(refs)


def _mask_comments_and_strings(text: str) -> str:
    result: list[str] = []
    index = 0
    in_block_comment = False
    in_line_comment = False
    string_quote = ""
    escape = False
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
                result.append(char)
            else:
                result.append(" ")
            index += 1
            continue
        if in_block_comment:
            if char == "*" and next_char == "/":
                result.extend("  ")
                in_block_comment = False
                index += 2
            else:
                result.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if string_quote:
            if escape:
                escape = False
                result.append(" ")
            elif char == "\\":
                escape = True
                result.append(" ")
            elif char == string_quote:
                string_quote = ""
                result.append(" ")
            else:
                result.append("\n" if char == "\n" else " ")
            index += 1
            continue
        if char == "/" and next_char == "/":
            in_line_comment = True
            result.extend("  ")
            index += 2
            continue
        if char == "/" and next_char == "*":
            in_block_comment = True
            result.extend("  ")
            index += 2
            continue
        if char in {'"', "'"}:
            string_quote = char
            result.append(" ")
            index += 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _selected_summary_paths(functions_root: Path, *, sample_limit: int) -> list[Path]:
    selected = []
    if not functions_root.exists():
        return selected
    for summary_path in sorted(functions_root.rglob("*.ida-batch-summary.json")):
        selected.append(summary_path)
        if sample_limit and len(selected) >= sample_limit:
            break
    return selected


def _selected_cleaned_paths(functions_root: Path, *, sample_limit: int) -> list[Path]:
    selected = []
    if not functions_root.exists():
        return selected
    for cleaned_path in sorted(functions_root.rglob("*.cleaned.cpp")):
        selected.append(cleaned_path)
        if sample_limit and len(selected) >= sample_limit:
            break
    return selected


def _context_from_summary(summary_path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "function": str(summary.get("function", "") or summary_path.parent.name),
        "ea": str(summary.get("function_ea", "") or _ea_from_directory(summary_path.parent.name)),
        "summary_path": str(summary_path),
    }


def _ea_from_directory(name: str) -> str:
    prefix = str(name or "").split("_", 1)[0]
    if re.fullmatch(r"[0-9A-Fa-f]{8,16}", prefix):
        return "0x%s" % prefix.upper()
    return ""


def _artifact_path(summary_path: Path, artifacts: dict[str, Any], key: str) -> Path:
    raw_value = str(artifacts.get(key, "") or "").strip()
    if raw_value:
        path = Path(raw_value)
        if path.exists():
            return path
        if path.name:
            sibling = summary_path.parent / path.name
            if sibling.exists():
                return sibling
            if not path.is_absolute():
                for parent in summary_path.parents:
                    parent_relative = parent / path
                    if parent_relative.exists():
                        return parent_relative
    suffix = ARTIFACT_SUFFIXES.get(key, "")
    if suffix:
        matches = sorted(summary_path.parent.glob("*%s" % suffix))
        if matches:
            return matches[0]
    return Path(raw_value)


def _read_json(path: Path) -> Any:
    if not path or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _read_text(path: Path) -> str:
    if not path or not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _coerce_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _issue(
    kind: str,
    severity: str,
    message: str,
    path: Path,
    context: dict[str, Any],
    *,
    line: int,
    evidence: str,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "severity": severity,
        "message": message,
        "function": str(context.get("function", "")),
        "ea": str(context.get("ea", "")),
        "path": str(path),
        "summary_path": str(context.get("summary_path", "")),
        "line": int(line or 0),
        "evidence": str(evidence or "")[:500],
    }


def _top_issues(issues: list[dict[str, Any]], *, top: int) -> list[dict[str, Any]]:
    order = {"error": 0, "warning": 1, "info": 2}
    return sorted(
        issues,
        key=lambda item: (
            order.get(str(item.get("severity", "")), 9),
            str(item.get("kind", "")),
            str(item.get("path", "")),
            int(item.get("line", 0) or 0),
        ),
    )[: max(1, top)]


def _line_text(lines: list[str], line_number: int) -> str:
    if line_number <= 0 or line_number > len(lines):
        return ""
    return lines[line_number - 1].strip()


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _markdown_escape(value: str) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


if __name__ == "__main__":
    raise SystemExit(main())

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

from ida_pseudoforge.version import VERSION, plugin_title


GENERIC_IDENTIFIER_RE = re.compile(r"\b[av]\d+\b")
OFFSET_DEREF_RE = re.compile(
    r"\*\s*\([^)]*\*\s*\)\s*\([^;\n]*\+\s*(?:0x[0-9A-Fa-f]+|\d+)(?:LL|i64|L)?\s*\)"
)
LABEL_RE = re.compile(r"\bLABEL_\d+\b")
DECIMAL_STATUS_RE = re.compile(r"\b(?:return|=|==|!=)\s*(-?107374\d+|-?\d{8,}|322122\d+)\b")
HEX_STATUS_RE = re.compile(r"\b0xC[0-9A-Fa-f]{7}\b")
FIELD_PREVIEW_RE = re.compile(r"-\s+inferred_offset_field_preview:")
LAYOUT_HINT_RE = re.compile(
    r"-\s+inferred_offset_layout:\s+Offset layout hint:\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s+has\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\)\s+"
    r"(?P<offsets>[^;]*);\s+observed types:\s+"
    r"(?P<types>.*?)\.\s+Review as (?P<review>[^.]+)\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)

ARTIFACT_SUFFIXES = {
    "cleaned_pseudocode": ".cleaned.cpp",
    "raw_pseudocode": ".raw.cpp",
    "rename_map": ".rename-map.json",
    "warnings": ".warnings.json",
    "buffer_contracts": ".buffer-contracts.json",
    "rule_report": ".rule-report.json",
}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    report = analyze_corpus(
        args.corpus_root,
        sample_limit=max(0, args.sample_limit),
        text_scan=not args.no_text_scan,
        top=max(1, args.top),
    )
    outputs = []
    if args.out:
        output_dir = Path(args.out)
        output_dir.mkdir(parents=True, exist_ok=True)
        if args.format in {"json", "both"}:
            json_path = output_dir / "corpus-quality.json"
            json_path.write_text(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
            outputs.append(str(json_path))
        if args.format in {"markdown", "both"}:
            markdown_path = output_dir / "corpus-quality.md"
            markdown_path.write_text(render_quality_markdown(report), encoding="utf-8")
            outputs.append(str(markdown_path))
        print("Wrote corpus quality report: %s" % ", ".join(outputs))
        return 0

    if args.format == "markdown":
        print(render_quality_markdown(report))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze PseudoForge IDA batch corpus quality and cleanup failure patterns."
    )
    parser.add_argument("--version", action="version", version=plugin_title())
    parser.add_argument("--corpus-root", required=True, help="PseudoForge IDA batch output directory.")
    parser.add_argument("--out", default="", help="Optional output directory for corpus-quality.json/md.")
    parser.add_argument(
        "--format",
        choices=("json", "markdown", "both"),
        default="json",
        help="Output format. With --out, both writes JSON and Markdown.",
    )
    parser.add_argument("--sample-limit", type=int, default=0, help="Analyze only the first N function summaries.")
    parser.add_argument("--no-text-scan", action="store_true", help="Skip cleaned pseudocode text pattern scan.")
    parser.add_argument("--top", type=int, default=20, help="Number of top warning functions/classes to include.")
    return parser


def analyze_corpus(
    corpus_root: str | Path,
    *,
    sample_limit: int = 0,
    text_scan: bool = True,
    top: int = 20,
) -> dict[str, Any]:
    root = Path(corpus_root)
    functions_root = root / "functions" if (root / "functions").exists() else root
    summary_paths = list(_iter_summary_paths(functions_root))
    if sample_limit:
        summary_paths = summary_paths[:sample_limit]

    warning_classes: Counter[str] = Counter()
    llm_statuses: Counter[str] = Counter()
    rename_sources: Counter[str] = Counter()
    rename_sources_applied: Counter[str] = Counter()
    rewrite_kinds: Counter[str] = Counter()
    api_semantic_reasons: Counter[str] = Counter()
    api_semantic_stages: Counter[str] = Counter()
    api_semantic_statuses: Counter[str] = Counter()
    layout_hint_bases: Counter[str] = Counter()
    layout_hint_types: Counter[str] = Counter()
    layout_totals = Counter()
    totals = Counter()
    text_totals = Counter()
    top_warning_functions = []
    top_layout_hint_functions = []

    for summary_path in summary_paths:
        summary = _coerce_dict(_read_json(summary_path))
        artifacts = _coerce_dict(summary.get("artifacts", {}))
        name = str(summary.get("function", "") or summary_path.parent.name)
        ea = str(summary.get("function_ea", ""))
        warnings = _read_warnings(_artifact_path(summary_path, artifacts, "warnings"))
        rename_items = _read_rename_items(_artifact_path(summary_path, artifacts, "rename_map"))
        rule_report = _coerce_dict(_read_json(_artifact_path(summary_path, artifacts, "rule_report")))
        buffer_contracts = _read_list(_artifact_path(summary_path, artifacts, "buffer_contracts"))
        cleaned_path = _artifact_path(summary_path, artifacts, "cleaned_pseudocode")

        rename_candidate_count = _int_value(summary.get("rename_candidates"), len(rename_items))
        applied_rename_count = _int_value(
            summary.get("renames"),
            sum(1 for item in rename_items if _rename_applied(item)),
        )
        totals["summaries"] += 1
        totals["rename_candidates"] += rename_candidate_count
        totals["applied_renames"] += applied_rename_count
        totals["warnings"] += _int_value(summary.get("warnings"), len(warnings))
        totals["flow_rewrites"] += _int_value(summary.get("flow_rewrites"), 0)
        totals["buffer_contracts"] += _int_value(summary.get("buffer_contracts"), len(buffer_contracts))
        totals["matched_rules"] += _int_value(_coerce_dict(summary.get("rule_diagnostics", {})).get("matched_rules"), 0)
        if warnings:
            totals["functions_with_warnings"] += 1
            top_warning_functions.append(
                {
                    "ea": ea,
                    "name": name,
                    "warning_count": len(warnings),
                    "warning_classes": dict(Counter(_classify_warning(item) for item in warnings).most_common(5)),
                    "summary_path": str(summary_path),
                }
            )
        if cleaned_path and cleaned_path.exists():
            totals["cleaned_files"] += 1
            if text_scan:
                layout_hints = _update_text_metrics(text_totals, cleaned_path)
                _update_layout_hint_metrics(
                    layout_hints,
                    layout_totals,
                    layout_hint_bases,
                    layout_hint_types,
                )
                if layout_hints:
                    top_layout_hint_functions.append(
                        _layout_hint_function_summary(name, ea, summary_path, layout_hints)
                    )

        llm_statuses[str(summary.get("llm_status", "") or "unknown")] += 1
        _update_rename_metrics(rename_items, rename_sources, rename_sources_applied)
        for warning in warnings:
            warning_classes[_classify_warning(warning)] += 1
        _update_rule_metrics(rule_report, rewrite_kinds, totals)
        api_diagnostic_count = _update_api_semantic_metrics(
            rule_report,
            api_semantic_reasons,
            api_semantic_stages,
            api_semantic_statuses,
            totals,
        )
        if api_diagnostic_count:
            totals["functions_with_api_semantic_diagnostics"] += 1

    top_warning_functions.sort(key=lambda item: (-int(item["warning_count"]), str(item["name"])))
    top_layout_hint_functions.sort(
        key=lambda item: (
            -int(item["hint_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    result = {
        "schema": "pseudoforge_corpus_quality_v1",
        "pseudoforge_version": VERSION,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "corpus_root": str(root),
        "functions_root": str(functions_root),
        "sample_limit": int(sample_limit),
        "text_scan": bool(text_scan),
        "totals": _counter_to_dict(totals),
        "rename_stats": {
            "apply_rate": _ratio(totals["applied_renames"], totals["rename_candidates"]),
            "by_source": _counter_to_dict(rename_sources),
            "applied_by_source": _counter_to_dict(rename_sources_applied),
            "llm_apply_rate": _ratio(rename_sources_applied["llm"], rename_sources["llm"]),
            "llm_rejected": max(0, rename_sources["llm"] - rename_sources_applied["llm"]),
        },
        "llm_statuses": _counter_to_dict(llm_statuses),
        "warning_stats": {
            "top_classes": _counter_to_dict(Counter(dict(warning_classes.most_common(top)))),
            "all_classes": _counter_to_dict(warning_classes),
        },
        "rule_stats": {
            "rewrite_emissions_by_kind": _counter_to_dict(rewrite_kinds),
            "rewrite_emissions": totals["rule_rewrite_emissions"],
            "rejected_emissions": totals["rule_rejected_emissions"],
            "load_errors": totals["rule_load_errors"],
            "validation_errors": totals["rule_validation_errors"],
        },
        "api_semantic_stats": {
            "diagnostics": totals["api_semantic_diagnostics"],
            "rejections": totals["api_semantic_rejections"],
            "functions_with_diagnostics": totals["functions_with_api_semantic_diagnostics"],
            "rejections_by_reason": _counter_to_dict(api_semantic_reasons),
            "rejections_by_stage": _counter_to_dict(api_semantic_stages),
            "statuses": _counter_to_dict(api_semantic_statuses),
        },
        "layout_hint_stats": {
            "totals": _counter_to_dict(layout_totals),
            "top_bases": _counter_to_dict(Counter(dict(layout_hint_bases.most_common(top)))),
            "observed_types": _counter_to_dict(Counter(dict(layout_hint_types.most_common(top)))),
            "top_functions": top_layout_hint_functions[:top],
        },
        "text_stats": _counter_to_dict(text_totals),
        "top_warning_functions": top_warning_functions[:top],
    }
    return result


def render_quality_markdown(report: dict[str, Any]) -> str:
    totals = _coerce_dict(report.get("totals", {}))
    rename_stats = _coerce_dict(report.get("rename_stats", {}))
    warning_stats = _coerce_dict(report.get("warning_stats", {}))
    rule_stats = _coerce_dict(report.get("rule_stats", {}))
    api_semantic_stats = _coerce_dict(report.get("api_semantic_stats", {}))
    layout_hint_stats = _coerce_dict(report.get("layout_hint_stats", {}))
    layout_totals = _coerce_dict(layout_hint_stats.get("totals", {}))
    text_stats = _coerce_dict(report.get("text_stats", {}))
    lines = [
        "# PseudoForge Corpus Quality Report",
        "",
        "- Corpus root: `%s`" % report.get("corpus_root", ""),
        "- Generated at: `%s`" % report.get("generated_at", ""),
        "- Functions scanned: `%s`" % totals.get("summaries", 0),
        "- Cleaned files: `%s`" % totals.get("cleaned_files", 0),
        "- Warnings: `%s` across `%s` functions"
        % (totals.get("warnings", 0), totals.get("functions_with_warnings", 0)),
        "- Rename apply rate: `%s`" % rename_stats.get("apply_rate", 0),
        "- LLM apply rate: `%s`" % rename_stats.get("llm_apply_rate", 0),
        "",
        "## Warning Classes",
        "",
    ]
    lines.extend(_markdown_counter_table(_coerce_dict(warning_stats.get("top_classes", {})), "Class"))
    lines.extend(
        [
            "",
            "## Rename Sources",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rename_stats.get("by_source", {})), "Source"))
    lines.extend(
        [
            "",
            "## Rule Coverage",
            "",
            "- Matched rules: `%s`" % totals.get("matched_rules", 0),
            "- Rewrite emissions: `%s`" % rule_stats.get("rewrite_emissions", 0),
            "- Rejected emissions: `%s`" % rule_stats.get("rejected_emissions", 0),
            "",
            "## API Semantic Diagnostics",
            "",
            "- Diagnostics: `%s`" % api_semantic_stats.get("diagnostics", 0),
            "- Rejections: `%s` across `%s` functions"
            % (
                api_semantic_stats.get("rejections", 0),
                api_semantic_stats.get("functions_with_diagnostics", 0),
            ),
            "",
            "### Rejections By Reason",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(api_semantic_stats.get("rejections_by_reason", {})), "Reason"))
    lines.extend(
        [
            "",
            "### Rejections By Stage",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(api_semantic_stats.get("rejections_by_stage", {})), "Stage"))
    lines.extend(
        [
            "",
            "## Inferred Layout Hints",
            "",
            "- Hints: `%s` across `%s` functions"
            % (layout_totals.get("hints", 0), layout_totals.get("functions_with_hints", 0)),
            "- Named-base hints: `%s`" % layout_totals.get("named_base_hints", 0),
            "- Temp-base hints: `%s`" % layout_totals.get("temp_base_hints", 0),
            "- Offset observations: `%s`" % layout_totals.get("offset_observations", 0),
            "",
            "### Top Layout Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(layout_hint_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Observed Layout Types",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(layout_hint_stats.get("observed_types", {})), "Type"))
    lines.extend(
        [
            "",
            "### Highest Layout Hint Functions",
            "",
            "| Function | EA | Hints | Max offsets | Max accesses | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for item in layout_hint_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("hint_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Text Residue",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(text_stats, "Metric"))
    lines.extend(
        [
            "",
            "## Highest Warning Functions",
            "",
            "| Function | EA | Warnings | Top classes |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for item in report.get("top_warning_functions", []) or []:
        if not isinstance(item, dict):
            continue
        classes = ", ".join("%s=%s" % (key, value) for key, value in _coerce_dict(item.get("warning_classes", {})).items())
        lines.append(
            "| `%s` | `%s` | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("warning_count", 0) or 0),
                classes,
            )
        )
    lines.append("")
    return "\n".join(lines)


def _iter_summary_paths(functions_root: Path):
    if not functions_root.exists():
        return
    yield from sorted(functions_root.rglob("*.ida-batch-summary.json"))


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


def _read_warnings(path: Path) -> list[str]:
    data = _read_json(path)
    if isinstance(data, list):
        return [str(item) for item in data]
    if isinstance(data, dict) and isinstance(data.get("warnings"), list):
        return [str(item) for item in data.get("warnings", [])]
    return []


def _read_list(path: Path) -> list[Any]:
    data = _read_json(path)
    if isinstance(data, list):
        return data
    return []


def _read_rename_items(path: Path) -> list[dict[str, Any]]:
    data = _read_json(path)
    if isinstance(data, dict):
        data = data.get("renames", [])
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _update_rename_metrics(
    rename_items: list[dict[str, Any]],
    sources: Counter[str],
    applied_sources: Counter[str],
) -> None:
    for item in rename_items:
        source = str(item.get("source", "") or "unknown")
        sources[source] += 1
        if _rename_applied(item):
            applied_sources[source] += 1


def _rename_applied(item: dict[str, Any]) -> bool:
    if "apply" not in item:
        return True
    return bool(item.get("apply"))


def _update_rule_metrics(rule_report: dict[str, Any], rewrite_kinds: Counter[str], totals: Counter[str]) -> None:
    rewrite_emissions = [item for item in rule_report.get("rewrite_emissions", []) or [] if isinstance(item, dict)]
    totals["rule_rewrite_emissions"] += len(rewrite_emissions)
    totals["rule_rejected_emissions"] += len(rule_report.get("rejected_emissions", []) or [])
    totals["rule_load_errors"] += len(rule_report.get("load_errors", []) or [])
    totals["rule_validation_errors"] += len(rule_report.get("validation_errors", []) or [])
    for item in rewrite_emissions:
        rewrite_kinds[str(item.get("kind", "") or "unknown")] += 1


def _update_api_semantic_metrics(
    rule_report: dict[str, Any],
    reasons: Counter[str],
    stages: Counter[str],
    statuses: Counter[str],
    totals: Counter[str],
) -> int:
    diagnostics = [
        item
        for item in rule_report.get("api_semantic_diagnostics", []) or []
        if isinstance(item, dict)
    ]
    for item in diagnostics:
        totals["api_semantic_diagnostics"] += 1
        status = str(item.get("status", "") or "unknown")
        statuses[status] += 1
        if status != "rejected":
            continue
        totals["api_semantic_rejections"] += 1
        reasons[str(item.get("reason", "") or "unknown")] += 1
        stages[str(item.get("stage", "") or "unknown")] += 1
    return len(diagnostics)


def _update_text_metrics(text_totals: Counter[str], path: Path) -> list[dict[str, Any]]:
    text = _read_text(path)
    if not text:
        return []
    _count_pattern(text_totals, text, GENERIC_IDENTIFIER_RE, "generic_identifier_tokens", "functions_with_generic_identifiers")
    _count_pattern(text_totals, text, OFFSET_DEREF_RE, "offset_deref_patterns", "functions_with_offset_derefs")
    _count_pattern(text_totals, text, LABEL_RE, "label_tokens", "functions_with_labels")
    _count_pattern(
        text_totals,
        text,
        DECIMAL_STATUS_RE,
        "decimal_status_like_literals",
        "functions_with_decimal_status_like_literals",
    )
    _count_pattern(text_totals, text, HEX_STATUS_RE, "hex_status_like_literals", "functions_with_hex_status_like_literals")
    layout_hints = _extract_layout_hints(text)
    text_totals["inferred_offset_layout_hints"] += len(layout_hints)
    if layout_hints:
        text_totals["functions_with_inferred_offset_layout_hints"] += 1
    _count_pattern(
        text_totals,
        text,
        FIELD_PREVIEW_RE,
        "inferred_offset_field_previews",
        "functions_with_inferred_offset_field_previews",
    )
    return layout_hints


def _count_pattern(
    counter: Counter[str],
    text: str,
    pattern: re.Pattern[str],
    token_key: str,
    function_key: str,
) -> None:
    count = len(pattern.findall(text))
    counter[token_key] += count
    if count:
        counter[function_key] += 1


def _extract_layout_hints(text: str) -> list[dict[str, Any]]:
    hints = []
    for match in LAYOUT_HINT_RE.finditer(text or ""):
        hint = {
            "base": match.group("base"),
            "access_count": _int_value(match.group("access_count"), 0),
            "offset_count": _int_value(match.group("offset_count"), 0),
            "confidence": _float_value(match.group("confidence"), 0.0),
            "review": match.group("review"),
            "types": _parse_layout_hint_types(match.group("types")),
        }
        hints.append(hint)
    return hints


def _parse_layout_hint_types(value: str) -> list[str]:
    result = []
    for item in str(value or "").split(","):
        type_name = item.strip().strip(".")
        if not type_name or type_name == "...":
            continue
        result.append(type_name)
    return result


def _update_layout_hint_metrics(
    hints: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    types: Counter[str],
) -> None:
    if not hints:
        return
    totals["functions_with_hints"] += 1
    for hint in hints:
        totals["hints"] += 1
        totals["access_observations"] += _int_value(hint.get("access_count"), 0)
        totals["offset_observations"] += _int_value(hint.get("offset_count"), 0)
        base = str(hint.get("base", "") or "unknown")
        bases[base] += 1
        if _is_decompiler_temp_base(base):
            totals["temp_base_hints"] += 1
        else:
            totals["named_base_hints"] += 1
        if _int_value(hint.get("offset_count"), 0) >= 8:
            totals["large_offset_hints"] += 1
        for type_name in hint.get("types", []) or []:
            types[str(type_name)] += 1


def _layout_hint_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    hints: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "ea": ea,
        "name": name,
        "hint_count": len(hints),
        "bases": [str(item.get("base", "") or "unknown") for item in hints[:8]],
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in hints), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in hints), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in hints), default=0.0),
        "summary_path": str(summary_path),
    }


def _is_decompiler_temp_base(name: str) -> bool:
    return re.fullmatch(r"[av]\d+", str(name or "")) is not None


def _classify_warning(warning: str) -> str:
    text = str(warning)
    lowered = text.lower()
    if "skipped pascalcase llm rename" in lowered:
        return "llm_pascal_case"
    if "low confidence" in lowered:
        return "llm_low_confidence"
    if "skipped generic argument rename" in lowered:
        return "llm_generic_argument"
    if "skipped weak argument rename" in lowered:
        return "llm_weak_argument"
    if "unsupported saved-argument" in lowered:
        return "llm_saved_argument_copy"
    if "value-invariant" in lowered:
        return "llm_value_invariant"
    if "pointer-bound" in lowered:
        return "llm_pointer_bound"
    if "dispatcher" in lowered and "rename" in lowered:
        return "llm_dispatcher_context"
    if "skipped duplicate target" in lowered:
        return "rename_duplicate_target"
    if "skipped colliding rename" in lowered:
        return "rename_collision"
    if "skipped invalid identifier" in lowered:
        return "rename_invalid_identifier"
    if "skipped missing identifier" in lowered:
        return "rename_missing_identifier"
    if "skipped noop rename" in lowered:
        return "rename_noop"
    if "potential bad call target" in lowered:
        return "call_target_review"
    if "deterministic rule pack rejected" in lowered:
        return "rule_pack_rejected"
    if "deterministic rule emission rejected" in lowered:
        return "rule_emission_rejected"
    return "other"


def _markdown_counter_table(counter: dict[str, Any], label: str) -> list[str]:
    if not counter:
        return ["No data."]
    lines = [
        "| %s | Count |" % label,
        "| --- | ---: |",
    ]
    for key, value in counter.items():
        lines.append("| `%s` | %s |" % (key, value))
    return lines


def _coerce_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _int_value(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)


def _float_value(value: Any, fallback: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(fallback)


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(float(numerator) * 100.0 / float(denominator), 2)


def _counter_to_dict(counter: Counter[str]) -> dict[str, int]:
    return {str(key): int(value) for key, value in counter.most_common()}


if __name__ == "__main__":
    raise SystemExit(main())

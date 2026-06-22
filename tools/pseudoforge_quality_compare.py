from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.version import VERSION, plugin_title


METRIC_SPECS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("summaries", ("totals", "summaries"), "same"),
    ("warnings", ("totals", "warnings"), "lower"),
    ("functions_with_warnings", ("totals", "functions_with_warnings"), "lower"),
    ("rename_candidates", ("totals", "rename_candidates"), "neutral"),
    ("applied_renames", ("totals", "applied_renames"), "higher"),
    ("rename_apply_rate", ("rename_stats", "apply_rate"), "higher"),
    ("llm_apply_rate", ("rename_stats", "llm_apply_rate"), "higher"),
    ("generic_identifier_tokens", ("text_stats", "generic_identifier_tokens"), "lower"),
    ("body_generic_identifier_tokens", ("body_text_stats", "generic_identifier_tokens"), "lower"),
    ("decimal_status_like_literals", ("text_stats", "decimal_status_like_literals"), "lower"),
    ("body_decimal_status_like_literals", ("body_text_stats", "decimal_status_like_literals"), "lower"),
    ("hex_status_like_literals", ("text_stats", "hex_status_like_literals"), "lower"),
    ("body_hex_status_like_literals", ("body_text_stats", "hex_status_like_literals"), "lower"),
    ("profiled_status_argument_literals", ("text_stats", "profiled_status_argument_literals"), "lower"),
    ("body_profiled_status_argument_literals", ("body_text_stats", "profiled_status_argument_literals"), "lower"),
    ("offset_deref_patterns", ("text_stats", "offset_deref_patterns"), "lower"),
    ("body_offset_deref_patterns", ("body_text_stats", "offset_deref_patterns"), "lower"),
    ("label_tokens", ("text_stats", "label_tokens"), "lower"),
    ("body_label_tokens", ("body_text_stats", "label_tokens"), "lower"),
    ("inferred_offset_layout_hints", ("text_stats", "inferred_offset_layout_hints"), "neutral"),
    ("inferred_offset_field_previews", ("text_stats", "inferred_offset_field_previews"), "neutral"),
    ("inferred_offset_field_aliases", ("text_stats", "inferred_offset_field_aliases"), "neutral"),
    ("inferred_offset_subfield_overlays", ("text_stats", "inferred_offset_subfield_overlays"), "neutral"),
    ("inferred_offset_rewrite_ready", ("text_stats", "inferred_offset_rewrite_ready"), "higher"),
    ("inferred_offset_rewrite_previews", ("text_stats", "inferred_offset_rewrite_previews"), "higher"),
    ("inferred_offset_rewrite_near_ready", ("text_stats", "inferred_offset_rewrite_near_ready"), "neutral"),
    ("inferred_offset_rewrite_blockers", ("text_stats", "inferred_offset_rewrite_blockers"), "lower"),
    (
        "layout_preview_artifacts",
        ("layout_rewrite_preview_artifact_stats", "totals", "preview_artifacts"),
        "higher",
    ),
    (
        "layout_preview_validation_errors",
        ("layout_rewrite_preview_artifact_stats", "totals", "validation_errors"),
        "lower",
    ),
    (
        "canonical_layout_rewrite_applied",
        ("layout_rewrite_preview_artifact_stats", "totals", "canonical_rewrite_applied"),
        "higher",
    ),
    (
        "canonical_layout_rewrite_errors",
        ("layout_rewrite_preview_artifact_stats", "totals", "canonical_rewrite_errors"),
        "lower",
    ),
    (
        "layout_rewritten_accesses",
        ("layout_rewrite_preview_artifact_stats", "totals", "rewritten_accesses"),
        "higher",
    ),
    (
        "layout_rewritten_fields",
        ("layout_rewrite_preview_artifact_stats", "totals", "rewritten_fields"),
        "higher",
    ),
    (
        "prototype_function_identity_candidates",
        ("prototype_correction_stats", "totals", "function_identity_candidates"),
        "neutral",
    ),
    (
        "prototype_parameter_type_corrections_applied",
        ("prototype_correction_stats", "totals", "applied_parameter_type_corrections"),
        "higher",
    ),
    (
        "prototype_parameter_type_corrections_blocked",
        ("prototype_correction_stats", "totals", "blocked_parameter_type_corrections"),
        "neutral",
    ),
    (
        "prototype_generic_parameter_survivors",
        ("prototype_correction_stats", "totals", "generic_parameter_survivors"),
        "lower",
    ),
    (
        "prototype_offset_deref_survivors",
        ("prototype_correction_stats", "totals", "offset_deref_survivors"),
        "lower",
    ),
    (
        "prototype_body_rewrite_ready",
        ("prototype_correction_stats", "totals", "body_rewrite_ready"),
        "higher",
    ),
    (
        "prototype_negative_controls",
        ("prototype_correction_stats", "totals", "negative_control_functions"),
        "neutral",
    ),
    ("api_semantic_rejections", ("api_semantic_stats", "rejections"), "lower"),
)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    report = compare_quality_reports(args.old, args.new)
    outputs = []
    if args.out:
        output_dir = Path(args.out)
        output_dir.mkdir(parents=True, exist_ok=True)
        if args.format in {"json", "both"}:
            json_path = output_dir / "quality-compare.json"
            json_path.write_text(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
            outputs.append(str(json_path))
        if args.format in {"markdown", "both"}:
            markdown_path = output_dir / "quality-compare.md"
            markdown_path.write_text(render_compare_markdown(report), encoding="utf-8")
            outputs.append(str(markdown_path))
        print("Wrote quality comparison: %s" % ", ".join(outputs))
        return 0
    if args.format == "markdown":
        print(render_compare_markdown(report))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare two PseudoForge corpus-quality.json reports.")
    parser.add_argument("--version", action="version", version=plugin_title())
    parser.add_argument("--old", required=True, help="Baseline corpus-quality.json path.")
    parser.add_argument("--new", required=True, help="New corpus-quality.json path.")
    parser.add_argument("--out", default="", help="Optional output directory for quality-compare.json/md.")
    parser.add_argument(
        "--format",
        choices=("json", "markdown", "both"),
        default="json",
        help="Output format. With --out, both writes JSON and Markdown.",
    )
    return parser


def compare_quality_reports(old_path: str | Path, new_path: str | Path) -> dict[str, Any]:
    old = _read_report(old_path)
    new = _read_report(new_path)
    metrics = []
    for label, path, direction in METRIC_SPECS:
        old_value = _read_metric(old, path)
        new_value = _read_metric(new, path)
        delta = _metric_delta(old_value, new_value)
        metrics.append(
            {
                "name": label,
                "path": list(path),
                "direction": direction,
                "old": old_value,
                "new": new_value,
                "delta": delta,
                "delta_percent": _metric_delta_percent(old_value, delta),
                "status": _metric_status(direction, delta),
            }
        )
    return {
        "schema": "pseudoforge_quality_compare_v1",
        "pseudoforge_version": VERSION,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "old_path": str(old_path),
        "new_path": str(new_path),
        "old_corpus_root": old.get("corpus_root", ""),
        "new_corpus_root": new.get("corpus_root", ""),
        "same_function_count": _read_metric(old, ("totals", "summaries"))
        == _read_metric(new, ("totals", "summaries")),
        "metrics": metrics,
        "summary": _status_counts(metrics),
    }


def render_compare_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# PseudoForge Quality Comparison",
        "",
        "- Old: `%s`" % report.get("old_path", ""),
        "- New: `%s`" % report.get("new_path", ""),
        "- Same function count: `%s`" % str(bool(report.get("same_function_count"))).lower(),
        "",
        "## Summary",
        "",
    ]
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    if summary:
        for key, value in summary.items():
            lines.append("- %s: `%s`" % (key, value))
    else:
        lines.append("No summary data.")
    lines.extend(
        [
            "",
            "## Metrics",
            "",
            "| Metric | Direction | Old | New | Delta | Delta % | Status |",
            "| --- | --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for item in report.get("metrics", []) or []:
        if not isinstance(item, dict):
            continue
        lines.append(
            "| `%s` | %s | %s | %s | %s | %s | `%s` |"
            % (
                item.get("name", ""),
                item.get("direction", ""),
                _markdown_value(item.get("old")),
                _markdown_value(item.get("new")),
                _markdown_value(item.get("delta")),
                _markdown_value(item.get("delta_percent")),
                item.get("status", ""),
            )
        )
    lines.append("")
    return "\n".join(lines)


def _read_report(path: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit("failed to read quality report %s: %s" % (path, exc)) from exc
    if not isinstance(data, dict):
        raise SystemExit("quality report is not a JSON object: %s" % path)
    return data


def _read_metric(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = data
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _metric_delta(old_value: Any, new_value: Any) -> float | int | None:
    if isinstance(old_value, (int, float)) and isinstance(new_value, (int, float)):
        return new_value - old_value
    return None


def _metric_delta_percent(old_value: Any, delta: float | int | None) -> float | None:
    if delta is None or not isinstance(old_value, (int, float)) or old_value == 0:
        return None
    return round(float(delta) * 100.0 / float(old_value), 2)


def _metric_status(direction: str, delta: float | int | None) -> str:
    if delta is None or direction == "neutral":
        return "info"
    if delta == 0:
        return "unchanged"
    if direction == "same":
        return "matched" if delta == 0 else "changed"
    if direction == "lower":
        return "improved" if delta < 0 else "regressed"
    if direction == "higher":
        return "improved" if delta > 0 else "regressed"
    return "info"


def _status_counts(metrics: list[dict[str, Any]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for item in metrics:
        status = str(item.get("status", "") or "info")
        result[status] = result.get(status, 0) + 1
    return dict(sorted(result.items()))


def _markdown_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return "%.2f" % value
    return str(value).replace("|", "\\|")


if __name__ == "__main__":
    raise SystemExit(main())

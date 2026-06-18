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
from tools.pseudoforge_corpus_quality import (
    DECIMAL_STATUS_RE,
    FIELD_BASE_STABILITY_DETAIL_RE,
    FIELD_BASE_STABILITY_RE,
    FIELD_REWRITE_BLOCKER_DETAIL_RE,
    FIELD_REWRITE_BLOCKER_RE,
    FIELD_REWRITE_NEAR_READY_DETAIL_RE,
    FIELD_REWRITE_NEAR_READY_RE,
    FIELD_REWRITE_PARTIAL_OPPORTUNITY_DETAIL_RE,
    FIELD_REWRITE_PARTIAL_OPPORTUNITY_RE,
    FIELD_STABLE_BASE_SOURCE_DETAIL_RE,
    FIELD_STABLE_BASE_SOURCE_RE,
    GENERIC_IDENTIFIER_RE,
    HEX_STATUS_RE,
    LABEL_RE,
    OFFSET_DEREF_RE,
    _artifact_path,
    _classify_warning,
    _coerce_dict,
    _int_value,
    _iter_summary_paths,
    _parse_ea_value,
    _read_json,
    _read_text,
    _read_warnings,
    _strip_pseudoforge_header,
)

GENERIC_RESIDUE_FULL_SCORE_LIMIT = 1000
GENERIC_RESIDUE_OVERFLOW_WEIGHT = 0.002
OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT = 120
OFFSET_DEREF_LAYOUT_WEIGHT = 2.0
OFFSET_DEREF_RESIDUE_OVERFLOW_WEIGHT = 0.25
OFFSET_DEREF_NO_LAYOUT_WEIGHT = 1.0
OFFSET_DEREF_NO_LAYOUT_OVERFLOW_WEIGHT = 0.10
LABEL_RESIDUE_FULL_SCORE_LIMIT = 120
LABEL_RESIDUE_OVERFLOW_WEIGHT = 0.05
SIMPLE_OFFSET_DEREF_BASE_RE = re.compile(
    r"\*\s*\([^)]*\*\s*\)\s*\(\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?:0x[0-9A-Fa-f]+|\d+)(?:LL|i64|L)?\s*\)"
)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    plan = build_replay_plan(
        args.corpus_root,
        limit=max(1, args.limit),
        top=max(1, args.top),
    )
    if args.out:
        output_dir = Path(args.out)
        output_dir.mkdir(parents=True, exist_ok=True)
        _write_plan_outputs(plan, output_dir)
        print("Wrote replay plan: %s" % ", ".join(plan["outputs"].values()))
        return 0
    if args.format == "markdown":
        print(render_replay_plan_markdown(plan))
    else:
        print(json.dumps(plan, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a ranked PseudoForge IDA replay EA plan.")
    parser.add_argument("--version", action="version", version=plugin_title())
    parser.add_argument("--corpus-root", required=True, help="Existing PseudoForge corpus root.")
    parser.add_argument("--out", default="", help="Output directory for replay-plan.json/md and replay-eas.txt.")
    parser.add_argument("--limit", type=int, default=500, help="Number of EAs to include in the replay set.")
    parser.add_argument("--top", type=int, default=25, help="Number of top functions to show in Markdown.")
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Output format when --out is not used.",
    )
    return parser


def build_replay_plan(corpus_root: str | Path, *, limit: int = 500, top: int = 25) -> dict[str, Any]:
    root = Path(corpus_root)
    functions_root = root / "functions" if (root / "functions").exists() else root
    items = []
    for summary_path in _iter_summary_paths(functions_root):
        item = _score_summary(summary_path)
        if item is not None:
            items.append(item)
    items.sort(
        key=lambda item: (
            -float(item["score"]),
            -int(item["metrics"].get("warnings", 0)),
            -int(item["metrics"].get("body_offset_deref_patterns", 0)),
            str(item["name"]),
            str(item["ea"]),
        )
    )
    selected = items[:limit]
    reason_counts: Counter[str] = Counter()
    for item in selected:
        for reason in item.get("reasons", []) or []:
            reason_counts[str(reason)] += 1
    return {
        "schema": "pseudoforge_replay_plan_v1",
        "pseudoforge_version": VERSION,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "corpus_root": str(root),
        "functions_root": str(functions_root),
        "limit": int(limit),
        "selected_count": len(selected),
        "candidate_count": len(items),
        "reason_counts": dict(sorted(reason_counts.items())),
        "score_model": _score_model(),
        "items": selected,
        "top": int(top),
        "recommended_commands": _recommended_commands(str(root), "replay-eas.txt"),
    }


def render_replay_plan_markdown(plan: dict[str, Any]) -> str:
    lines = [
        "# PseudoForge Replay Plan",
        "",
        "- Corpus root: `%s`" % plan.get("corpus_root", ""),
        "- Selected functions: `%s` / `%s`" % (plan.get("selected_count", 0), plan.get("candidate_count", 0)),
        "- Limit: `%s`" % plan.get("limit", 0),
        "",
        "## Reason Counts",
        "",
    ]
    reason_counts = _coerce_dict(plan.get("reason_counts", {}))
    if reason_counts:
        for key, value in reason_counts.items():
            lines.append("- `%s`: `%s`" % (key, value))
    else:
        lines.append("No selected reasons.")
    lines.extend(
        [
            "",
            "## Top Functions",
            "",
            (
                "| Rank | Function | EA | Score | Warnings | Rename gap | Body generics | "
                "Body offsets | Layout offsets | Non-layout offsets | Body labels | Reasons |"
            ),
            "| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for index, item in enumerate(plan.get("items", [])[: int(plan.get("top", 25) or 25)], start=1):
        if not isinstance(item, dict):
            continue
        metrics = _coerce_dict(item.get("metrics", {}))
        lines.append(
            "| %d | `%s` | `%s` | %.2f | %d | %d | %d | %d | %d | %d | %d | %s |"
            % (
                index,
                item.get("name", ""),
                item.get("ea", ""),
                float(item.get("score", 0.0) or 0.0),
                int(metrics.get("warnings", 0) or 0),
                int(metrics.get("rename_gap", 0) or 0),
                int(metrics.get("body_generic_identifier_tokens", 0) or 0),
                int(metrics.get("body_offset_deref_patterns", 0) or 0),
                int(metrics.get("body_offset_deref_layout_actionable_patterns", 0) or 0),
                int(metrics.get("body_offset_deref_bulk_noise_patterns", 0) or 0),
                int(metrics.get("body_label_tokens", 0) or 0),
                ", ".join("`%s`" % reason for reason in item.get("reasons", []) or []),
            )
        )
    lines.extend(
        [
            "",
            "## Recommended Commands",
            "",
        ]
    )
    for command in plan.get("recommended_commands", []) or []:
        lines.extend(["```powershell", str(command), "```", ""])
    return "\n".join(lines)


def _write_plan_outputs(plan: dict[str, Any], output_dir: Path) -> dict[str, str]:
    ea_path = output_dir / "replay-eas.txt"
    json_path = output_dir / "replay-plan.json"
    markdown_path = output_dir / "replay-plan.md"
    outputs = {
        "ea_file": str(ea_path),
        "json": str(json_path),
        "markdown": str(markdown_path),
    }
    plan["outputs"] = outputs
    plan["recommended_commands"] = _recommended_commands(str(plan.get("corpus_root", "")), str(ea_path))
    ea_path.write_text(
        "\n".join(str(item.get("ea", "")) for item in plan.get("items", []) if item.get("ea")) + "\n",
        encoding="utf-8",
    )
    json_path.write_text(json.dumps(plan, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(render_replay_plan_markdown(plan), encoding="utf-8")
    return outputs


def _score_summary(summary_path: Path) -> dict[str, Any] | None:
    summary = _coerce_dict(_read_json(summary_path))
    if not summary:
        return None
    ea_value = _parse_ea_value(summary.get("function_ea"))
    if ea_value is None:
        ea_value = _parse_ea_value(str(summary_path.parent.name).split("_", 1)[0])
    if ea_value is None:
        return None
    artifacts = _coerce_dict(summary.get("artifacts", {}))
    warnings = _read_warnings(_artifact_path(summary_path, artifacts, "warnings"))
    cleaned_text = _read_text(_artifact_path(summary_path, artifacts, "cleaned_pseudocode"))
    body_text = _strip_pseudoforge_header(cleaned_text)
    warning_classes = Counter(_classify_warning(item) for item in warnings)
    rename_candidates = _int_value(summary.get("rename_candidates"), 0)
    applied_renames = _int_value(summary.get("renames"), 0)
    partial_opportunities = _layout_partial_opportunity_counts(cleaned_text)
    body_generic_tokens = len(GENERIC_IDENTIFIER_RE.findall(body_text))
    body_label_tokens = len(LABEL_RE.findall(body_text))
    layout_actionable_bases = _layout_actionable_bases(cleaned_text)
    offset_base_counts = _simple_offset_deref_base_counts(body_text)
    simple_base_offset_derefs = sum(offset_base_counts.values())
    legacy_offset_derefs = len(OFFSET_DEREF_RE.findall(body_text))
    body_offset_derefs = max(legacy_offset_derefs, simple_base_offset_derefs)
    layout_actionable_base_offset_derefs = sum(
        count for base, count in offset_base_counts.items() if base in layout_actionable_bases
    )
    non_layout_base_offset_derefs = simple_base_offset_derefs - layout_actionable_base_offset_derefs
    unmatched_base_offset_derefs = max(0, body_offset_derefs - simple_base_offset_derefs)
    bulk_noise_offset_derefs = non_layout_base_offset_derefs + unmatched_base_offset_derefs
    layout_rewrite_blockers = len(FIELD_REWRITE_BLOCKER_RE.findall(cleaned_text))
    layout_rewrite_near_ready = len(FIELD_REWRITE_NEAR_READY_RE.findall(cleaned_text))
    layout_rewrite_partial_review_only = int(partial_opportunities.get("review_only", 0))
    layout_base_stability = len(FIELD_BASE_STABILITY_RE.findall(cleaned_text))
    layout_stable_base_sources = len(FIELD_STABLE_BASE_SOURCE_RE.findall(cleaned_text))
    layout_actionability_signals = (
        layout_rewrite_blockers
        + layout_rewrite_near_ready
        + layout_rewrite_partial_review_only
        + layout_base_stability
        + layout_stable_base_sources
    )
    metrics = {
        "warnings": _int_value(summary.get("warnings"), len(warnings)),
        "rename_candidates": rename_candidates,
        "applied_renames": applied_renames,
        "rename_gap": max(0, rename_candidates - applied_renames),
        "body_generic_identifier_tokens": body_generic_tokens,
        "body_generic_identifier_overflow_tokens": max(
            0,
            body_generic_tokens - GENERIC_RESIDUE_FULL_SCORE_LIMIT,
        ),
        "body_offset_deref_legacy_patterns": legacy_offset_derefs,
        "body_offset_deref_patterns": body_offset_derefs,
        "body_offset_deref_overflow_patterns": max(
            0,
            body_offset_derefs - OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT,
        ),
        "body_offset_deref_simple_base_patterns": simple_base_offset_derefs,
        "body_offset_deref_layout_actionable_patterns": layout_actionable_base_offset_derefs,
        "body_offset_deref_layout_actionable_overflow_patterns": max(
            0,
            layout_actionable_base_offset_derefs - OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT,
        ),
        "body_offset_deref_non_layout_base_patterns": non_layout_base_offset_derefs,
        "body_offset_deref_unmatched_base_patterns": unmatched_base_offset_derefs,
        "body_offset_deref_bulk_noise_patterns": bulk_noise_offset_derefs,
        "body_offset_deref_bulk_noise_overflow_patterns": max(
            0,
            bulk_noise_offset_derefs - OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT,
        ),
        "body_label_tokens": body_label_tokens,
        "body_label_overflow_tokens": max(0, body_label_tokens - LABEL_RESIDUE_FULL_SCORE_LIMIT),
        "body_decimal_status_like_literals": len(DECIMAL_STATUS_RE.findall(body_text)),
        "body_hex_status_like_literals": len(HEX_STATUS_RE.findall(body_text)),
        "layout_actionability_bases": len(layout_actionable_bases),
        "layout_actionability_signals": layout_actionability_signals,
        "layout_rewrite_blockers": layout_rewrite_blockers,
        "layout_rewrite_near_ready": layout_rewrite_near_ready,
        "layout_rewrite_partial_opportunities": int(partial_opportunities.get("total", 0)),
        "layout_rewrite_partial_review_only": layout_rewrite_partial_review_only,
        "layout_rewrite_partial_validated_applied": int(
            partial_opportunities.get("validated_partial_applied", 0)
        ),
        "layout_base_stability": layout_base_stability,
        "layout_stable_base_sources": layout_stable_base_sources,
        "llm_fallback": 1 if str(summary.get("llm_status", "") or "") == "fallback" else 0,
    }
    score, reasons = _score_metrics(metrics, warning_classes)
    return {
        "ea": "0x%X" % ea_value,
        "name": str(summary.get("function", "") or summary_path.parent.name),
        "score": round(score, 2),
        "reasons": reasons,
        "warning_classes": dict(warning_classes.most_common(8)),
        "metrics": metrics,
        "summary_path": str(summary_path),
    }


def _layout_partial_opportunity_counts(text: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for match in FIELD_REWRITE_PARTIAL_OPPORTUNITY_DETAIL_RE.finditer(text or ""):
        counts["total"] += 1
        disposition = str(match.groupdict().get("disposition") or "")
        if "Validated partial layout rewrite applied" in disposition:
            counts["validated_partial_applied"] += 1
        else:
            counts["review_only"] += 1
    if not counts:
        total = len(FIELD_REWRITE_PARTIAL_OPPORTUNITY_RE.findall(text or ""))
        if total:
            counts["total"] = total
            counts["review_only"] = total
    return counts


def _layout_actionable_bases(text: str) -> set[str]:
    bases: set[str] = set()
    for pattern in (
        FIELD_REWRITE_BLOCKER_DETAIL_RE,
        FIELD_REWRITE_NEAR_READY_DETAIL_RE,
        FIELD_BASE_STABILITY_DETAIL_RE,
        FIELD_STABLE_BASE_SOURCE_DETAIL_RE,
    ):
        for match in pattern.finditer(text or ""):
            base = str(match.groupdict().get("base") or "")
            if base:
                bases.add(base)
    for match in FIELD_REWRITE_PARTIAL_OPPORTUNITY_DETAIL_RE.finditer(text or ""):
        disposition = str(match.groupdict().get("disposition") or "")
        if "Validated partial layout rewrite applied" in disposition:
            continue
        base = str(match.groupdict().get("base") or "")
        if base:
            bases.add(base)
    return bases


def _simple_offset_deref_base_counts(text: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for match in SIMPLE_OFFSET_DEREF_BASE_RE.finditer(text or ""):
        base = str(match.groupdict().get("base") or "")
        if base:
            counts[base] += 1
    return counts


def _score_metrics(metrics: dict[str, int], warning_classes: Counter[str]) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    score += metrics["warnings"] * 4.0
    score += metrics["rename_gap"] * 1.5
    score += _residue_score(
        metrics["body_generic_identifier_tokens"],
        0.02,
        GENERIC_RESIDUE_FULL_SCORE_LIMIT,
        GENERIC_RESIDUE_OVERFLOW_WEIGHT,
    )
    score += _offset_deref_residue_score(metrics)
    score += _residue_score(
        metrics["body_label_tokens"],
        1.0,
        LABEL_RESIDUE_FULL_SCORE_LIMIT,
        LABEL_RESIDUE_OVERFLOW_WEIGHT,
    )
    score += metrics["body_decimal_status_like_literals"] * 6.0
    score += metrics["body_hex_status_like_literals"] * 3.0
    score += metrics["layout_rewrite_blockers"] * 10.0
    score += metrics["layout_rewrite_near_ready"] * 8.0
    score += metrics["layout_rewrite_partial_review_only"] * 12.0
    score += metrics["layout_base_stability"] * 8.0
    score += metrics["layout_stable_base_sources"] * 4.0
    score += metrics["llm_fallback"] * 25.0
    score += warning_classes.get("llm_pascal_case", 0) * 2.0
    score += warning_classes.get("llm_dispatcher_context", 0) * 1.5
    if metrics["warnings"]:
        reasons.append("warnings")
    if metrics["rename_gap"] >= 8:
        reasons.append("rename_gap")
    if metrics["body_generic_identifier_tokens"] >= 50:
        reasons.append("generic_residue")
    if metrics["body_offset_deref_patterns"] >= 10:
        reasons.append("offset_deref_residue")
        if metrics["body_offset_deref_layout_actionable_patterns"] >= 10:
            reasons.append("layout_actionable_offset_residue")
        if metrics["body_offset_deref_bulk_noise_patterns"] >= 10:
            reasons.append("non_layout_offset_residue")
            if metrics["body_offset_deref_bulk_noise_overflow_patterns"]:
                reasons.append("bulk_offset_residue")
    if metrics["body_label_tokens"] >= 8:
        reasons.append("label_residue")
    if (
        metrics["body_generic_identifier_overflow_tokens"]
        or metrics["body_offset_deref_overflow_patterns"]
        or metrics["body_label_overflow_tokens"]
    ):
        reasons.append("bulk_residue_saturation")
    if metrics["body_decimal_status_like_literals"] or metrics["body_hex_status_like_literals"]:
        reasons.append("status_literal_residue")
    if metrics["layout_rewrite_blockers"]:
        reasons.append("layout_blockers")
    if metrics["layout_rewrite_near_ready"] or metrics["layout_rewrite_partial_review_only"]:
        reasons.append("layout_near_ready")
    if metrics["layout_base_stability"]:
        reasons.append("layout_base_stability")
    if metrics["llm_fallback"]:
        reasons.append("llm_fallback")
    return score, reasons or ["baseline_sample"]


def _residue_score(value: int, weight: float, full_score_limit: int, overflow_weight: float) -> float:
    normalized = max(0, int(value or 0))
    full_score_value = min(normalized, full_score_limit)
    overflow_value = max(0, normalized - full_score_limit)
    return (full_score_value * weight) + (overflow_value * overflow_weight)


def _offset_deref_residue_score(metrics: dict[str, int]) -> float:
    layout_count = int(metrics["body_offset_deref_layout_actionable_patterns"] or 0)
    bulk_count = int(metrics["body_offset_deref_bulk_noise_patterns"] or 0)
    layout_full_score_count = min(layout_count, OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT)
    layout_overflow_count = max(0, layout_count - OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT)
    remaining_full_score_capacity = max(0, OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT - layout_count)
    bulk_full_score_count = min(bulk_count, remaining_full_score_capacity)
    bulk_overflow_count = max(0, bulk_count - bulk_full_score_count)
    return (
        (layout_full_score_count * OFFSET_DEREF_LAYOUT_WEIGHT)
        + (layout_overflow_count * OFFSET_DEREF_RESIDUE_OVERFLOW_WEIGHT)
        + (bulk_full_score_count * OFFSET_DEREF_NO_LAYOUT_WEIGHT)
        + (bulk_overflow_count * OFFSET_DEREF_NO_LAYOUT_OVERFLOW_WEIGHT)
    )


def _score_model() -> dict[str, Any]:
    return {
        "bulk_residue_saturation": {
            "generic_identifier_full_score_limit": GENERIC_RESIDUE_FULL_SCORE_LIMIT,
            "generic_identifier_overflow_weight": GENERIC_RESIDUE_OVERFLOW_WEIGHT,
            "offset_deref_full_score_limit": OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT,
            "offset_deref_overflow_weight": OFFSET_DEREF_RESIDUE_OVERFLOW_WEIGHT,
            "label_full_score_limit": LABEL_RESIDUE_FULL_SCORE_LIMIT,
            "label_overflow_weight": LABEL_RESIDUE_OVERFLOW_WEIGHT,
        },
        "offset_actionability": {
            "layout_signal_metrics": [
                "layout_rewrite_blockers",
                "layout_rewrite_near_ready",
                "layout_rewrite_partial_review_only",
                "layout_base_stability",
                "layout_stable_base_sources",
            ],
            "layout_base_match_metric": "body_offset_deref_layout_actionable_patterns",
            "non_layout_base_metric": "body_offset_deref_bulk_noise_patterns",
            "full_score_limit_is_shared": True,
            "layout_signal_weight": OFFSET_DEREF_LAYOUT_WEIGHT,
            "no_layout_weight": OFFSET_DEREF_NO_LAYOUT_WEIGHT,
            "no_layout_overflow_weight": OFFSET_DEREF_NO_LAYOUT_OVERFLOW_WEIGHT,
        }
    }


def _recommended_commands(corpus_root: str, ea_file_name: str) -> list[str]:
    baseline_quality = "pseudoforge_out\\top500-baseline-quality"
    replay_out = "pseudoforge_out\\top500-replay-nollm"
    replay_quality = "pseudoforge_out\\top500-replay-nollm-quality"
    compare_out = "pseudoforge_out\\top500-quality-compare"
    return [
        (
            "python -B tools\\pseudoforge_corpus_quality.py --corpus-root \"%s\" "
            "--ea-file \"%s\" --out \"%s\" --format both --top 25"
        )
        % (corpus_root, ea_file_name, baseline_quality),
        (
            "python -B tools\\pseudoforge_ida_cli.py \"$Ida\" \"$Idb\" \"%s\" "
            "--target-path \"$Target\" --pdb-path \"$PdbPath\" --ea-file \"%s\" "
            "--no-llm-renames --allow-no-llm --apply-validated-layout-rewrites --no-index"
        )
        % (replay_out, ea_file_name),
        (
            "python -B tools\\pseudoforge_corpus_quality.py --corpus-root \"%s\" "
            "--out \"%s\" --format both --top 25"
        )
        % (replay_out, replay_quality),
        (
            "python -B tools\\pseudoforge_quality_compare.py --old \"%s\\corpus-quality.json\" "
            "--new \"%s\\corpus-quality.json\" --out \"%s\" --format both"
        )
        % (baseline_quality, replay_quality, compare_out),
    ]


if __name__ == "__main__":
    raise SystemExit(main())

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

from ida_pseudoforge.core.field_layout_hints import field_layout_comments
from ida_pseudoforge.version import VERSION, plugin_title
from tools.pseudoforge_corpus_quality import (
    DECIMAL_STATUS_RE,
    FIELD_CALL_RESULT_PARAMETER_MERGE_PROVENANCE_RE,
    FIELD_BASE_MERGE_EVIDENCE_RE,
    FIELD_BASE_STABILITY_DETAIL_RE,
    FIELD_BASE_STABILITY_RE,
    FIELD_HOT_CLUSTER_DETAIL_RE,
    FIELD_HOT_CLUSTER_RE,
    FIELD_REWRITE_BLOCKER_DETAIL_RE,
    FIELD_REWRITE_BLOCKER_RE,
    FIELD_REWRITE_NEAR_READY_DETAIL_RE,
    FIELD_REWRITE_NEAR_READY_RE,
    FIELD_REWRITE_PARTIAL_OPPORTUNITY_DETAIL_RE,
    FIELD_REWRITE_PARTIAL_OPPORTUNITY_RE,
    FIELD_SAME_SOURCE_FAMILY_MERGE_DOMINANCE_RE,
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
OFFSET_DEREF_DOMAIN_IDENTITY_WEIGHT = 1.5
OFFSET_DEREF_DOMAIN_IDENTITY_OVERFLOW_WEIGHT = 0.15
OFFSET_DEREF_SOURCE_IDENTITY_WEIGHT = 1.25
OFFSET_DEREF_SOURCE_IDENTITY_OVERFLOW_WEIGHT = 0.12
OFFSET_DEREF_NO_LAYOUT_WEIGHT = 1.0
OFFSET_DEREF_NO_LAYOUT_OVERFLOW_WEIGHT = 0.10
LABEL_RESIDUE_FULL_SCORE_LIMIT = 120
LABEL_RESIDUE_OVERFLOW_WEIGHT = 0.05
OFFSET_BASE_BREAKDOWN_LIMIT = 15
SOURCE_IDENTITY_QUEUE_LIMIT = 15
SOURCE_IDENTITY_QUEUE_MIN_OFFSET_DEREFS = 10
TEMP_OFFSET_BASE_PATTERN = r"[av]\d+"
ARGUMENT_OFFSET_BASE_PATTERN = r"argument\d+"
CONTEXT_OFFSET_BASE_PATTERN = r"context"
BUGCHECK_PARAMETER_OFFSET_BASE_PATTERN = r"BugCheckParameter\d+"
ARGUMENT_IDENTITY_OFFSET_BASE_PATTERN = (
    r"(?:%s|%s|%s)"
    % (
        ARGUMENT_OFFSET_BASE_PATTERN,
        CONTEXT_OFFSET_BASE_PATTERN,
        BUGCHECK_PARAMETER_OFFSET_BASE_PATTERN,
    )
)
TEMP_OFFSET_BASE_RE = re.compile(r"%s\Z" % TEMP_OFFSET_BASE_PATTERN)
ARGUMENT_OFFSET_BASE_RE = re.compile(r"%s\Z" % ARGUMENT_OFFSET_BASE_PATTERN)
CONTEXT_OFFSET_BASE_RE = re.compile(r"%s\Z" % CONTEXT_OFFSET_BASE_PATTERN)
BUGCHECK_PARAMETER_OFFSET_BASE_RE = re.compile(r"%s\Z" % BUGCHECK_PARAMETER_OFFSET_BASE_PATTERN)
ARGUMENT_IDENTITY_OFFSET_BASE_RE = re.compile(r"%s\Z" % ARGUMENT_IDENTITY_OFFSET_BASE_PATTERN)
GENERIC_OFFSET_BASE_RE = re.compile(
    r"(?:%s|%s)\Z" % (TEMP_OFFSET_BASE_PATTERN, ARGUMENT_IDENTITY_OFFSET_BASE_PATTERN)
)
SIMPLE_OFFSET_DEREF_BASE_RE = re.compile(
    r"\*\s*\([^)]*\*\s*\)\s*\(\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?:0x[0-9A-Fa-f]+|\d+)(?:LL|i64|L)?\s*\)"
)
REGISTRY_DOMAIN_ROLE_RE = re.compile(r"\bregistry_domain_role_evidence\b")
DOMAIN_STRUCTURE_IDENTITY_RE = re.compile(
    r"-\s+domain_structure_identity:\s+Domain identity for "
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*):\s+"
    r"role\s+(?P<role>[A-Za-z_][A-Za-z0-9_]*)"
    r".*?\bstructure\s+(?P<structure>[A-Za-z_][A-Za-z0-9_]*)\b"
)
FIELD_BASE_MERGE_EVIDENCE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_base_merge_evidence:\s+Base merge evidence for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:"
)
FIELD_BASE_MERGE_FAMILY_DISPOSITION_RE = re.compile(
    r"-\s+inferred_offset_base_merge_evidence:\s+Base merge evidence for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:[^\n]*?"
    r"\bSource families\s+[^\n]*?;\s+disposition\s+"
    r"(?P<disposition>[a-z_]+)\."
)
FIELD_BASE_MERGE_SHAPE_RE = re.compile(
    r"-\s+inferred_offset_base_merge_evidence:\s+Base merge evidence for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:[^\n]*?"
    r"\bMerge shape\s+(?P<shape>[a-z_]+)"
    r"\s+\((?P<risk>[a-z_]+)\s+risk\)"
)
FIELD_CALL_RESULT_PARAMETER_MERGE_PROVENANCE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_call_result_parameter_merge_provenance:\s+"
    r"Call-result/parameter merge provenance for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:"
)
FIELD_SAME_SOURCE_FAMILY_MERGE_DOMINANCE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_same_source_family_merge_dominance:\s+"
    r"Same-source-family merge dominance for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:"
)
SCALAR_OFFSET_DOMAIN_STRUCTURES = {
    "VIRTUAL_ADDRESS",
}


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
        "offset_base_breakdown": _offset_base_breakdown(selected),
        "source_identity_review_queues": _source_identity_review_queues(selected),
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
    lines.extend(_render_offset_base_breakdown(plan))
    lines.extend(_render_source_identity_review_queues(plan))
    lines.extend(
        [
            "",
            "## Top Functions",
            "",
            (
                "| Rank | Function | EA | Score | Warnings | Rename gap | Body generics | "
                "Body offsets | Layout offsets | Domain offsets | Source-id offsets | "
                "Unannotated offsets | Unmatched offsets | Body labels | Reasons |"
            ),
            (
                "| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | "
                "---: | ---: | ---: | ---: | --- |"
            ),
        ]
    )
    for index, item in enumerate(plan.get("items", [])[: int(plan.get("top", 25) or 25)], start=1):
        if not isinstance(item, dict):
            continue
        metrics = _coerce_dict(item.get("metrics", {}))
        lines.append(
            "| %d | `%s` | `%s` | %.2f | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %s |"
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
                int(metrics.get("body_offset_deref_domain_identified_base_patterns", 0) or 0),
                int(
                    metrics.get("body_offset_deref_source_identity_blocked_base_patterns", 0)
                    or 0
                ),
                int(metrics.get("body_offset_deref_non_layout_base_patterns", 0) or 0),
                int(metrics.get("body_offset_deref_unmatched_base_patterns", 0) or 0),
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


def _render_offset_base_breakdown(plan: dict[str, Any]) -> list[str]:
    breakdown = _coerce_dict(plan.get("offset_base_breakdown", {}))
    if not breakdown:
        return []
    lines = ["", "## Offset Base Breakdown", ""]
    for title, key in (
        ("Top layout-actionable bases", "top_layout_actionable_bases"),
        ("Top domain-identified residual bases", "top_domain_identified_bases"),
        ("Top source-identity-blocked bases", "top_source_identity_blocked_bases"),
        ("Top unannotated bases", "top_unannotated_bases"),
        ("Top unannotated argument-identity bases", "top_unannotated_argument_identity_bases"),
        ("Top unannotated context bases", "top_unannotated_context_bases"),
        ("Top unannotated argument bases", "top_unannotated_argument_bases"),
        ("Top unannotated bugcheck bases", "top_unannotated_bugcheck_bases"),
        ("Top unannotated temp bases", "top_unannotated_temp_bases"),
        ("Top unannotated named bases", "top_unannotated_named_bases"),
        ("Top annotated scalar/code-pointer bases", "top_annotated_scalar_bases"),
        ("Top projected hot cluster bases", "top_projected_hot_cluster_bases"),
    ):
        entries = breakdown.get(key, []) or []
        lines.append("### %s" % title)
        lines.append("")
        if not isinstance(entries, list) or not entries:
            lines.append("No bases.")
            lines.append("")
            continue
        lines.append("| Base | Offset derefs |")
        lines.append("| --- | ---: |")
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            lines.append("| `%s` | %d |" % (entry.get("base", ""), int(entry.get("count", 0) or 0)))
        lines.append("")
    return lines


def _render_source_identity_review_queues(plan: dict[str, Any]) -> list[str]:
    queues = _coerce_dict(plan.get("source_identity_review_queues", {}))
    if not queues:
        return []
    lines = ["", "## Source Identity Review Queues", ""]
    for title, key in (
        ("Source-identity-blocked bases", "source_identity_blocked"),
        ("Context parameter candidates", "context"),
        ("Argument parameter candidates", "argument"),
        ("Bugcheck parameter pointer candidates", "bugcheck"),
    ):
        entries = queues.get(key, []) or []
        lines.append("### %s" % title)
        lines.append("")
        if not isinstance(entries, list) or not entries:
            lines.append("No candidates.")
            lines.append("")
            continue
        lines.append(
            (
                "| Function | EA | Base | Offset derefs | Projected hot cluster accesses | "
                "Function layout offsets | Function blockers | Merge shape | Disposition |"
            )
        )
        lines.append("| --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |")
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            lines.append(
                "| `%s` | `%s` | `%s` | %d | %d | %d | %d | `%s` | `%s` |"
                % (
                    entry.get("function", ""),
                    entry.get("ea", ""),
                    entry.get("base", ""),
                    int(entry.get("offset_derefs", 0) or 0),
                    int(entry.get("projected_hot_cluster_accesses", 0) or 0),
                    int(entry.get("layout_actionable_offset_derefs", 0) or 0),
                    int(entry.get("layout_blockers", 0) or 0),
                    entry.get("merge_shape", ""),
                    entry.get("disposition", ""),
                )
            )
        lines.append("")
    return lines


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


def _offset_base_breakdown(items: list[dict[str, Any]]) -> dict[str, Any]:
    layout_actionable: Counter[str] = Counter()
    domain_identified: Counter[str] = Counter()
    source_identity_blocked: Counter[str] = Counter()
    unannotated: Counter[str] = Counter()
    unannotated_argument_identity: Counter[str] = Counter()
    unannotated_context: Counter[str] = Counter()
    unannotated_argument: Counter[str] = Counter()
    unannotated_bugcheck: Counter[str] = Counter()
    unannotated_temp: Counter[str] = Counter()
    unannotated_named: Counter[str] = Counter()
    annotated_scalar: Counter[str] = Counter()
    projected_hot_cluster: Counter[str] = Counter()
    for item in items:
        if not isinstance(item, dict):
            continue
        offset_base_counts = _coerce_dict(item.get("offset_base_counts", {}))
        for key, counter in (
            ("layout_actionable", layout_actionable),
            ("domain_identified", domain_identified),
            ("source_identity_blocked", source_identity_blocked),
            ("unannotated", unannotated),
            ("unannotated_argument_identity", unannotated_argument_identity),
            ("unannotated_context", unannotated_context),
            ("unannotated_argument", unannotated_argument),
            ("unannotated_bugcheck", unannotated_bugcheck),
            ("unannotated_temp", unannotated_temp),
            ("unannotated_named", unannotated_named),
            ("annotated_scalar", annotated_scalar),
            ("projected_hot_cluster", projected_hot_cluster),
        ):
            entries = offset_base_counts.get(key, []) or []
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                base = str(entry.get("base", "") or "")
                if not base:
                    continue
                counter[base] += int(entry.get("count", 0) or 0)
    return {
        "top_layout_actionable_bases": _top_counter_items(
            layout_actionable,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
        "top_domain_identified_bases": _top_counter_items(
            domain_identified,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
        "top_source_identity_blocked_bases": _top_counter_items(
            source_identity_blocked,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
        "top_unannotated_bases": _top_counter_items(
            unannotated,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
        "top_unannotated_argument_identity_bases": _top_counter_items(
            unannotated_argument_identity,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
        "top_unannotated_context_bases": _top_counter_items(
            unannotated_context,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
        "top_unannotated_argument_bases": _top_counter_items(
            unannotated_argument,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
        "top_unannotated_bugcheck_bases": _top_counter_items(
            unannotated_bugcheck,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
        "top_unannotated_temp_bases": _top_counter_items(
            unannotated_temp,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
        "top_unannotated_named_bases": _top_counter_items(
            unannotated_named,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
        "top_annotated_scalar_bases": _top_counter_items(
            annotated_scalar,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
        "top_projected_hot_cluster_bases": _top_counter_items(
            projected_hot_cluster,
            OFFSET_BASE_BREAKDOWN_LIMIT,
        ),
    }


def _source_identity_review_queues(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    queue_specs = (
        (
            "source_identity_blocked",
            "source_identity_blocked",
            "source_identity_recovery_review",
            "Trace temp/generic base assignment provenance before enabling rewrite.",
        ),
        (
            "context",
            "unannotated_context",
            "generic_parameter_trust_review",
            "Review generic context parameter identity before enabling rewrite.",
        ),
        (
            "argument",
            "unannotated_argument",
            "argument_parameter_identity_review",
            "Review argumentN parameter role before promoting layout identity.",
        ),
        (
            "bugcheck",
            "unannotated_bugcheck",
            "bugcheck_parameter_pointer_review",
            "Review bugcheck-code-specific pointer meaning before promotion.",
        ),
    )
    queues: dict[str, list[dict[str, Any]]] = {}
    for source_kind, count_key, disposition, recommended_next in queue_specs:
        rows: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            metrics = _coerce_dict(item.get("metrics", {}))
            offset_base_counts = _coerce_dict(item.get("offset_base_counts", {}))
            base_merge_evidence_bases = {
                str(entry.get("base", "") or "")
                for entry in offset_base_counts.get("base_merge_evidence", []) or []
                if isinstance(entry, dict)
            }
            same_source_family_merge_bases = {
                str(entry.get("base", "") or "")
                for entry in offset_base_counts.get("base_merge_same_source_family", []) or []
                if isinstance(entry, dict)
            }
            call_result_parameter_provenance_bases = {
                str(entry.get("base", "") or "")
                for entry in offset_base_counts.get(
                    "call_result_parameter_merge_provenance",
                    [],
                )
                or []
                if isinstance(entry, dict)
            }
            same_source_family_dominance_bases = {
                str(entry.get("base", "") or "")
                for entry in offset_base_counts.get(
                    "same_source_family_merge_dominance",
                    [],
                )
                or []
                if isinstance(entry, dict)
            }
            base_merge_shapes = _coerce_dict(item.get("base_merge_shapes", {}))
            base_merge_risks = _coerce_dict(item.get("base_merge_risks", {}))
            projected_hot_cluster_accesses = {
                str(entry.get("base", "") or ""): int(entry.get("count", 0) or 0)
                for entry in offset_base_counts.get("projected_hot_cluster", []) or []
                if isinstance(entry, dict)
            }
            entries = offset_base_counts.get(count_key, []) or []
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                base = str(entry.get("base", "") or "")
                count = int(entry.get("count", 0) or 0)
                if not base or count < SOURCE_IDENTITY_QUEUE_MIN_OFFSET_DEREFS:
                    continue
                has_base_merge_evidence = (
                    source_kind == "source_identity_blocked"
                    and base in base_merge_evidence_bases
                )
                effective_disposition = disposition
                effective_recommended_next = recommended_next
                merge_shape = ""
                merge_risk = ""
                if has_base_merge_evidence:
                    merge_shape = str(base_merge_shapes.get(base, "") or "unknown")
                    merge_risk = str(base_merge_risks.get(base, "") or "")
                    has_same_source_family_dominance = base in same_source_family_dominance_bases
                    effective_disposition = "path_sensitive_merge_review"
                    effective_recommended_next = (
                        "Review branch/call-result source dominance before promoting this "
                        "merged layout base."
                    )
                    if base in same_source_family_merge_bases:
                        effective_disposition = "same_source_family_merge_review"
                        effective_recommended_next = (
                            "Review same-source-family branch shapes before promoting this "
                            "merged layout base."
                        )
                    effective_recommended_next = _merge_shape_recommended_next(
                        merge_shape,
                        effective_recommended_next,
                    )
                    if merge_shape == "allocation_null_branch":
                        effective_disposition = "allocation_null_dominance_review"
                    elif merge_shape == "call_result_branch":
                        effective_disposition = "call_result_equivalence_review"
                    elif merge_shape == "call_result_parameter_branch":
                        effective_disposition = "parameter_provenance_review"
                    elif merge_shape == "call_result_temporary_branch":
                        effective_disposition = "temporary_provenance_review"
                    if base in call_result_parameter_provenance_bases:
                        effective_disposition = "parameter_provenance_review"
                        effective_recommended_next = (
                            "Validate parameter/call-result path dominance before "
                            "promoting this merged layout base."
                        )
                    if has_same_source_family_dominance:
                        effective_disposition = "same_source_family_dominance_review"
                        effective_recommended_next = (
                            "Validate same-root branch dominance before promoting this "
                            "merged layout base."
                        )
                rows.append(
                    {
                        "function": str(item.get("name", "") or ""),
                        "ea": str(item.get("ea", "") or ""),
                        "base": base,
                        "source_kind": source_kind,
                        "offset_derefs": count,
                        "layout_actionable_offset_derefs": int(
                            metrics.get("body_offset_deref_layout_actionable_patterns", 0)
                            or 0
                        ),
                        "projected_hot_cluster_accesses": int(
                            projected_hot_cluster_accesses.get(base, 0)
                        ),
                        "unmatched_offset_derefs": int(
                            metrics.get("body_offset_deref_unmatched_base_patterns", 0)
                            or 0
                        ),
                        "layout_blockers": int(metrics.get("layout_rewrite_blockers", 0) or 0),
                        "layout_base_stability": int(
                            metrics.get("layout_base_stability", 0) or 0
                        ),
                        "layout_base_merge_evidence": 1 if has_base_merge_evidence else 0,
                        "merge_shape": merge_shape,
                        "merge_risk": merge_risk,
                        "disposition": effective_disposition,
                        "recommended_next": effective_recommended_next,
                    }
                )
        rows.sort(
            key=lambda row: (
                -int(row.get("layout_base_merge_evidence", 0) or 0),
                -int(row["offset_derefs"]),
                -int(row["layout_actionable_offset_derefs"]),
                -int(row["layout_blockers"]),
                str(row["function"]),
                str(row["ea"]),
                str(row["base"]),
            )
        )
        queues[source_kind] = rows[:SOURCE_IDENTITY_QUEUE_LIMIT]
    return queues


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
    analysis_text = _analysis_text_with_rename_map_comments(
        cleaned_text,
        _artifact_path(summary_path, artifacts, "rename_map"),
    )
    body_text = _strip_pseudoforge_header(cleaned_text)
    warning_classes = Counter(_classify_warning(item) for item in warnings)
    rename_candidates = _int_value(summary.get("rename_candidates"), 0)
    applied_renames = _int_value(summary.get("renames"), 0)
    partial_opportunities = _layout_partial_opportunity_counts(analysis_text)
    body_generic_tokens = len(GENERIC_IDENTIFIER_RE.findall(body_text))
    body_label_tokens = len(LABEL_RE.findall(body_text))
    source_identity_blocked_bases = _source_identity_blocked_bases(analysis_text)
    layout_actionable_bases = _layout_actionable_bases(analysis_text)
    base_merge_evidence_bases = _base_merge_evidence_bases(analysis_text)
    base_merge_family_dispositions = _base_merge_family_dispositions(analysis_text)
    base_merge_shapes, base_merge_risks = _base_merge_shapes_and_risks(analysis_text)
    call_result_parameter_merge_provenance_bases = (
        _call_result_parameter_merge_provenance_bases(analysis_text)
    )
    same_source_family_merge_dominance_bases = _same_source_family_merge_dominance_bases(
        analysis_text,
    )
    domain_identified_bases = _domain_identified_offset_bases(analysis_text)
    annotated_scalar_bases = _annotated_scalar_offset_bases(analysis_text)
    domain_identified_residual_bases = (
        domain_identified_bases - layout_actionable_bases - annotated_scalar_bases
    )
    projected_hot_field_clusters = _projected_hot_field_clusters(
        analysis_text,
        layout_actionable_bases,
    )
    projected_hot_field_cluster_base_counts = Counter(
        {
            str(item.get("base", "") or "unknown"): _int_value(item.get("access_count"), 0)
            for item in projected_hot_field_clusters
        }
    )
    offset_base_counts = _simple_offset_deref_base_counts(body_text)
    simple_base_offset_derefs = sum(offset_base_counts.values())
    legacy_offset_derefs = len(OFFSET_DEREF_RE.findall(body_text))
    body_offset_derefs = max(legacy_offset_derefs, simple_base_offset_derefs)
    layout_actionable_base_offset_derefs = sum(
        count for base, count in offset_base_counts.items() if base in layout_actionable_bases
    )
    layout_actionable_base_counts = Counter(
        {base: count for base, count in offset_base_counts.items() if base in layout_actionable_bases}
    )
    annotated_scalar_base_counts = Counter(
        {base: count for base, count in offset_base_counts.items() if base in annotated_scalar_bases}
    )
    domain_identified_base_counts = Counter(
        {
            base: count
            for base, count in offset_base_counts.items()
            if base in domain_identified_residual_bases
        }
    )
    source_identity_blocked_base_counts = Counter(
        {
            base: count
            for base, count in offset_base_counts.items()
            if (
                base in source_identity_blocked_bases
                and base not in layout_actionable_bases
                and base not in domain_identified_residual_bases
                and base not in annotated_scalar_bases
            )
        }
    )
    base_merge_evidence_base_counts = Counter(
        {base: 1 for base in base_merge_evidence_bases}
    )
    base_merge_same_source_family_base_counts = Counter(
        {
            base: 1
            for base, disposition in base_merge_family_dispositions.items()
            if disposition == "same_source_family_review"
        }
    )
    unannotated_base_counts = Counter(
        {
            base: count
            for base, count in offset_base_counts.items()
            if (
                base not in layout_actionable_bases
                and base not in annotated_scalar_bases
                and base not in domain_identified_residual_bases
                and base not in source_identity_blocked_bases
            )
        }
    )
    annotated_scalar_base_offset_derefs = sum(annotated_scalar_base_counts.values())
    domain_identified_base_offset_derefs = sum(domain_identified_base_counts.values())
    source_identity_blocked_base_offset_derefs = sum(source_identity_blocked_base_counts.values())
    non_layout_base_offset_derefs = sum(unannotated_base_counts.values())
    unannotated_temp_base_counts = Counter(
        {base: count for base, count in unannotated_base_counts.items() if _is_temp_offset_base(base)}
    )
    unannotated_argument_identity_base_counts = Counter(
        {
            base: count
            for base, count in unannotated_base_counts.items()
            if _is_argument_identity_offset_base(base)
        }
    )
    unannotated_context_base_counts = Counter(
        {base: count for base, count in unannotated_base_counts.items() if _is_context_offset_base(base)}
    )
    unannotated_argument_base_counts = Counter(
        {base: count for base, count in unannotated_base_counts.items() if _is_argument_offset_base(base)}
    )
    unannotated_bugcheck_base_counts = Counter(
        {base: count for base, count in unannotated_base_counts.items() if _is_bugcheck_offset_base(base)}
    )
    unannotated_named_base_counts = Counter(
        {
            base: count
            for base, count in unannotated_base_counts.items()
            if not _is_generic_offset_base(base)
        }
    )
    unannotated_generic_base_offset_derefs = sum(
        count for base, count in unannotated_base_counts.items() if _is_generic_offset_base(base)
    )
    unannotated_temp_base_offset_derefs = sum(unannotated_temp_base_counts.values())
    unannotated_argument_identity_base_offset_derefs = sum(
        unannotated_argument_identity_base_counts.values()
    )
    unannotated_context_base_offset_derefs = sum(unannotated_context_base_counts.values())
    unannotated_argument_base_offset_derefs = sum(unannotated_argument_base_counts.values())
    unannotated_bugcheck_base_offset_derefs = sum(unannotated_bugcheck_base_counts.values())
    unannotated_named_base_offset_derefs = (
        non_layout_base_offset_derefs - unannotated_generic_base_offset_derefs
    )
    unmatched_base_offset_derefs = max(0, body_offset_derefs - simple_base_offset_derefs)
    bulk_noise_offset_derefs = non_layout_base_offset_derefs + unmatched_base_offset_derefs
    actionable_offset_derefs = (
        layout_actionable_base_offset_derefs
        + domain_identified_base_offset_derefs
        + source_identity_blocked_base_offset_derefs
        + bulk_noise_offset_derefs
    )
    layout_rewrite_blockers = len(FIELD_REWRITE_BLOCKER_RE.findall(analysis_text))
    layout_rewrite_near_ready = len(FIELD_REWRITE_NEAR_READY_RE.findall(analysis_text))
    layout_rewrite_partial_review_only = int(partial_opportunities.get("review_only", 0))
    layout_base_stability = len(FIELD_BASE_STABILITY_RE.findall(analysis_text))
    layout_base_merge_evidence = len(FIELD_BASE_MERGE_EVIDENCE_RE.findall(analysis_text))
    layout_call_result_parameter_merge_provenance = len(
        FIELD_CALL_RESULT_PARAMETER_MERGE_PROVENANCE_RE.findall(analysis_text)
    )
    layout_same_source_family_merge_dominance = len(
        FIELD_SAME_SOURCE_FAMILY_MERGE_DOMINANCE_RE.findall(analysis_text)
    )
    layout_stable_base_sources = len(FIELD_STABLE_BASE_SOURCE_RE.findall(analysis_text))
    layout_hot_field_clusters = len(FIELD_HOT_CLUSTER_RE.findall(analysis_text))
    registry_domain_profile_hits = len(REGISTRY_DOMAIN_ROLE_RE.findall(analysis_text))
    projected_hot_field_cluster_accesses = sum(projected_hot_field_cluster_base_counts.values())
    layout_actionability_signals = (
        layout_rewrite_blockers
        + layout_rewrite_near_ready
        + layout_rewrite_partial_review_only
        + layout_base_stability
        + layout_base_merge_evidence
        + layout_call_result_parameter_merge_provenance
        + layout_same_source_family_merge_dominance
        + layout_stable_base_sources
        + layout_hot_field_clusters
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
        "body_offset_deref_actionable_patterns": actionable_offset_derefs,
        "body_offset_deref_actionable_overflow_patterns": max(
            0,
            actionable_offset_derefs - OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT,
        ),
        "body_offset_deref_simple_base_patterns": simple_base_offset_derefs,
        "body_offset_deref_layout_actionable_patterns": layout_actionable_base_offset_derefs,
        "body_offset_deref_layout_actionable_overflow_patterns": max(
            0,
            layout_actionable_base_offset_derefs - OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT,
        ),
        "body_offset_deref_layout_actionable_bases": len(layout_actionable_base_counts),
        "body_offset_deref_domain_identified_base_patterns": domain_identified_base_offset_derefs,
        "body_offset_deref_domain_identified_bases": len(domain_identified_base_counts),
        "body_offset_deref_source_identity_blocked_base_patterns": (
            source_identity_blocked_base_offset_derefs
        ),
        "body_offset_deref_source_identity_blocked_bases": len(
            source_identity_blocked_base_counts
        ),
        "body_offset_deref_annotated_scalar_base_patterns": annotated_scalar_base_offset_derefs,
        "body_offset_deref_annotated_scalar_bases": len(annotated_scalar_base_counts),
        "body_offset_deref_non_layout_base_patterns": non_layout_base_offset_derefs,
        "body_offset_deref_non_layout_bases": len(unannotated_base_counts),
        "body_offset_deref_unannotated_generic_base_patterns": unannotated_generic_base_offset_derefs,
        "body_offset_deref_unannotated_temp_base_patterns": unannotated_temp_base_offset_derefs,
        "body_offset_deref_unannotated_argument_identity_base_patterns": (
            unannotated_argument_identity_base_offset_derefs
        ),
        "body_offset_deref_unannotated_context_base_patterns": (
            unannotated_context_base_offset_derefs
        ),
        "body_offset_deref_unannotated_argument_base_patterns": (
            unannotated_argument_base_offset_derefs
        ),
        "body_offset_deref_unannotated_bugcheck_base_patterns": (
            unannotated_bugcheck_base_offset_derefs
        ),
        "body_offset_deref_unannotated_named_base_patterns": unannotated_named_base_offset_derefs,
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
        "layout_base_merge_evidence": layout_base_merge_evidence,
        "layout_call_result_parameter_merge_provenance": layout_call_result_parameter_merge_provenance,
        "layout_same_source_family_merge_dominance": layout_same_source_family_merge_dominance,
        "layout_stable_base_sources": layout_stable_base_sources,
        "layout_hot_field_clusters": layout_hot_field_clusters,
        "registry_domain_profile_hits": registry_domain_profile_hits,
        "projected_layout_hot_field_clusters": len(projected_hot_field_clusters),
        "projected_layout_hot_field_cluster_bases": len(projected_hot_field_cluster_base_counts),
        "projected_layout_hot_field_cluster_accesses": projected_hot_field_cluster_accesses,
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
        "offset_base_counts": {
            "layout_actionable": _top_counter_items(
                layout_actionable_base_counts,
                len(layout_actionable_base_counts),
            ),
            "domain_identified": _top_counter_items(
                domain_identified_base_counts,
                len(domain_identified_base_counts),
            ),
            "source_identity_blocked": _top_counter_items(
                source_identity_blocked_base_counts,
                len(source_identity_blocked_base_counts),
            ),
            "base_merge_evidence": _top_counter_items(
                base_merge_evidence_base_counts,
                len(base_merge_evidence_base_counts),
            ),
            "base_merge_same_source_family": _top_counter_items(
                base_merge_same_source_family_base_counts,
                len(base_merge_same_source_family_base_counts),
            ),
            "call_result_parameter_merge_provenance": _top_counter_items(
                Counter({base: 1 for base in call_result_parameter_merge_provenance_bases}),
                len(call_result_parameter_merge_provenance_bases),
            ),
            "same_source_family_merge_dominance": _top_counter_items(
                Counter({base: 1 for base in same_source_family_merge_dominance_bases}),
                len(same_source_family_merge_dominance_bases),
            ),
            "unannotated": _top_counter_items(
                unannotated_base_counts,
                len(unannotated_base_counts),
            ),
            "unannotated_argument_identity": _top_counter_items(
                unannotated_argument_identity_base_counts,
                len(unannotated_argument_identity_base_counts),
            ),
            "unannotated_context": _top_counter_items(
                unannotated_context_base_counts,
                len(unannotated_context_base_counts),
            ),
            "unannotated_argument": _top_counter_items(
                unannotated_argument_base_counts,
                len(unannotated_argument_base_counts),
            ),
            "unannotated_bugcheck": _top_counter_items(
                unannotated_bugcheck_base_counts,
                len(unannotated_bugcheck_base_counts),
            ),
            "unannotated_temp": _top_counter_items(
                unannotated_temp_base_counts,
                len(unannotated_temp_base_counts),
            ),
            "unannotated_named": _top_counter_items(
                unannotated_named_base_counts,
                len(unannotated_named_base_counts),
            ),
            "annotated_scalar": _top_counter_items(
                annotated_scalar_base_counts,
                len(annotated_scalar_base_counts),
            ),
            "projected_hot_cluster": _top_counter_items(
                projected_hot_field_cluster_base_counts,
                len(projected_hot_field_cluster_base_counts),
            ),
        },
        "base_merge_shapes": base_merge_shapes,
        "base_merge_risks": base_merge_risks,
        "summary_path": str(summary_path),
    }


def _analysis_text_with_rename_map_comments(cleaned_text: str, rename_map_path: Path) -> str:
    rename_map = _coerce_dict(_read_json(rename_map_path))
    comments = rename_map.get("comments", [])
    if not isinstance(comments, list) or not comments:
        return cleaned_text
    merged_lines: list[str] = []
    existing_text = cleaned_text or ""
    for comment in comments:
        if not isinstance(comment, dict):
            continue
        kind = str(comment.get("kind", "") or "").strip()
        text = str(comment.get("text", "") or "").strip()
        if not kind or not text or text in existing_text:
            continue
        confidence_text = _comment_confidence_suffix(comment.get("confidence"))
        merged_lines.append("      - %s: %s%s" % (kind, text, confidence_text))
    if not merged_lines:
        return cleaned_text
    return "%s\n%s\n" % (cleaned_text or "", "\n".join(merged_lines))


def _comment_confidence_suffix(value: Any) -> str:
    if value is None:
        return ""
    try:
        return " confidence=%.2f" % float(value)
    except (TypeError, ValueError):
        return ""


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
    source_identity_blocked = _source_identity_blocked_bases(text)
    for pattern in (FIELD_REWRITE_NEAR_READY_DETAIL_RE, FIELD_BASE_STABILITY_DETAIL_RE):
        for match in pattern.finditer(text or ""):
            base = str(match.groupdict().get("base") or "")
            if base in source_identity_blocked:
                continue
            if base:
                bases.add(base)
    for match in FIELD_REWRITE_BLOCKER_DETAIL_RE.finditer(text or ""):
        if _is_source_identity_blocker(match.groupdict().get("reasons")):
            continue
        base = str(match.groupdict().get("base") or "")
        if base in source_identity_blocked:
            continue
        if base:
            bases.add(base)
    for match in FIELD_STABLE_BASE_SOURCE_DETAIL_RE.finditer(text or ""):
        base = str(match.groupdict().get("base") or "")
        source_kind = str(match.groupdict().get("source_kind") or "")
        if source_kind in {"temp", "generic"}:
            continue
        if base:
            bases.add(base)
    for match in FIELD_HOT_CLUSTER_DETAIL_RE.finditer(text or ""):
        base = str(match.groupdict().get("base") or "")
        if base in source_identity_blocked:
            continue
        if base:
            bases.add(base)
    for match in FIELD_REWRITE_PARTIAL_OPPORTUNITY_DETAIL_RE.finditer(text or ""):
        disposition = str(match.groupdict().get("disposition") or "")
        if "Validated partial layout rewrite applied" in disposition:
            continue
        base = str(match.groupdict().get("base") or "")
        if base in source_identity_blocked:
            continue
        if base:
            bases.add(base)
    return bases


def _source_identity_blocked_bases(text: str) -> set[str]:
    bases: set[str] = set()
    trusted_alias_bases = _trusted_source_identity_alias_bases(text)
    for match in FIELD_REWRITE_BLOCKER_DETAIL_RE.finditer(text or ""):
        if not _is_source_identity_blocker(match.groupdict().get("reasons")):
            continue
        base = str(match.groupdict().get("base") or "")
        if base in trusted_alias_bases:
            continue
        if base:
            bases.add(base)
    for match in FIELD_STABLE_BASE_SOURCE_DETAIL_RE.finditer(text or ""):
        source_kind = str(match.groupdict().get("source_kind") or "")
        if source_kind not in {"temp", "generic"}:
            continue
        base = str(match.groupdict().get("base") or "")
        if base in trusted_alias_bases:
            continue
        if base:
            bases.add(base)
    return bases


def _base_merge_evidence_bases(text: str) -> set[str]:
    bases: set[str] = set()
    for match in FIELD_BASE_MERGE_EVIDENCE_DETAIL_RE.finditer(text or ""):
        base = str(match.groupdict().get("base") or "")
        if base:
            bases.add(base)
    return bases


def _base_merge_family_dispositions(text: str) -> dict[str, str]:
    dispositions: dict[str, str] = {}
    for match in FIELD_BASE_MERGE_FAMILY_DISPOSITION_RE.finditer(text or ""):
        base = str(match.groupdict().get("base") or "")
        disposition = str(match.groupdict().get("disposition") or "")
        if base and disposition:
            dispositions[base] = disposition
    return dispositions


def _base_merge_shapes_and_risks(text: str) -> tuple[dict[str, str], dict[str, str]]:
    shapes: dict[str, str] = {}
    risks: dict[str, str] = {}
    for match in FIELD_BASE_MERGE_SHAPE_RE.finditer(text or ""):
        base = str(match.groupdict().get("base") or "")
        shape = str(match.groupdict().get("shape") or "")
        risk = str(match.groupdict().get("risk") or "")
        if base and shape:
            shapes[base] = shape
        if base and risk:
            risks[base] = risk
    return shapes, risks


def _call_result_parameter_merge_provenance_bases(text: str) -> set[str]:
    bases: set[str] = set()
    for match in FIELD_CALL_RESULT_PARAMETER_MERGE_PROVENANCE_DETAIL_RE.finditer(text or ""):
        base = str(match.groupdict().get("base") or "")
        if base:
            bases.add(base)
    return bases


def _same_source_family_merge_dominance_bases(text: str) -> set[str]:
    bases: set[str] = set()
    for match in FIELD_SAME_SOURCE_FAMILY_MERGE_DOMINANCE_DETAIL_RE.finditer(text or ""):
        base = str(match.groupdict().get("base") or "")
        if base:
            bases.add(base)
    return bases


def _merge_shape_recommended_next(merge_shape: str, fallback: str) -> str:
    shape = str(merge_shape or "")
    if shape == "same_source_family":
        return "Review same-source-family branch dominance before promoting this merged layout base."
    if shape == "allocation_null_branch":
        return "Review allocation/null guard dominance before promoting this merged layout base."
    if shape == "allocation_call_result_branch":
        return "Review allocation result equivalence before promoting this merged layout base."
    if shape == "call_result_branch":
        return "Review call-result object equivalence before promoting this merged layout base."
    if shape == "call_result_parameter_branch":
        return "Review parameter/call-result path dominance before promoting this merged layout base."
    if shape == "call_result_temporary_branch":
        return "Trace temporary/call-result dominance before promoting this merged layout base."
    if shape == "bugcheck_parameter_branch":
        return "Resolve bugcheck parameter domain identity before promoting this merged layout base."
    return fallback


def _trusted_source_identity_alias_bases(text: str) -> set[str]:
    bases: set[str] = set()
    for match in FIELD_STABLE_BASE_SOURCE_DETAIL_RE.finditer(text or ""):
        source_kind = str(match.groupdict().get("source_kind") or "")
        if source_kind in {"temp", "generic"}:
            continue
        base = str(match.groupdict().get("base") or "")
        if base:
            bases.add(base)
    return bases


def _is_source_identity_blocker(reasons: Any) -> bool:
    text = str(reasons or "")
    return (
        "base is a decompiler temporary" in text
        or "base name is generic" in text
        or "base has multiple initializers" in text
    )


def _projected_hot_field_clusters(text: str, existing_layout_bases: set[str]) -> list[dict[str, Any]]:
    candidates = []
    existing = set(existing_layout_bases or set())
    for comment in field_layout_comments(text or ""):
        if comment.get("kind") != "inferred_offset_field_hot_cluster":
            continue
        base = str(comment.get("base", "") or "")
        if not base or base in existing:
            continue
        candidates.append(comment)
    return candidates


def _simple_offset_deref_base_counts(text: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for match in SIMPLE_OFFSET_DEREF_BASE_RE.finditer(text or ""):
        base = str(match.groupdict().get("base") or "")
        if base:
            counts[base] += 1
    return counts


def _domain_identified_offset_bases(cleaned_text: str) -> set[str]:
    bases: set[str] = set()
    for match in DOMAIN_STRUCTURE_IDENTITY_RE.finditer(cleaned_text or ""):
        base = str(match.group("base") or "")
        if base:
            bases.add(base)
    return bases


def _annotated_scalar_offset_bases(cleaned_text: str) -> set[str]:
    bases: set[str] = set()
    for match in DOMAIN_STRUCTURE_IDENTITY_RE.finditer(cleaned_text or ""):
        structure = str(match.group("structure") or "")
        if structure not in SCALAR_OFFSET_DOMAIN_STRUCTURES:
            continue
        base = str(match.group("base") or "")
        if base:
            bases.add(base)
    return bases


def _top_counter_items(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
    return [
        {"base": base, "count": int(count)}
        for base, count in counter.most_common(max(0, int(limit)))
    ]


def _is_generic_offset_base(base: str) -> bool:
    return bool(GENERIC_OFFSET_BASE_RE.fullmatch(base or ""))


def _is_temp_offset_base(base: str) -> bool:
    return bool(TEMP_OFFSET_BASE_RE.fullmatch(base or ""))


def _is_argument_identity_offset_base(base: str) -> bool:
    return bool(ARGUMENT_IDENTITY_OFFSET_BASE_RE.fullmatch(base or ""))


def _is_context_offset_base(base: str) -> bool:
    return bool(CONTEXT_OFFSET_BASE_RE.fullmatch(base or ""))


def _is_argument_offset_base(base: str) -> bool:
    return bool(ARGUMENT_OFFSET_BASE_RE.fullmatch(base or ""))


def _is_bugcheck_offset_base(base: str) -> bool:
    return bool(BUGCHECK_PARAMETER_OFFSET_BASE_RE.fullmatch(base or ""))


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
    score += metrics["layout_base_merge_evidence"] * 6.0
    score += metrics["layout_call_result_parameter_merge_provenance"] * 4.0
    score += metrics["layout_same_source_family_merge_dominance"] * 4.0
    score += metrics["layout_stable_base_sources"] * 4.0
    score += metrics["layout_hot_field_clusters"] * 4.0
    score += metrics["registry_domain_profile_hits"] * 3.0
    score += metrics["projected_layout_hot_field_clusters"] * 6.0
    score += min(metrics["projected_layout_hot_field_cluster_accesses"], 120) * 0.25
    score += metrics["llm_fallback"] * 25.0
    score += warning_classes.get("llm_pascal_case", 0) * 2.0
    score += warning_classes.get("llm_dispatcher_context", 0) * 1.5
    if metrics["warnings"]:
        reasons.append("warnings")
    if metrics["rename_gap"] >= 8:
        reasons.append("rename_gap")
    if metrics["body_generic_identifier_tokens"] >= 50:
        reasons.append("generic_residue")
    if metrics["body_offset_deref_actionable_patterns"] >= 10:
        reasons.append("offset_deref_residue")
        if metrics["body_offset_deref_layout_actionable_patterns"] >= 10:
            reasons.append("layout_actionable_offset_residue")
        if metrics["body_offset_deref_domain_identified_base_patterns"] >= 10:
            reasons.append("domain_identified_offset_residue")
        if metrics["body_offset_deref_source_identity_blocked_base_patterns"] >= 10:
            reasons.append("source_identity_blocked_offset_residue")
        if metrics["body_offset_deref_bulk_noise_patterns"] >= 10:
            reasons.append("non_layout_offset_residue")
            if metrics["body_offset_deref_non_layout_base_patterns"] >= 10:
                reasons.append("unannotated_base_offset_residue")
                if metrics["body_offset_deref_unannotated_generic_base_patterns"] >= 10:
                    reasons.append("generic_unannotated_base_offset_residue")
                    if metrics["body_offset_deref_unannotated_temp_base_patterns"] >= 10:
                        reasons.append("temp_unannotated_base_offset_residue")
                    if metrics["body_offset_deref_unannotated_argument_identity_base_patterns"] >= 10:
                        reasons.append("argument_identity_unannotated_base_offset_residue")
                        if metrics["body_offset_deref_unannotated_context_base_patterns"] >= 10:
                            reasons.append("context_unannotated_base_offset_residue")
                        if metrics["body_offset_deref_unannotated_argument_base_patterns"] >= 10:
                            reasons.append("argument_unannotated_base_offset_residue")
                        if metrics["body_offset_deref_unannotated_bugcheck_base_patterns"] >= 10:
                            reasons.append("bugcheck_unannotated_base_offset_residue")
                if metrics["body_offset_deref_unannotated_named_base_patterns"] >= 10:
                    reasons.append("named_unannotated_base_offset_residue")
            if metrics["body_offset_deref_unmatched_base_patterns"] >= 10:
                reasons.append("unmatched_base_offset_residue")
            if metrics["body_offset_deref_bulk_noise_overflow_patterns"]:
                reasons.append("bulk_offset_residue")
    if metrics["body_label_tokens"] >= 8:
        reasons.append("label_residue")
    if (
        metrics["body_generic_identifier_overflow_tokens"]
        or metrics["body_offset_deref_actionable_overflow_patterns"]
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
    if metrics["layout_base_merge_evidence"]:
        reasons.append("layout_base_merge_evidence")
    if metrics["layout_call_result_parameter_merge_provenance"]:
        reasons.append("layout_call_result_parameter_merge_provenance")
    if metrics["layout_same_source_family_merge_dominance"]:
        reasons.append("layout_same_source_family_merge_dominance")
    if metrics["layout_hot_field_clusters"]:
        reasons.append("layout_hot_field_cluster")
    if metrics["registry_domain_profile_hits"]:
        reasons.append("registry_domain_profile_hit")
    if metrics["projected_layout_hot_field_clusters"]:
        reasons.append("projected_layout_hot_field_cluster")
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
    domain_identified_count = int(
        metrics["body_offset_deref_domain_identified_base_patterns"] or 0
    )
    source_identity_count = int(
        metrics["body_offset_deref_source_identity_blocked_base_patterns"] or 0
    )
    bulk_count = int(metrics["body_offset_deref_bulk_noise_patterns"] or 0)
    layout_full_score_count = min(layout_count, OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT)
    layout_overflow_count = max(0, layout_count - OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT)
    remaining_full_score_capacity = max(0, OFFSET_DEREF_RESIDUE_FULL_SCORE_LIMIT - layout_count)
    domain_identified_full_score_count = min(domain_identified_count, remaining_full_score_capacity)
    domain_identified_overflow_count = max(
        0,
        domain_identified_count - domain_identified_full_score_count,
    )
    remaining_full_score_capacity = max(
        0,
        remaining_full_score_capacity - domain_identified_full_score_count,
    )
    source_identity_full_score_count = min(source_identity_count, remaining_full_score_capacity)
    source_identity_overflow_count = max(
        0,
        source_identity_count - source_identity_full_score_count,
    )
    remaining_full_score_capacity = max(
        0,
        remaining_full_score_capacity - source_identity_full_score_count,
    )
    bulk_full_score_count = min(bulk_count, remaining_full_score_capacity)
    bulk_overflow_count = max(0, bulk_count - bulk_full_score_count)
    return (
        (layout_full_score_count * OFFSET_DEREF_LAYOUT_WEIGHT)
        + (layout_overflow_count * OFFSET_DEREF_RESIDUE_OVERFLOW_WEIGHT)
        + (domain_identified_full_score_count * OFFSET_DEREF_DOMAIN_IDENTITY_WEIGHT)
        + (domain_identified_overflow_count * OFFSET_DEREF_DOMAIN_IDENTITY_OVERFLOW_WEIGHT)
        + (source_identity_full_score_count * OFFSET_DEREF_SOURCE_IDENTITY_WEIGHT)
        + (source_identity_overflow_count * OFFSET_DEREF_SOURCE_IDENTITY_OVERFLOW_WEIGHT)
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
                "layout_base_merge_evidence",
                "layout_call_result_parameter_merge_provenance",
                "layout_same_source_family_merge_dominance",
                "layout_stable_base_sources",
                "layout_hot_field_clusters",
                "registry_domain_profile_hits",
            ],
            "layout_base_match_metric": "body_offset_deref_layout_actionable_patterns",
            "domain_identified_base_metric": (
                "body_offset_deref_domain_identified_base_patterns"
            ),
            "source_identity_blocked_base_metric": (
                "body_offset_deref_source_identity_blocked_base_patterns"
            ),
            "annotated_scalar_base_metric": "body_offset_deref_annotated_scalar_base_patterns",
            "annotated_scalar_domain_structures": sorted(SCALAR_OFFSET_DOMAIN_STRUCTURES),
            "unannotated_base_metric": "body_offset_deref_non_layout_base_patterns",
            "unannotated_generic_base_metric": (
                "body_offset_deref_unannotated_generic_base_patterns"
            ),
            "unannotated_generic_base_pattern": GENERIC_OFFSET_BASE_RE.pattern,
            "unannotated_temp_base_metric": "body_offset_deref_unannotated_temp_base_patterns",
            "unannotated_temp_base_pattern": TEMP_OFFSET_BASE_RE.pattern,
            "unannotated_argument_identity_base_metric": (
                "body_offset_deref_unannotated_argument_identity_base_patterns"
            ),
            "unannotated_argument_identity_base_pattern": ARGUMENT_IDENTITY_OFFSET_BASE_RE.pattern,
            "unannotated_context_base_metric": (
                "body_offset_deref_unannotated_context_base_patterns"
            ),
            "unannotated_context_base_pattern": CONTEXT_OFFSET_BASE_RE.pattern,
            "unannotated_argument_base_metric": (
                "body_offset_deref_unannotated_argument_base_patterns"
            ),
            "unannotated_argument_base_pattern": ARGUMENT_OFFSET_BASE_RE.pattern,
            "unannotated_bugcheck_base_metric": (
                "body_offset_deref_unannotated_bugcheck_base_patterns"
            ),
            "unannotated_bugcheck_base_pattern": BUGCHECK_PARAMETER_OFFSET_BASE_RE.pattern,
            "unannotated_named_base_metric": "body_offset_deref_unannotated_named_base_patterns",
            "unmatched_base_metric": "body_offset_deref_unmatched_base_patterns",
            "bulk_noise_metric": "body_offset_deref_bulk_noise_patterns",
            "full_score_limit_is_shared": True,
            "layout_signal_weight": OFFSET_DEREF_LAYOUT_WEIGHT,
            "domain_identity_weight": OFFSET_DEREF_DOMAIN_IDENTITY_WEIGHT,
            "domain_identity_overflow_weight": OFFSET_DEREF_DOMAIN_IDENTITY_OVERFLOW_WEIGHT,
            "source_identity_weight": OFFSET_DEREF_SOURCE_IDENTITY_WEIGHT,
            "source_identity_overflow_weight": OFFSET_DEREF_SOURCE_IDENTITY_OVERFLOW_WEIGHT,
            "no_layout_weight": OFFSET_DEREF_NO_LAYOUT_WEIGHT,
            "no_layout_overflow_weight": OFFSET_DEREF_NO_LAYOUT_OVERFLOW_WEIGHT,
        },
        "hot_cluster_projection": {
            "cluster_metric": "projected_layout_hot_field_clusters",
            "base_metric": "projected_layout_hot_field_cluster_bases",
            "access_metric": "projected_layout_hot_field_cluster_accesses",
            "cluster_weight": 6.0,
            "access_weight": 0.25,
            "access_score_cap": 120,
            "purpose": "Rank old corpus outputs that will gain hot-cluster review artifacts after deterministic replay.",
        },
        "source_identity_review_queues": {
            "queue_limit": SOURCE_IDENTITY_QUEUE_LIMIT,
            "min_offset_derefs": SOURCE_IDENTITY_QUEUE_MIN_OFFSET_DEREFS,
            "merge_evidence_disposition": "path_sensitive_merge_review",
            "same_source_family_merge_disposition": "same_source_family_merge_review",
            "same_source_family_dominance_disposition": "same_source_family_dominance_review",
            "allocation_null_merge_disposition": "allocation_null_dominance_review",
            "call_result_merge_disposition": "call_result_equivalence_review",
            "call_result_parameter_merge_disposition": "parameter_provenance_review",
            "call_result_temporary_merge_disposition": "temporary_provenance_review",
            "source_kinds": [
                "source_identity_blocked",
                "context",
                "argument",
                "bugcheck",
            ],
            "purpose": (
                "Rank unannotated parameter-like bases before enabling promotion rules; "
                "split branch/call-result merged layout bases into path-sensitive review."
            ),
        },
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

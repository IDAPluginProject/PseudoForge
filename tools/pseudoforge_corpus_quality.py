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

from ida_pseudoforge.core.api_semantics import NTSTATUS_RETURN_MAP, STATUS_ARGUMENT_INDEXES
from ida_pseudoforge.version import VERSION, plugin_title


GENERIC_IDENTIFIER_RE = re.compile(r"\b[av]\d+\b")
OFFSET_DEREF_RE = re.compile(
    r"\*\s*\([^)]*\*\s*\)\s*\([^;\n]*\+\s*(?:0x[0-9A-Fa-f]+|\d+)(?:LL|i64|L)?\s*\)"
)
LABEL_RE = re.compile(r"\bLABEL_\d+\b")
DECIMAL_STATUS_RE = re.compile(
    r"(?:\breturn\b|(?<![=!<>])(?:==|!=|=))\s*-?(?:107374\d+|\d{8,}|322122\d+)\b"
    r"|\b-?(?:107374\d+|\d{8,}|322122\d+)\s*(?:==|!=)"
)
HEX_STATUS_RE = re.compile(r"\b0xC[0-9A-Fa-f]{7}\b")
NUMERIC_LITERAL_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))"
    r"(?P<suffix>u?LL|ULL|LL|u|U|L)?\b"
)
FIELD_PREVIEW_RE = re.compile(r"-\s+inferred_offset_field_preview:")
FIELD_ALIAS_RE = re.compile(r"-\s+inferred_offset_field_aliases:")
FIELD_SUBFIELD_OVERLAY_RE = re.compile(r"-\s+inferred_offset_subfield_overlays:")
FIELD_SUBFIELD_OVERLAY_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_subfield_overlays:\s+"
    r"(?:Subfield overlay evidence for|Review subfield overlays for)\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)(?:\s+\([^)]*\))?:\s+"
    r"(?P<fields>.*?)\.\s+Review-only(?: evidence)?;\s+"
    r"field rewrite remains blocked for mixed-width offsets\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_NARROW_SUBFIELD_RE = re.compile(r"-\s+inferred_offset_narrow_subfields:")
FIELD_NARROW_SUBFIELD_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_narrow_subfields:\s+"
    r"(?:Narrow subfield candidates for|Review narrow subfields for)\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)(?:\s+\([^)]*\))?:\s+"
    r"(?P<fields>.*?)\.\s+Audit-only;\s+"
    r"body rewrite remains disabled until the parent structure is trusted\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_BITFIELD_ALIAS_RE = re.compile(r"-\s+inferred_offset_bitfield_aliases:")
FIELD_BITFIELD_ALIAS_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_bitfield_aliases:\s+"
    r"(?:Bitfield aliases for|Review bitfield aliases for)\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)(?:\s+\([^)]*\))?:\s+"
    r"(?P<fields>.*?)\.\s+Review-only names;\s+"
    r"body rewrite remains disabled until the parent structure is trusted\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_STABLE_BASE_SOURCE_RE = re.compile(r"-\s+inferred_offset_stable_base_source:")
FIELD_STABLE_BASE_SOURCE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_stable_base_source:\s+Stable base source for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<source>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"\((?P<source_kind>[a-z_]+)\s+source\),\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\)\.\s+"
    r"Review-only; temp/generic base keeps rewrite blocked until source identity is trusted\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_GENERIC_BASE_EVIDENCE_RE = re.compile(r"-\s+inferred_offset_generic_base_evidence:")
FIELD_GENERIC_BASE_EVIDENCE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_generic_base_evidence:\s+Generic base evidence for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\),\s+blocker profile\s+"
    r"(?P<blocker_profile>[a-z_]+)\.\s+"
    r"Review-only; rewrite remains blocked until the base identity is trusted\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_GENERIC_BASE_TRUST_CANDIDATE_RE = re.compile(r"-\s+inferred_offset_generic_base_trust_candidate:")
FIELD_GENERIC_BASE_TRUST_CANDIDATE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_generic_base_trust_candidate:\s+Generic base trust candidate for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<source_kind>[a-z_]+)\s+source,\s+"
    r"(?P<blocker_profile>[a-z-]+)\s+blockers,\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\)\.\s+"
    r"Promotion review only;\s+"
    r"rewrite remains disabled until external type identity is confirmed\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
SUBFIELD_OVERLAY_FIELD_RE = re.compile(
    r"\+0x(?P<offset>[0-9A-Fa-f]+)\s+field_[0-9A-Fa-f]+\s+uses\s+"
    r"(?P<sizes>[0-9/]+)-byte accesses\s+\((?P<types>[^)]*)\)"
    r"(?:\s+\[(?P<annotation>[^\]]+)\])?"
)
BITFIELD_ALIAS_FIELD_RE = re.compile(
    r"field_(?P<offset>[0-9A-Fa-f]+)=\+0x[0-9A-Fa-f]+\s+"
    r"(?P<aliases>[A-Za-z0-9_/,]+)\s+masks=(?P<masks>[0-9A-Fa-fx,]+|unknown)"
)
FIELD_REWRITE_READY_RE = re.compile(r"-\s+inferred_offset_rewrite_ready:")
FIELD_REWRITE_READY_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_rewrite_ready:\s+Offset field rewrite candidate for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\),\s+no rewrite blockers found\.\s+"
    r"Audit only; body rewrite was not applied\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_REWRITE_NEAR_READY_RE = re.compile(r"-\s+inferred_offset_rewrite_near_ready:")
FIELD_REWRITE_NEAR_READY_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_rewrite_near_ready:\s+Offset field rewrite near-ready for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\),\s+missing\s+"
    r"(?P<missing>offset|access)\s+threshold only\.\s+"
    r"Audit only; body rewrite was not applied\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_REWRITE_BLOCKER_RE = re.compile(r"-\s+inferred_offset_rewrite_blockers:")
FIELD_REWRITE_BLOCKER_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_rewrite_blockers:\s+Offset field rewrite blocked for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<reasons>.*?)\.\s+Review-only aliases remain available\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
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
    subfield_overlay_bases: Counter[str] = Counter()
    subfield_overlay_size_classes: Counter[str] = Counter()
    subfield_overlay_policy_classes: Counter[str] = Counter()
    subfield_overlay_interpretations: Counter[str] = Counter()
    subfield_overlay_bit_masks: Counter[str] = Counter()
    subfield_overlay_bit_operations: Counter[str] = Counter()
    subfield_overlay_mask_families: Counter[str] = Counter()
    subfield_overlay_totals = Counter()
    narrow_subfield_bases: Counter[str] = Counter()
    narrow_subfield_size_classes: Counter[str] = Counter()
    narrow_subfield_interpretations: Counter[str] = Counter()
    narrow_subfield_bit_masks: Counter[str] = Counter()
    narrow_subfield_bit_operations: Counter[str] = Counter()
    narrow_subfield_mask_families: Counter[str] = Counter()
    narrow_subfield_totals = Counter()
    bitfield_alias_bases: Counter[str] = Counter()
    bitfield_alias_names: Counter[str] = Counter()
    bitfield_alias_masks: Counter[str] = Counter()
    bitfield_alias_totals = Counter()
    stable_base_source_bases: Counter[str] = Counter()
    stable_base_source_sources: Counter[str] = Counter()
    stable_base_source_kinds: Counter[str] = Counter()
    stable_base_source_totals = Counter()
    generic_base_evidence_bases: Counter[str] = Counter()
    generic_base_evidence_profiles: Counter[str] = Counter()
    generic_base_evidence_totals = Counter()
    generic_base_trust_candidate_bases: Counter[str] = Counter()
    generic_base_trust_candidate_sources: Counter[str] = Counter()
    generic_base_trust_candidate_profiles: Counter[str] = Counter()
    generic_base_trust_candidate_totals = Counter()
    rewrite_ready_bases: Counter[str] = Counter()
    rewrite_ready_totals = Counter()
    rewrite_near_ready_bases: Counter[str] = Counter()
    rewrite_near_ready_missing: Counter[str] = Counter()
    rewrite_near_ready_totals = Counter()
    rewrite_blocker_bases: Counter[str] = Counter()
    rewrite_blocker_reasons: Counter[str] = Counter()
    rewrite_blocker_totals = Counter()
    ntstatus_body_unprofiled_values: Counter[str] = Counter()
    ntstatus_body_unprofiled_value_functions: dict[str, set[str]] = {}
    ntstatus_body_unprofiled_value_contexts: dict[str, Counter[str]] = {}
    ntstatus_body_unprofiled_context_kinds: Counter[str] = Counter()
    totals = Counter()
    text_totals = Counter()
    body_text_totals = Counter()
    top_warning_functions = []
    top_layout_hint_functions = []
    top_subfield_overlay_functions = []
    top_narrow_subfield_functions = []
    top_bitfield_alias_functions = []
    top_stable_base_source_functions = []
    top_generic_base_evidence_functions = []
    top_generic_base_trust_candidate_functions = []
    top_rewrite_ready_functions = []
    top_rewrite_near_ready_functions = []
    top_rewrite_blocker_functions = []
    top_ntstatus_body_unprofiled_functions = []

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
                (
                    layout_hints,
                    subfield_overlays,
                    narrow_subfields,
                    bitfield_aliases,
                    stable_base_sources,
                    generic_base_evidence,
                    generic_base_trust_candidates,
                    rewrite_ready,
                    rewrite_near_ready,
                    rewrite_blockers,
                    ntstatus_body_literals,
                ) = _update_text_metrics(
                    text_totals,
                    body_text_totals,
                    cleaned_path,
                )
                _update_layout_hint_metrics(
                    layout_hints,
                    layout_totals,
                    layout_hint_bases,
                    layout_hint_types,
                )
                _update_layout_subfield_overlay_metrics(
                    subfield_overlays,
                    subfield_overlay_totals,
                    subfield_overlay_bases,
                    subfield_overlay_size_classes,
                    subfield_overlay_policy_classes,
                    subfield_overlay_interpretations,
                    subfield_overlay_bit_masks,
                    subfield_overlay_bit_operations,
                    subfield_overlay_mask_families,
                )
                _update_layout_narrow_subfield_metrics(
                    narrow_subfields,
                    narrow_subfield_totals,
                    narrow_subfield_bases,
                    narrow_subfield_size_classes,
                    narrow_subfield_interpretations,
                    narrow_subfield_bit_masks,
                    narrow_subfield_bit_operations,
                    narrow_subfield_mask_families,
                )
                _update_layout_bitfield_alias_metrics(
                    bitfield_aliases,
                    bitfield_alias_totals,
                    bitfield_alias_bases,
                    bitfield_alias_names,
                    bitfield_alias_masks,
                )
                _update_layout_stable_base_source_metrics(
                    stable_base_sources,
                    stable_base_source_totals,
                    stable_base_source_bases,
                    stable_base_source_sources,
                    stable_base_source_kinds,
                )
                _update_layout_generic_base_evidence_metrics(
                    generic_base_evidence,
                    generic_base_evidence_totals,
                    generic_base_evidence_bases,
                    generic_base_evidence_profiles,
                )
                _update_layout_generic_base_trust_candidate_metrics(
                    generic_base_trust_candidates,
                    generic_base_trust_candidate_totals,
                    generic_base_trust_candidate_bases,
                    generic_base_trust_candidate_sources,
                    generic_base_trust_candidate_profiles,
                )
                _update_layout_rewrite_ready_metrics(
                    rewrite_ready,
                    rewrite_ready_totals,
                    rewrite_ready_bases,
                )
                _update_layout_rewrite_near_ready_metrics(
                    rewrite_near_ready,
                    rewrite_near_ready_totals,
                    rewrite_near_ready_bases,
                    rewrite_near_ready_missing,
                )
                _update_layout_rewrite_blocker_metrics(
                    rewrite_blockers,
                    rewrite_blocker_totals,
                    rewrite_blocker_bases,
                    rewrite_blocker_reasons,
                )
                if layout_hints:
                    top_layout_hint_functions.append(
                        _layout_hint_function_summary(name, ea, summary_path, layout_hints)
                    )
                if subfield_overlays:
                    top_subfield_overlay_functions.append(
                        _subfield_overlay_function_summary(name, ea, summary_path, subfield_overlays)
                    )
                if narrow_subfields:
                    top_narrow_subfield_functions.append(
                        _narrow_subfield_function_summary(name, ea, summary_path, narrow_subfields)
                    )
                if bitfield_aliases:
                    top_bitfield_alias_functions.append(
                        _bitfield_alias_function_summary(name, ea, summary_path, bitfield_aliases)
                    )
                if stable_base_sources:
                    top_stable_base_source_functions.append(
                        _stable_base_source_function_summary(name, ea, summary_path, stable_base_sources)
                    )
                if generic_base_evidence:
                    top_generic_base_evidence_functions.append(
                        _generic_base_evidence_function_summary(name, ea, summary_path, generic_base_evidence)
                    )
                if generic_base_trust_candidates:
                    top_generic_base_trust_candidate_functions.append(
                        _generic_base_trust_candidate_function_summary(
                            name,
                            ea,
                            summary_path,
                            generic_base_trust_candidates,
                        )
                    )
                if rewrite_ready:
                    top_rewrite_ready_functions.append(
                        _rewrite_ready_function_summary(name, ea, summary_path, rewrite_ready)
                    )
                if rewrite_near_ready:
                    top_rewrite_near_ready_functions.append(
                        _rewrite_near_ready_function_summary(name, ea, summary_path, rewrite_near_ready)
                    )
                if rewrite_blockers:
                    top_rewrite_blocker_functions.append(
                        _rewrite_blocker_function_summary(name, ea, summary_path, rewrite_blockers)
                    )
                unprofiled_ntstatus_body_literals = [
                    item
                    for item in ntstatus_body_literals
                    if not bool(item.get("profiled")) and str(item.get("severity", "")) == "error"
                ]
                if unprofiled_ntstatus_body_literals:
                    _update_ntstatus_body_unprofiled_value_metrics(
                        unprofiled_ntstatus_body_literals,
                        ntstatus_body_unprofiled_values,
                        ntstatus_body_unprofiled_value_functions,
                        ntstatus_body_unprofiled_value_contexts,
                        ntstatus_body_unprofiled_context_kinds,
                        name,
                    )
                    top_ntstatus_body_unprofiled_functions.append(
                        _ntstatus_body_unprofiled_function_summary(
                            name,
                            ea,
                            summary_path,
                            unprofiled_ntstatus_body_literals,
                        )
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
    top_subfield_overlay_functions.sort(
        key=lambda item: (
            -int(item["overlay_count"]),
            -int(item["field_count"]),
            str(item["name"]),
        )
    )
    top_narrow_subfield_functions.sort(
        key=lambda item: (
            -int(item["candidate_count"]),
            -int(item["field_count"]),
            str(item["name"]),
        )
    )
    top_bitfield_alias_functions.sort(
        key=lambda item: (
            -int(item["alias_comment_count"]),
            -int(item["field_count"]),
            str(item["name"]),
        )
    )
    top_stable_base_source_functions.sort(
        key=lambda item: (
            -int(item["source_comment_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_generic_base_evidence_functions.sort(
        key=lambda item: (
            -int(item["evidence_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_generic_base_trust_candidate_functions.sort(
        key=lambda item: (
            -int(item["candidate_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_rewrite_ready_functions.sort(
        key=lambda item: (
            -int(item["ready_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_rewrite_near_ready_functions.sort(
        key=lambda item: (
            -int(item["near_ready_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_rewrite_blocker_functions.sort(
        key=lambda item: (
            -int(item["blocker_count"]),
            -int(item["reason_count"]),
            str(item["name"]),
        )
    )
    top_ntstatus_body_unprofiled_functions.sort(
        key=lambda item: (
            -int(item["literal_count"]),
            str(item["name"]),
        )
    )
    ntstatus_unprofiled_value_summaries = _ntstatus_unprofiled_value_summaries(
        ntstatus_body_unprofiled_values,
        ntstatus_body_unprofiled_value_functions,
        ntstatus_body_unprofiled_value_contexts,
        top,
    )
    ntstatus_unprofiled_function_summaries = top_ntstatus_body_unprofiled_functions[:top]
    ntstatus_review_hint_counts = _ntstatus_review_hint_counts(ntstatus_body_unprofiled_value_contexts)
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
        "layout_subfield_overlay_stats": {
            "totals": _counter_to_dict(subfield_overlay_totals),
            "top_bases": _counter_to_dict(Counter(dict(subfield_overlay_bases.most_common(top)))),
            "size_classes": _counter_to_dict(Counter(dict(subfield_overlay_size_classes.most_common(top)))),
            "policy_classes": _counter_to_dict(Counter(dict(subfield_overlay_policy_classes.most_common(top)))),
            "interpretations": _counter_to_dict(Counter(dict(subfield_overlay_interpretations.most_common(top)))),
            "bit_masks": _counter_to_dict(Counter(dict(subfield_overlay_bit_masks.most_common(top)))),
            "bit_operations": _counter_to_dict(Counter(dict(subfield_overlay_bit_operations.most_common(top)))),
            "mask_families": _counter_to_dict(Counter(dict(subfield_overlay_mask_families.most_common(top)))),
            "top_functions": top_subfield_overlay_functions[:top],
        },
        "layout_narrow_subfield_stats": {
            "totals": _counter_to_dict(narrow_subfield_totals),
            "top_bases": _counter_to_dict(Counter(dict(narrow_subfield_bases.most_common(top)))),
            "size_classes": _counter_to_dict(Counter(dict(narrow_subfield_size_classes.most_common(top)))),
            "interpretations": _counter_to_dict(Counter(dict(narrow_subfield_interpretations.most_common(top)))),
            "bit_masks": _counter_to_dict(Counter(dict(narrow_subfield_bit_masks.most_common(top)))),
            "bit_operations": _counter_to_dict(Counter(dict(narrow_subfield_bit_operations.most_common(top)))),
            "mask_families": _counter_to_dict(Counter(dict(narrow_subfield_mask_families.most_common(top)))),
            "top_functions": top_narrow_subfield_functions[:top],
        },
        "layout_bitfield_alias_stats": {
            "totals": _counter_to_dict(bitfield_alias_totals),
            "top_bases": _counter_to_dict(Counter(dict(bitfield_alias_bases.most_common(top)))),
            "aliases": _counter_to_dict(Counter(dict(bitfield_alias_names.most_common(top)))),
            "masks": _counter_to_dict(Counter(dict(bitfield_alias_masks.most_common(top)))),
            "top_functions": top_bitfield_alias_functions[:top],
        },
        "layout_stable_base_source_stats": {
            "totals": _counter_to_dict(stable_base_source_totals),
            "top_bases": _counter_to_dict(Counter(dict(stable_base_source_bases.most_common(top)))),
            "sources": _counter_to_dict(Counter(dict(stable_base_source_sources.most_common(top)))),
            "source_kinds": _counter_to_dict(Counter(dict(stable_base_source_kinds.most_common(top)))),
            "top_functions": top_stable_base_source_functions[:top],
        },
        "layout_generic_base_evidence_stats": {
            "totals": _counter_to_dict(generic_base_evidence_totals),
            "top_bases": _counter_to_dict(Counter(dict(generic_base_evidence_bases.most_common(top)))),
            "blocker_profiles": _counter_to_dict(Counter(dict(generic_base_evidence_profiles.most_common(top)))),
            "top_functions": top_generic_base_evidence_functions[:top],
        },
        "layout_generic_base_trust_candidate_stats": {
            "totals": _counter_to_dict(generic_base_trust_candidate_totals),
            "top_bases": _counter_to_dict(Counter(dict(generic_base_trust_candidate_bases.most_common(top)))),
            "source_kinds": _counter_to_dict(Counter(dict(generic_base_trust_candidate_sources.most_common(top)))),
            "blocker_profiles": _counter_to_dict(Counter(dict(generic_base_trust_candidate_profiles.most_common(top)))),
            "top_functions": top_generic_base_trust_candidate_functions[:top],
        },
        "layout_rewrite_ready_stats": {
            "totals": _counter_to_dict(rewrite_ready_totals),
            "top_bases": _counter_to_dict(Counter(dict(rewrite_ready_bases.most_common(top)))),
            "top_functions": top_rewrite_ready_functions[:top],
        },
        "layout_rewrite_near_ready_stats": {
            "totals": _counter_to_dict(rewrite_near_ready_totals),
            "top_bases": _counter_to_dict(Counter(dict(rewrite_near_ready_bases.most_common(top)))),
            "missing_thresholds": _counter_to_dict(Counter(dict(rewrite_near_ready_missing.most_common(top)))),
            "top_functions": top_rewrite_near_ready_functions[:top],
        },
        "layout_rewrite_blocker_stats": {
            "totals": _counter_to_dict(rewrite_blocker_totals),
            "top_bases": _counter_to_dict(Counter(dict(rewrite_blocker_bases.most_common(top)))),
            "reasons": _counter_to_dict(Counter(dict(rewrite_blocker_reasons.most_common(top)))),
            "top_functions": top_rewrite_blocker_functions[:top],
        },
        "ntstatus_body_residue_stats": {
            "top_unprofiled_error_values": ntstatus_unprofiled_value_summaries,
            "unprofiled_error_context_kinds": _counter_to_dict(
                Counter(dict(ntstatus_body_unprofiled_context_kinds.most_common(top)))
            ),
            "unprofiled_error_review_hints": _counter_to_dict(
                Counter(dict(ntstatus_review_hint_counts.most_common(top)))
            ),
            "review_queues": _ntstatus_review_queues(
                ntstatus_unprofiled_value_summaries,
                ntstatus_unprofiled_function_summaries,
            ),
            "top_unprofiled_error_functions": ntstatus_unprofiled_function_summaries,
        },
        "text_stats": _counter_to_dict(text_totals),
        "body_text_stats": _counter_to_dict(body_text_totals),
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
    subfield_overlay_stats = _coerce_dict(report.get("layout_subfield_overlay_stats", {}))
    narrow_subfield_stats = _coerce_dict(report.get("layout_narrow_subfield_stats", {}))
    bitfield_alias_stats = _coerce_dict(report.get("layout_bitfield_alias_stats", {}))
    stable_base_source_stats = _coerce_dict(report.get("layout_stable_base_source_stats", {}))
    generic_base_evidence_stats = _coerce_dict(report.get("layout_generic_base_evidence_stats", {}))
    generic_base_trust_candidate_stats = _coerce_dict(report.get("layout_generic_base_trust_candidate_stats", {}))
    rewrite_ready_stats = _coerce_dict(report.get("layout_rewrite_ready_stats", {}))
    rewrite_near_ready_stats = _coerce_dict(report.get("layout_rewrite_near_ready_stats", {}))
    rewrite_blocker_stats = _coerce_dict(report.get("layout_rewrite_blocker_stats", {}))
    ntstatus_body_residue_stats = _coerce_dict(report.get("ntstatus_body_residue_stats", {}))
    ntstatus_review_queues = _coerce_dict(ntstatus_body_residue_stats.get("review_queues", {}))
    layout_totals = _coerce_dict(layout_hint_stats.get("totals", {}))
    subfield_overlay_totals = _coerce_dict(subfield_overlay_stats.get("totals", {}))
    narrow_subfield_totals = _coerce_dict(narrow_subfield_stats.get("totals", {}))
    bitfield_alias_totals = _coerce_dict(bitfield_alias_stats.get("totals", {}))
    stable_base_source_totals = _coerce_dict(stable_base_source_stats.get("totals", {}))
    generic_base_evidence_totals = _coerce_dict(generic_base_evidence_stats.get("totals", {}))
    generic_base_trust_candidate_totals = _coerce_dict(generic_base_trust_candidate_stats.get("totals", {}))
    rewrite_ready_totals = _coerce_dict(rewrite_ready_stats.get("totals", {}))
    rewrite_near_ready_totals = _coerce_dict(rewrite_near_ready_stats.get("totals", {}))
    rewrite_blocker_totals = _coerce_dict(rewrite_blocker_stats.get("totals", {}))
    text_stats = _coerce_dict(report.get("text_stats", {}))
    body_text_stats = _coerce_dict(report.get("body_text_stats", {}))
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
            "## Layout Stable Base Sources",
            "",
            "- Stable base source comments: `%s` across `%s` functions"
            % (
                stable_base_source_totals.get("source_comments", 0),
                stable_base_source_totals.get("functions_with_source_comments", 0),
            ),
            "- Stable source offset observations: `%s`" % stable_base_source_totals.get("offset_observations", 0),
            "- Stable source access observations: `%s`" % stable_base_source_totals.get("access_observations", 0),
            "",
            "### Stable Base Source Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(stable_base_source_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Stable Base Source Names",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(stable_base_source_stats.get("sources", {})), "Source"))
    lines.extend(
        [
            "",
            "### Stable Base Source Kinds",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(stable_base_source_stats.get("source_kinds", {})), "Kind"))
    lines.extend(
        [
            "",
            "### Highest Stable Base Source Functions",
            "",
            "| Function | EA | Source comments | Max offsets | Max accesses | Sources | Source kinds | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in stable_base_source_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        sources = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_sources", {})).items()
        )
        source_kinds = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_source_kinds", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("source_comment_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                sources,
                source_kinds,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Generic Base Evidence",
            "",
            "- Generic base evidence comments: `%s` across `%s` functions"
            % (
                generic_base_evidence_totals.get("evidence_comments", 0),
                generic_base_evidence_totals.get("functions_with_evidence_comments", 0),
            ),
            "- Generic base evidence offset observations: `%s`" % generic_base_evidence_totals.get("offset_observations", 0),
            "- Generic base evidence access observations: `%s`" % generic_base_evidence_totals.get("access_observations", 0),
            "",
            "### Generic Base Evidence Profiles",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(generic_base_evidence_stats.get("blocker_profiles", {})), "Profile"))
    lines.extend(
        [
            "",
            "### Generic Base Evidence Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(generic_base_evidence_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Highest Generic Base Evidence Functions",
            "",
            "| Function | EA | Evidence | Max offsets | Max accesses | Profiles | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for item in generic_base_evidence_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        profiles = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("blocker_profiles", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("evidence_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                profiles,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Generic Base Trust Candidates",
            "",
            "- Generic base trust candidates: `%s` across `%s` functions"
            % (
                generic_base_trust_candidate_totals.get("trust_candidates", 0),
                generic_base_trust_candidate_totals.get("functions_with_trust_candidates", 0),
            ),
            "- Trust candidate offset observations: `%s`" % generic_base_trust_candidate_totals.get("offset_observations", 0),
            "- Trust candidate access observations: `%s`" % generic_base_trust_candidate_totals.get("access_observations", 0),
            "",
            "### Generic Base Trust Source Kinds",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(generic_base_trust_candidate_stats.get("source_kinds", {})), "Kind"))
    lines.extend(
        [
            "",
            "### Generic Base Trust Profiles",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(generic_base_trust_candidate_stats.get("blocker_profiles", {})), "Profile"))
    lines.extend(
        [
            "",
            "### Generic Base Trust Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(generic_base_trust_candidate_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Highest Generic Base Trust Candidate Functions",
            "",
            "| Function | EA | Candidates | Max offsets | Max accesses | Sources | Profiles | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in generic_base_trust_candidate_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        sources = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("source_kinds", {})).items()
        )
        profiles = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("blocker_profiles", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("candidate_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                sources,
                profiles,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Subfield Overlays",
            "",
            "- Overlay comments: `%s` across `%s` functions"
            % (
                subfield_overlay_totals.get("overlay_comments", 0),
                subfield_overlay_totals.get("functions_with_overlay_comments", 0),
            ),
            "- Overlay field observations: `%s`" % subfield_overlay_totals.get("field_observations", 0),
            "",
            "### Subfield Overlay Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Size Classes",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("size_classes", {})), "Size class"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Policy Classes",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("policy_classes", {})), "Policy class"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Interpretations",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("interpretations", {})), "Interpretation"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Bit Masks",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("bit_masks", {})), "Mask"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Bit Operations",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("bit_operations", {})), "Operation"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Mask Families",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("mask_families", {})), "Family"))
    lines.extend(
        [
            "",
            "### Highest Subfield Overlay Functions",
            "",
            "| Function | EA | Overlays | Fields | Size classes | Policy classes | Interpretations | Bit masks | Bit operations | Mask families | Bases |",
            "| --- | --- | ---: | ---: | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in subfield_overlay_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        size_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_size_classes", {})).items()
        )
        policy_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_policy_classes", {})).items()
        )
        interpretations = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_interpretations", {})).items()
        )
        bit_masks = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_bit_masks", {})).items()
        )
        bit_operations = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_bit_operations", {})).items()
        )
        mask_families = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_mask_families", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("overlay_count", 0) or 0),
                int(item.get("field_count", 0) or 0),
                size_classes,
                policy_classes,
                interpretations,
                bit_masks,
                bit_operations,
                mask_families,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Narrow Subfields",
            "",
            "- Narrow subfield comments: `%s` across `%s` functions"
            % (
                narrow_subfield_totals.get("candidate_comments", 0),
                narrow_subfield_totals.get("functions_with_candidate_comments", 0),
            ),
            "- Narrow field observations: `%s`" % narrow_subfield_totals.get("field_observations", 0),
            "",
            "### Narrow Subfield Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Narrow Subfield Size Classes",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("size_classes", {})), "Size class"))
    lines.extend(
        [
            "",
            "### Narrow Subfield Interpretations",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("interpretations", {})), "Interpretation"))
    lines.extend(
        [
            "",
            "### Narrow Subfield Bit Masks",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("bit_masks", {})), "Mask"))
    lines.extend(
        [
            "",
            "### Narrow Subfield Bit Operations",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("bit_operations", {})), "Operation"))
    lines.extend(
        [
            "",
            "### Narrow Subfield Mask Families",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("mask_families", {})), "Family"))
    lines.extend(
        [
            "",
            "### Highest Narrow Subfield Functions",
            "",
            "| Function | EA | Candidates | Fields | Size classes | Interpretations | Bit masks | Bit operations | Mask families | Bases |",
            "| --- | --- | ---: | ---: | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in narrow_subfield_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        size_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_size_classes", {})).items()
        )
        interpretations = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_interpretations", {})).items()
        )
        bit_masks = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_bit_masks", {})).items()
        )
        bit_operations = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_bit_operations", {})).items()
        )
        mask_families = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_mask_families", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("candidate_count", 0) or 0),
                int(item.get("field_count", 0) or 0),
                size_classes,
                interpretations,
                bit_masks,
                bit_operations,
                mask_families,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Bitfield Aliases",
            "",
            "- Bitfield alias comments: `%s` across `%s` functions"
            % (
                bitfield_alias_totals.get("alias_comments", 0),
                bitfield_alias_totals.get("functions_with_alias_comments", 0),
            ),
            "- Bitfield alias field observations: `%s`" % bitfield_alias_totals.get("field_observations", 0),
            "",
            "### Bitfield Alias Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(bitfield_alias_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Bitfield Alias Names",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(bitfield_alias_stats.get("aliases", {})), "Alias"))
    lines.extend(
        [
            "",
            "### Bitfield Alias Masks",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(bitfield_alias_stats.get("masks", {})), "Mask"))
    lines.extend(
        [
            "",
            "### Highest Bitfield Alias Functions",
            "",
            "| Function | EA | Alias comments | Fields | Aliases | Masks | Bases |",
            "| --- | --- | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in bitfield_alias_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        aliases = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_aliases", {})).items()
        )
        masks = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_masks", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("alias_comment_count", 0) or 0),
                int(item.get("field_count", 0) or 0),
                aliases,
                masks,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Rewrite Readiness",
            "",
            "- Ready candidates: `%s` across `%s` functions"
            % (rewrite_ready_totals.get("ready_candidates", 0), rewrite_ready_totals.get("functions_with_ready_candidates", 0)),
            "- Ready offset observations: `%s`" % rewrite_ready_totals.get("offset_observations", 0),
            "- Ready access observations: `%s`" % rewrite_ready_totals.get("access_observations", 0),
            "",
            "### Rewrite-Ready Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_ready_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Highest Rewrite-Ready Functions",
            "",
            "| Function | EA | Ready | Max offsets | Max accesses | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for item in rewrite_ready_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("ready_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Rewrite Near-Ready",
            "",
            "- Near-ready candidates: `%s` across `%s` functions"
            % (
                rewrite_near_ready_totals.get("near_ready_candidates", 0),
                rewrite_near_ready_totals.get("functions_with_near_ready_candidates", 0),
            ),
            "- Near-ready offset observations: `%s`" % rewrite_near_ready_totals.get("offset_observations", 0),
            "- Near-ready access observations: `%s`" % rewrite_near_ready_totals.get("access_observations", 0),
            "",
            "### Missing Thresholds",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_near_ready_stats.get("missing_thresholds", {})), "Threshold"))
    lines.extend(
        [
            "",
            "### Near-Ready Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_near_ready_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Highest Near-Ready Functions",
            "",
            "| Function | EA | Near-ready | Max offsets | Max accesses | Missing | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for item in rewrite_near_ready_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        missing = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("missing_thresholds", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("near_ready_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                missing,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Rewrite Blockers",
            "",
            "- Blockers: `%s` across `%s` functions"
            % (rewrite_blocker_totals.get("blockers", 0), rewrite_blocker_totals.get("functions_with_blockers", 0)),
            "- Reason observations: `%s`" % rewrite_blocker_totals.get("reason_observations", 0),
            "",
            "### Rewrite Blocker Reasons",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_blocker_stats.get("reasons", {})), "Reason"))
    lines.extend(
        [
            "",
            "### Rewrite Blocker Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_blocker_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Highest Rewrite Blocker Functions",
            "",
            "| Function | EA | Blockers | Reasons | Bases | Top reasons |",
            "| --- | --- | ---: | ---: | --- | --- |",
        ]
    )
    for item in rewrite_blocker_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        reasons = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_reasons", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("blocker_count", 0) or 0),
                int(item.get("reason_count", 0) or 0),
                bases,
                reasons,
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
            "## Code Body Residue",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(body_text_stats, "Metric"))
    lines.extend(
        [
            "",
            "### Unprofiled NTSTATUS Error Values",
            "",
            "| Value | Signed | Facility | Code | Hint | Kinds | Count | Functions |",
            "| --- | ---: | ---: | ---: | --- | --- | ---: | ---: |",
        ]
    )
    for item in ntstatus_body_residue_stats.get("top_unprofiled_error_values", []) or []:
        if not isinstance(item, dict):
            continue
        context_kinds = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("context_kinds", {})).items()
        )
        lines.append(
            "| `%s` | %s | `%s` | `%s` | %s | %s | %s | %s |"
            % (
                str(item.get("hex_value", "")),
                int(item.get("signed_value", 0) or 0),
                str(item.get("facility_hex", "")),
                str(item.get("code_hex", "")),
                _markdown_table_cell(item.get("review_hint", "")),
                _markdown_table_cell(context_kinds),
                int(item.get("count", 0) or 0),
                int(item.get("function_count", 0) or 0),
            )
        )
    lines.extend(
        [
            "",
            "### Unprofiled NTSTATUS Error Context Kinds",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(ntstatus_body_residue_stats.get("unprofiled_error_context_kinds", {})),
            "Kind",
        )
    )
    lines.extend(
        [
            "",
            "### Unprofiled NTSTATUS Error Review Hints",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(ntstatus_body_residue_stats.get("unprofiled_error_review_hints", {})),
            "Hint",
        )
    )
    lines.extend(
        [
            "",
            "### Unprofiled NTSTATUS Review Queues",
            "",
            "| Queue | Values | Functions |",
            "| --- | ---: | ---: |",
        ]
    )
    for queue_name in (
        "status_profile_candidates",
        "comparison_sentinel_candidates",
        "manual_review",
    ):
        queue = _coerce_dict(ntstatus_review_queues.get(queue_name, {}))
        values = queue.get("values", []) if isinstance(queue.get("values", []), list) else []
        functions = queue.get("functions", []) if isinstance(queue.get("functions", []), list) else []
        lines.append(
            "| `%s` | %s | %s |"
            % (
                queue_name,
                len(values),
                len(functions),
            )
        )
    lines.extend(
        [
            "",
            "### Functions With Unprofiled NTSTATUS Errors",
            "",
            "| Function | EA | Literals | Hint | Kinds | Values | Lines | Context | Raw literals |",
            "| --- | --- | ---: | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in ntstatus_body_residue_stats.get("top_unprofiled_error_functions", []) or []:
        if not isinstance(item, dict):
            continue
        values = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("values", {})).items()
        )
        raw_literals = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("raw_literals", {})).items()
        )
        context_kinds = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("context_kinds", {})).items()
        )
        lines_text = ", ".join(
            str(context.get("line", ""))
            for context in item.get("contexts", []) or []
            if isinstance(context, dict)
        )
        context_text = "; ".join(
            "L%s: %s" % (context.get("line", ""), context.get("source", ""))
            for context in item.get("contexts", []) or []
            if isinstance(context, dict)
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("literal_count", 0) or 0),
                _markdown_table_cell(item.get("review_hint", "")),
                _markdown_table_cell(context_kinds),
                _markdown_table_cell(values),
                _markdown_table_cell(lines_text),
                _markdown_table_cell(context_text),
                _markdown_table_cell(raw_literals),
            )
        )
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


def _update_text_metrics(
    text_totals: Counter[str],
    body_text_totals: Counter[str],
    path: Path,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    text = _read_text(path)
    if not text:
        return [], [], [], [], [], [], [], [], [], [], []
    _update_residue_metrics(text_totals, text)
    body_text = _strip_pseudoforge_header(text)
    _update_residue_metrics(body_text_totals, body_text)
    ntstatus_body_literals = _ntstatus_family_literals(body_text)
    layout_hints = _extract_layout_hints(text)
    subfield_overlays = _extract_layout_subfield_overlays(text)
    narrow_subfields = _extract_layout_narrow_subfields(text)
    bitfield_aliases = _extract_layout_bitfield_aliases(text)
    stable_base_sources = _extract_layout_stable_base_sources(text)
    generic_base_evidence = _extract_layout_generic_base_evidence(text)
    generic_base_trust_candidates = _extract_layout_generic_base_trust_candidates(text)
    rewrite_ready = _extract_layout_rewrite_ready(text)
    rewrite_near_ready = _extract_layout_rewrite_near_ready(text)
    rewrite_blockers = _extract_layout_rewrite_blockers(text)
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
    _count_pattern(
        text_totals,
        text,
        FIELD_ALIAS_RE,
        "inferred_offset_field_aliases",
        "functions_with_inferred_offset_field_aliases",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_SUBFIELD_OVERLAY_RE,
        "inferred_offset_subfield_overlays",
        "functions_with_inferred_offset_subfield_overlays",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_NARROW_SUBFIELD_RE,
        "inferred_offset_narrow_subfields",
        "functions_with_inferred_offset_narrow_subfields",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_BITFIELD_ALIAS_RE,
        "inferred_offset_bitfield_aliases",
        "functions_with_inferred_offset_bitfield_aliases",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_STABLE_BASE_SOURCE_RE,
        "inferred_offset_stable_base_sources",
        "functions_with_inferred_offset_stable_base_sources",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_GENERIC_BASE_EVIDENCE_RE,
        "inferred_offset_generic_base_evidence",
        "functions_with_inferred_offset_generic_base_evidence",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_GENERIC_BASE_TRUST_CANDIDATE_RE,
        "inferred_offset_generic_base_trust_candidates",
        "functions_with_inferred_offset_generic_base_trust_candidates",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_REWRITE_READY_RE,
        "inferred_offset_rewrite_ready",
        "functions_with_inferred_offset_rewrite_ready",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_REWRITE_NEAR_READY_RE,
        "inferred_offset_rewrite_near_ready",
        "functions_with_inferred_offset_rewrite_near_ready",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_REWRITE_BLOCKER_RE,
        "inferred_offset_rewrite_blockers",
        "functions_with_inferred_offset_rewrite_blockers",
    )
    return (
        layout_hints,
        subfield_overlays,
        narrow_subfields,
        bitfield_aliases,
        stable_base_sources,
        generic_base_evidence,
        generic_base_trust_candidates,
        rewrite_ready,
        rewrite_near_ready,
        rewrite_blockers,
        ntstatus_body_literals,
    )


def _update_residue_metrics(text_totals: Counter[str], text: str) -> None:
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
    _count_profiled_status_argument_literals(text_totals, text)
    _count_ntstatus_family_literals(text_totals, text)


def _strip_pseudoforge_header(text: str) -> str:
    match = re.match(r"\s*/\*(?P<header>.*?)\*/\s*", text or "", flags=re.DOTALL)
    if match is None:
        return text
    header = match.group("header")
    if not any(marker in header for marker in ("Generated by PseudoForge", "Kernel insights:", "Rename candidates:")):
        return text
    return text[match.end() :]


def _count_profiled_status_argument_literals(counter: Counter[str], text: str) -> None:
    count = _profiled_status_argument_literal_count(text)
    counter["profiled_status_argument_literals"] += count
    if count:
        counter["functions_with_profiled_status_argument_literals"] += 1


def _count_ntstatus_family_literals(counter: Counter[str], text: str) -> None:
    literals = _ntstatus_family_literals(text)
    if not literals:
        return
    counter["ntstatus_family_literals"] += len(literals)
    counter["functions_with_ntstatus_family_literals"] += 1
    known_count = sum(1 for item in literals if item["profiled"])
    unknown_count = len(literals) - known_count
    counter["ntstatus_profiled_family_literals"] += known_count
    counter["ntstatus_unprofiled_family_literals"] += unknown_count
    if unknown_count:
        counter["functions_with_ntstatus_unprofiled_family_literals"] += 1
    for item in literals:
        severity = str(item["severity"])
        counter["ntstatus_%s_family_literals" % severity] += 1
        if not item["profiled"]:
            counter["ntstatus_unprofiled_%s_family_literals" % severity] += 1


def _ntstatus_family_literals(text: str) -> list[dict[str, Any]]:
    result = []
    for match in NUMERIC_LITERAL_RE.finditer(text or ""):
        context_kind = _ntstatus_literal_context_kind(text, match)
        if not context_kind:
            continue
        parsed = _parse_numeric_literal(match.group("literal"))
        if parsed is None:
            continue
        if parsed >= 0 and parsed > 0xFFFFFFFF:
            continue
        unsigned_value = parsed & 0xFFFFFFFF
        severity = _ntstatus_severity_name(unsigned_value)
        if not severity:
            continue
        profile_name = _ntstatus_profile_name(parsed, match.group("literal"))
        if not profile_name and severity != "error":
            continue
        result.append(
            {
                "literal": match.group("literal"),
                "unsigned_value": unsigned_value,
                "signed_value": _signed_32bit_value(unsigned_value),
                "hex_value": "0x%08X" % unsigned_value,
                "facility": _ntstatus_facility_value(unsigned_value),
                "facility_hex": "0x%03X" % _ntstatus_facility_value(unsigned_value),
                "code": unsigned_value & 0xFFFF,
                "code_hex": "0x%04X" % (unsigned_value & 0xFFFF),
                "customer": bool((unsigned_value >> 29) & 1),
                "line": _line_number_for_offset(text, match.start()),
                "line_text": _line_for_match(text, match.start(), match.end()).strip(),
                "context_kind": context_kind,
                "severity": severity,
                "profile_name": profile_name,
                "profiled": profile_name != "",
            }
        )
    return result


def _update_ntstatus_body_unprofiled_value_metrics(
    literals: list[dict[str, Any]],
    values: Counter[str],
    value_functions: dict[str, set[str]],
    value_contexts: dict[str, Counter[str]],
    context_kinds: Counter[str],
    function_name: str,
) -> None:
    for item in literals:
        hex_value = str(item.get("hex_value", "") or "")
        if not hex_value:
            continue
        context_kind = str(item.get("context_kind", "") or "unknown")
        values[hex_value] += 1
        value_functions.setdefault(hex_value, set()).add(str(function_name or ""))
        value_contexts.setdefault(hex_value, Counter())[context_kind] += 1
        context_kinds[context_kind] += 1


def _ntstatus_unprofiled_value_summaries(
    values: Counter[str],
    value_functions: dict[str, set[str]],
    value_contexts: dict[str, Counter[str]],
    top: int,
) -> list[dict[str, Any]]:
    result = []
    for hex_value, count in values.most_common(top):
        unsigned_value = _parse_numeric_literal(hex_value)
        if unsigned_value is None:
            continue
        result.append(
            {
                "hex_value": hex_value,
                "signed_value": _signed_32bit_value(unsigned_value & 0xFFFFFFFF),
                "facility": _ntstatus_facility_value(unsigned_value),
                "facility_hex": "0x%03X" % _ntstatus_facility_value(unsigned_value),
                "code": unsigned_value & 0xFFFF,
                "code_hex": "0x%04X" % (unsigned_value & 0xFFFF),
                "customer": bool((unsigned_value >> 29) & 1),
                "context_kinds": _counter_to_dict(value_contexts.get(hex_value, Counter())),
                "review_hint": _ntstatus_review_hint(value_contexts.get(hex_value, Counter())),
                "count": int(count),
                "function_count": len(value_functions.get(hex_value, set())),
            }
        )
    return result


def _ntstatus_body_unprofiled_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    literals: list[dict[str, Any]],
) -> dict[str, Any]:
    values = Counter(str(item.get("hex_value", "") or "") for item in literals)
    raw_literals = Counter(str(item.get("literal", "") or "") for item in literals)
    context_kinds = Counter(str(item.get("context_kind", "") or "unknown") for item in literals)
    return {
        "ea": ea,
        "name": name,
        "literal_count": len(literals),
        "review_hint": _ntstatus_review_hint(context_kinds),
        "context_kinds": _counter_to_dict(context_kinds),
        "values": _counter_to_dict(values),
        "raw_literals": _counter_to_dict(raw_literals),
        "contexts": [
            {
                "line": int(item.get("line", 0) or 0),
                "literal": str(item.get("literal", "") or ""),
                "hex_value": str(item.get("hex_value", "") or ""),
                "kind": str(item.get("context_kind", "") or "unknown"),
                "source": str(item.get("line_text", "") or ""),
            }
            for item in literals
        ],
        "summary_path": str(summary_path),
    }


def _ntstatus_facility_value(unsigned_value: int) -> int:
    return (int(unsigned_value) >> 16) & 0xFFF


def _ntstatus_review_hint(context_kinds: Counter[str]) -> str:
    kinds = {str(kind) for kind in context_kinds if str(kind)}
    if not kinds:
        return "manual_review"
    if kinds <= {"comparison"}:
        return "comparison_sentinel_candidate"
    if kinds & {"return", "assignment", "status_argument", "guard_dispatch_fallback"}:
        return "status_profile_candidate"
    return "manual_review"


def _ntstatus_review_hint_counts(value_contexts: dict[str, Counter[str]]) -> Counter[str]:
    result: Counter[str] = Counter()
    for context_kinds in value_contexts.values():
        result[_ntstatus_review_hint(context_kinds)] += 1
    return result


def _ntstatus_review_queues(
    value_summaries: list[dict[str, Any]],
    function_summaries: list[dict[str, Any]],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    queue_by_hint = {
        "comparison_sentinel_candidate": "comparison_sentinel_candidates",
        "manual_review": "manual_review",
        "status_profile_candidate": "status_profile_candidates",
    }
    result = {
        "comparison_sentinel_candidates": {"values": [], "functions": []},
        "manual_review": {"values": [], "functions": []},
        "status_profile_candidates": {"values": [], "functions": []},
    }
    for item in value_summaries:
        queue_name = queue_by_hint.get(str(item.get("review_hint", "")), "manual_review")
        result[queue_name]["values"].append(item)
    for item in function_summaries:
        queue_name = queue_by_hint.get(str(item.get("review_hint", "")), "manual_review")
        result[queue_name]["functions"].append(item)
    return result


def _signed_32bit_value(unsigned_value: int) -> int:
    value = int(unsigned_value) & 0xFFFFFFFF
    if value & 0x80000000:
        return value - 0x100000000
    return value


def _is_ntstatus_literal_context(text: str, match: re.Match[str]) -> bool:
    return _ntstatus_literal_context_kind(text, match) != ""


def _ntstatus_literal_context_kind(text: str, match: re.Match[str]) -> str:
    line = _line_for_match(text, match.start(), match.end())
    token = re.escape(match.group(0))
    if _line_has_bitwise_literal_context(line, token):
        return ""
    for kind, pattern in (
        ("return", r"\breturn\s+(?:\([^)]+\)\s*)?%s\s*;"),
        ("comparison", r"(?:==|!=)\s*%s\b"),
        ("comparison", r"(?<![A-Za-z0-9_])%s\s*(?:==|!=)"),
        ("assignment", r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:\([^)]+\)\s*)?%s\s*;"),
        ("status_argument", r"\bSetFailureLocation\s*\([^;\n]*%s"),
        ("guard_dispatch_fallback", r"\bguard_dispatch_icall_no_overrides\s*\([^;\n]*[?:][^;\n]*%s"),
        ("guard_dispatch_fallback", r"\b%s[^;\n]*[?:][^;\n]*guard_dispatch_icall_no_overrides\s*\("),
    ):
        if re.search(pattern % token, line):
            return kind
    return ""


def _line_for_match(text: str, start: int, end: int) -> str:
    line_start = str(text or "").rfind("\n", 0, max(0, start)) + 1
    line_end = str(text or "").find("\n", max(0, end))
    if line_end < 0:
        line_end = len(str(text or ""))
    return str(text or "")[line_start:line_end]


def _line_number_for_offset(text: str, offset: int) -> int:
    return str(text or "").count("\n", 0, max(0, offset)) + 1


def _line_has_bitwise_literal_context(line: str, token: str) -> bool:
    bitwise_operator = r"(?:\||\^|<<|>>|(?<!&)&(?!&))"
    return (
        re.search(r"%s\s*%s" % (bitwise_operator, token), line or "") is not None
        or re.search(r"%s\s*%s" % (token, bitwise_operator), line or "") is not None
    )


def _ntstatus_severity_name(unsigned_value: int) -> str:
    severity = (int(unsigned_value) >> 30) & 0x3
    if severity == 1:
        return "informational"
    if severity == 2:
        return "warning"
    if severity == 3 and ((int(unsigned_value) >> 28) & 0xF) == 0xC:
        return "error"
    return ""


def _ntstatus_profile_name(value: int, literal: str) -> str:
    candidates = [str(value), str(literal)]
    unsigned_value = value & 0xFFFFFFFF
    candidates.append(str(unsigned_value))
    if unsigned_value & 0x80000000:
        candidates.append(str(unsigned_value - 0x100000000))
    candidates.append("0x%08X" % unsigned_value)
    candidates.append("0x%X" % unsigned_value)
    for candidate in candidates:
        name = NTSTATUS_RETURN_MAP.get(candidate)
        if name:
            return name
    return ""


def _parse_numeric_literal(literal: str) -> int | None:
    try:
        text = str(literal or "")
        if text.lower().startswith("-0x"):
            return -int(text[3:], 16)
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def _profiled_status_argument_literal_count(text: str) -> int:
    if not STATUS_ARGUMENT_INDEXES:
        return 0
    function_names = sorted(STATUS_ARGUMENT_INDEXES, key=len, reverse=True)
    pattern = re.compile(
        r"\b(?P<function>%s)\((?P<args>[^;\n]*)\)"
        % "|".join(re.escape(name) for name in function_names)
    )
    count = 0
    for match in pattern.finditer(text):
        indexes = STATUS_ARGUMENT_INDEXES.get(match.group("function"), set())
        spans = _top_level_argument_spans(match.group("args"))
        for index in indexes:
            if index >= len(spans):
                continue
            start, end = spans[index]
            if _is_status_like_numeric_argument(match.group("args")[start:end]):
                count += 1
    return count


def _is_status_like_numeric_argument(argument: str) -> bool:
    return re.fullmatch(
        r"\s*-?(?:0xC[0-9A-Fa-f]{7}|107374\d+|\d{8,}|322122\d+)"
        r"(?:u?LL|ULL|LL|u|U|L)?\s*",
        argument,
    ) is not None


def _top_level_argument_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            continue
        if char == "," and depth == 0:
            spans.append((start, index))
            start = index + 1
    spans.append((start, len(text)))
    return spans


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


def _extract_layout_subfield_overlays(text: str) -> list[dict[str, Any]]:
    overlays = []
    for match in FIELD_SUBFIELD_OVERLAY_DETAIL_RE.finditer(text or ""):
        fields = _parse_subfield_overlay_fields(match.group("fields"))
        overlays.append(
            {
                "base": match.group("base"),
                "field_count": len(fields),
                "fields": fields,
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return overlays


def _extract_layout_narrow_subfields(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_NARROW_SUBFIELD_DETAIL_RE.finditer(text or ""):
        fields = _parse_subfield_overlay_fields(match.group("fields"))
        candidates.append(
            {
                "base": match.group("base"),
                "field_count": len(fields),
                "fields": fields,
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_bitfield_aliases(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_BITFIELD_ALIAS_DETAIL_RE.finditer(text or ""):
        fields = _parse_bitfield_alias_fields(match.group("fields"))
        candidates.append(
            {
                "base": match.group("base"),
                "field_count": len(fields),
                "fields": fields,
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_stable_base_sources(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_STABLE_BASE_SOURCE_DETAIL_RE.finditer(text or ""):
        candidates.append(
            {
                "base": match.group("base"),
                "source": match.group("source"),
                "source_kind": match.group("source_kind"),
                "access_count": _int_value(match.group("access_count"), 0),
                "offset_count": _int_value(match.group("offset_count"), 0),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_generic_base_evidence(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_GENERIC_BASE_EVIDENCE_DETAIL_RE.finditer(text or ""):
        candidates.append(
            {
                "base": match.group("base"),
                "blocker_profile": match.group("blocker_profile"),
                "access_count": _int_value(match.group("access_count"), 0),
                "offset_count": _int_value(match.group("offset_count"), 0),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_generic_base_trust_candidates(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_GENERIC_BASE_TRUST_CANDIDATE_DETAIL_RE.finditer(text or ""):
        candidates.append(
            {
                "base": match.group("base"),
                "source_kind": match.group("source_kind"),
                "blocker_profile": match.group("blocker_profile").replace("-", "_"),
                "access_count": _int_value(match.group("access_count"), 0),
                "offset_count": _int_value(match.group("offset_count"), 0),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_rewrite_ready(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_REWRITE_READY_DETAIL_RE.finditer(text or ""):
        candidates.append(
            {
                "base": match.group("base"),
                "access_count": _int_value(match.group("access_count"), 0),
                "offset_count": _int_value(match.group("offset_count"), 0),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_rewrite_near_ready(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_REWRITE_NEAR_READY_DETAIL_RE.finditer(text or ""):
        candidates.append(
            {
                "base": match.group("base"),
                "access_count": _int_value(match.group("access_count"), 0),
                "offset_count": _int_value(match.group("offset_count"), 0),
                "missing_threshold": match.group("missing"),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_rewrite_blockers(text: str) -> list[dict[str, Any]]:
    blockers = []
    for match in FIELD_REWRITE_BLOCKER_DETAIL_RE.finditer(text or ""):
        reasons = [
            item.strip()
            for item in match.group("reasons").split(";")
            if item.strip()
        ]
        blockers.append(
            {
                "base": match.group("base"),
                "reasons": reasons,
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return blockers


def _parse_layout_hint_types(value: str) -> list[str]:
    result = []
    for item in str(value or "").split(","):
        type_name = item.strip().strip(".")
        if not type_name or type_name == "...":
            continue
        result.append(type_name)
    return result


def _parse_subfield_overlay_fields(value: str) -> list[dict[str, Any]]:
    fields = []
    for match in SUBFIELD_OVERLAY_FIELD_RE.finditer(value or ""):
        sizes = [
            _int_value(item, 0)
            for item in match.group("sizes").split("/")
            if item
        ]
        size_class = _subfield_overlay_size_class(sizes)
        annotation = _parse_subfield_overlay_annotation(match.group("annotation"))
        fields.append(
            {
                "offset": int(match.group("offset"), 16),
                "sizes": [item for item in sizes if item > 0],
                "size_class": size_class,
                "policy_class": _subfield_overlay_policy_class(size_class),
                "interpretation": annotation["interpretation"],
                "bit_masks": annotation["bit_masks"],
                "bit_operations": annotation["bit_operations"],
                "mask_families": annotation["mask_families"],
                "types": [
                    item.strip()
                    for item in match.group("types").split("/")
                    if item.strip()
                ],
            }
        )
    return fields


def _parse_bitfield_alias_fields(value: str) -> list[dict[str, Any]]:
    fields = []
    for match in BITFIELD_ALIAS_FIELD_RE.finditer(value or ""):
        masks = [
            item
            for item in match.group("masks").split(",")
            if item and item != "unknown"
        ]
        aliases = [
            item
            for item in match.group("aliases").split("/")
            if item
        ]
        offset = int(match.group("offset"), 16)
        fields.append(
            {
                "offset": offset,
                "name": "field_%X" % offset,
                "aliases": aliases,
                "masks": masks,
            }
        )
    return fields


def _parse_subfield_overlay_annotation(value: str | None) -> dict[str, Any]:
    parts = [item for item in str(value or "").split() if item]
    annotation = {
        "interpretation": "unknown",
        "bit_masks": [],
        "bit_operations": [],
        "mask_families": [],
    }
    for index, part in enumerate(parts):
        if index == 0 and "=" not in part:
            annotation["interpretation"] = part
            continue
        key, separator, raw_value = part.partition("=")
        if not separator:
            continue
        values = [item for item in raw_value.split(",") if item]
        if key == "masks":
            annotation["bit_masks"] = values
        elif key == "ops":
            annotation["bit_operations"] = values
        elif key == "families":
            annotation["mask_families"] = values
    return annotation


def _subfield_overlay_size_class(sizes: list[int]) -> str:
    normalized = sorted({int(size) for size in sizes if int(size) > 0})
    if normalized == [1, 2]:
        return "byte_word"
    if normalized == [1, 4]:
        return "byte_dword"
    if normalized == [2, 4]:
        return "word_dword"
    if normalized == [4, 8]:
        return "dword_qword"
    if normalized == [8, 16]:
        return "qword_oword"
    return "mixed_width"


def _subfield_overlay_policy_class(size_class: str) -> str:
    if size_class in {"byte_word", "byte_dword", "word_dword"}:
        return "narrow_subfield"
    if size_class in {"dword_qword", "qword_oword"}:
        return "wide_overlay"
    return "irregular_overlay"


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


def _update_layout_subfield_overlay_metrics(
    overlays: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    size_classes: Counter[str],
    policy_classes: Counter[str],
    interpretations: Counter[str],
    bit_masks: Counter[str],
    bit_operations: Counter[str],
    mask_families: Counter[str],
) -> None:
    if not overlays:
        return
    totals["functions_with_overlay_comments"] += 1
    for overlay in overlays:
        totals["overlay_comments"] += 1
        totals["field_observations"] += _int_value(overlay.get("field_count"), 0)
        bases[str(overlay.get("base", "") or "unknown")] += 1
        for field in overlay.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            size_classes[str(field.get("size_class", "") or "unknown")] += 1
            policy_classes[str(field.get("policy_class", "") or "unknown")] += 1
            interpretations[str(field.get("interpretation", "") or "unknown")] += 1
            for mask in field.get("bit_masks", []) or []:
                bit_masks[str(mask)] += 1
            for operation in field.get("bit_operations", []) or []:
                bit_operations[str(operation)] += 1
            for family in field.get("mask_families", []) or []:
                mask_families[str(family)] += 1


def _update_layout_narrow_subfield_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    size_classes: Counter[str],
    interpretations: Counter[str],
    bit_masks: Counter[str],
    bit_operations: Counter[str],
    mask_families: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_candidate_comments"] += 1
    for candidate in candidates:
        totals["candidate_comments"] += 1
        totals["field_observations"] += _int_value(candidate.get("field_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        for field in candidate.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            size_classes[str(field.get("size_class", "") or "unknown")] += 1
            interpretations[str(field.get("interpretation", "") or "unknown")] += 1
            for mask in field.get("bit_masks", []) or []:
                bit_masks[str(mask)] += 1
            for operation in field.get("bit_operations", []) or []:
                bit_operations[str(operation)] += 1
            for family in field.get("mask_families", []) or []:
                mask_families[str(family)] += 1


def _update_layout_bitfield_alias_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    aliases: Counter[str],
    masks: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_alias_comments"] += 1
    for candidate in candidates:
        totals["alias_comments"] += 1
        totals["field_observations"] += _int_value(candidate.get("field_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        for field in candidate.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            for alias in field.get("aliases", []) or []:
                aliases[str(alias)] += 1
            for mask in field.get("masks", []) or []:
                masks[str(mask)] += 1


def _update_layout_stable_base_source_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    sources: Counter[str],
    source_kinds: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_source_comments"] += 1
    for candidate in candidates:
        totals["source_comments"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        sources[str(candidate.get("source", "") or "unknown")] += 1
        source_kinds[str(candidate.get("source_kind", "") or "unknown")] += 1


def _update_layout_generic_base_evidence_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    blocker_profiles: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_evidence_comments"] += 1
    for candidate in candidates:
        totals["evidence_comments"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        blocker_profiles[str(candidate.get("blocker_profile", "") or "unknown")] += 1


def _update_layout_generic_base_trust_candidate_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    source_kinds: Counter[str],
    blocker_profiles: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_trust_candidates"] += 1
    for candidate in candidates:
        totals["trust_candidates"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        source_kinds[str(candidate.get("source_kind", "") or "unknown")] += 1
        blocker_profiles[str(candidate.get("blocker_profile", "") or "unknown")] += 1


def _update_layout_rewrite_ready_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_ready_candidates"] += 1
    for candidate in candidates:
        totals["ready_candidates"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1


def _update_layout_rewrite_near_ready_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    missing_thresholds: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_near_ready_candidates"] += 1
    for candidate in candidates:
        totals["near_ready_candidates"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        missing_thresholds[str(candidate.get("missing_threshold", "") or "unknown")] += 1


def _update_layout_rewrite_blocker_metrics(
    blockers: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    reasons: Counter[str],
) -> None:
    if not blockers:
        return
    totals["functions_with_blockers"] += 1
    for blocker in blockers:
        totals["blockers"] += 1
        base = str(blocker.get("base", "") or "unknown")
        bases[base] += 1
        reason_items = [str(item) for item in blocker.get("reasons", []) or []]
        totals["reason_observations"] += len(reason_items)
        for reason in reason_items:
            reasons[reason] += 1


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


def _subfield_overlay_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    overlays: list[dict[str, Any]],
) -> dict[str, Any]:
    size_classes = Counter()
    policy_classes = Counter()
    interpretations = Counter()
    bit_masks = Counter()
    bit_operations = Counter()
    mask_families = Counter()
    for overlay in overlays:
        for field in overlay.get("fields", []) or []:
            if isinstance(field, dict):
                size_classes[str(field.get("size_class", "") or "unknown")] += 1
                policy_classes[str(field.get("policy_class", "") or "unknown")] += 1
                interpretations[str(field.get("interpretation", "") or "unknown")] += 1
                for mask in field.get("bit_masks", []) or []:
                    bit_masks[str(mask)] += 1
                for operation in field.get("bit_operations", []) or []:
                    bit_operations[str(operation)] += 1
                for family in field.get("mask_families", []) or []:
                    mask_families[str(family)] += 1
    return {
        "ea": ea,
        "name": name,
        "overlay_count": len(overlays),
        "field_count": sum(_int_value(item.get("field_count"), 0) for item in overlays),
        "bases": [str(item.get("base", "") or "unknown") for item in overlays[:8]],
        "top_size_classes": _counter_to_dict(Counter(dict(size_classes.most_common(5)))),
        "top_policy_classes": _counter_to_dict(Counter(dict(policy_classes.most_common(5)))),
        "top_interpretations": _counter_to_dict(Counter(dict(interpretations.most_common(5)))),
        "top_bit_masks": _counter_to_dict(Counter(dict(bit_masks.most_common(5)))),
        "top_bit_operations": _counter_to_dict(Counter(dict(bit_operations.most_common(5)))),
        "top_mask_families": _counter_to_dict(Counter(dict(mask_families.most_common(5)))),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in overlays), default=0.0),
        "summary_path": str(summary_path),
    }


def _narrow_subfield_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    size_classes = Counter()
    interpretations = Counter()
    bit_masks = Counter()
    bit_operations = Counter()
    mask_families = Counter()
    for candidate in candidates:
        for field in candidate.get("fields", []) or []:
            if isinstance(field, dict):
                size_classes[str(field.get("size_class", "") or "unknown")] += 1
                interpretations[str(field.get("interpretation", "") or "unknown")] += 1
                for mask in field.get("bit_masks", []) or []:
                    bit_masks[str(mask)] += 1
                for operation in field.get("bit_operations", []) or []:
                    bit_operations[str(operation)] += 1
                for family in field.get("mask_families", []) or []:
                    mask_families[str(family)] += 1
    return {
        "ea": ea,
        "name": name,
        "candidate_count": len(candidates),
        "field_count": sum(_int_value(item.get("field_count"), 0) for item in candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "top_size_classes": _counter_to_dict(Counter(dict(size_classes.most_common(5)))),
        "top_interpretations": _counter_to_dict(Counter(dict(interpretations.most_common(5)))),
        "top_bit_masks": _counter_to_dict(Counter(dict(bit_masks.most_common(5)))),
        "top_bit_operations": _counter_to_dict(Counter(dict(bit_operations.most_common(5)))),
        "top_mask_families": _counter_to_dict(Counter(dict(mask_families.most_common(5)))),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _bitfield_alias_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    aliases = Counter()
    masks = Counter()
    for candidate in candidates:
        for field in candidate.get("fields", []) or []:
            if isinstance(field, dict):
                for alias in field.get("aliases", []) or []:
                    aliases[str(alias)] += 1
                for mask in field.get("masks", []) or []:
                    masks[str(mask)] += 1
    return {
        "ea": ea,
        "name": name,
        "alias_comment_count": len(candidates),
        "field_count": sum(_int_value(item.get("field_count"), 0) for item in candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "top_aliases": _counter_to_dict(Counter(dict(aliases.most_common(5)))),
        "top_masks": _counter_to_dict(Counter(dict(masks.most_common(5)))),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _stable_base_source_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    sources = Counter()
    source_kinds = Counter()
    for candidate in candidates:
        sources[str(candidate.get("source", "") or "unknown")] += 1
        source_kinds[str(candidate.get("source_kind", "") or "unknown")] += 1
    return {
        "ea": ea,
        "name": name,
        "source_comment_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "top_sources": _counter_to_dict(Counter(dict(sources.most_common(5)))),
        "top_source_kinds": _counter_to_dict(Counter(dict(source_kinds.most_common(5)))),
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _generic_base_evidence_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    blocker_profiles = Counter(
        str(item.get("blocker_profile", "") or "unknown")
        for item in candidates
    )
    return {
        "ea": ea,
        "name": name,
        "evidence_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "blocker_profiles": _counter_to_dict(blocker_profiles),
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _generic_base_trust_candidate_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    source_kinds = Counter(
        str(item.get("source_kind", "") or "unknown")
        for item in candidates
    )
    blocker_profiles = Counter(
        str(item.get("blocker_profile", "") or "unknown")
        for item in candidates
    )
    return {
        "ea": ea,
        "name": name,
        "candidate_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "source_kinds": _counter_to_dict(source_kinds),
        "blocker_profiles": _counter_to_dict(blocker_profiles),
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _rewrite_ready_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "ea": ea,
        "name": name,
        "ready_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _rewrite_near_ready_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    missing_thresholds = Counter(
        str(item.get("missing_threshold", "") or "unknown")
        for item in candidates
    )
    return {
        "ea": ea,
        "name": name,
        "near_ready_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "missing_thresholds": _counter_to_dict(missing_thresholds),
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _rewrite_blocker_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    blockers: list[dict[str, Any]],
) -> dict[str, Any]:
    reasons = Counter()
    bases = []
    for blocker in blockers:
        bases.append(str(blocker.get("base", "") or "unknown"))
        for reason in blocker.get("reasons", []) or []:
            reasons[str(reason)] += 1
    return {
        "ea": ea,
        "name": name,
        "blocker_count": len(blockers),
        "reason_count": sum(reasons.values()),
        "bases": bases[:8],
        "top_reasons": _counter_to_dict(Counter(dict(reasons.most_common(5)))),
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


def _markdown_table_cell(value: Any) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return text.replace("|", "\\|")


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

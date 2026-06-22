from __future__ import annotations

import difflib
import hashlib
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from ida_pseudoforge.core.buffer_contracts import (
    buffer_contracts_json_payload,
    render_buffer_contract_report,
    render_buffer_struct_header,
)
from ida_pseudoforge.core.layout_rewrite_preview import build_layout_rewrite_preview_bundle
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture
from ida_pseudoforge.core.domain_identity_summary import domain_identity_summary_payload
from ida_pseudoforge.core.render import (
    render_cleaned_pseudocode,
    render_flow_report,
    render_switch_outline,
)
from ida_pseudoforge.core.render_warnings import export_warnings
from ida_pseudoforge.core.rule_diagnostics import summarize_rule_report
from ida_pseudoforge.profiles.loader import (
    active_profile_manifests,
    active_profile_names,
    active_profile_root,
    profile_load_warnings,
)
from ida_pseudoforge.version import VERSION


def write_export_bundle(
    output_dir: str | Path,
    capture: FunctionCapture,
    plan: CleanPlan,
    entrypoint: str = "export_bundle",
    summary_suffix: str = "summary",
    cleaned_text: str | None = None,
    extra_summary: dict[str, object] | None = None,
    extra_artifacts: dict[str, str] | None = None,
    file_stem: str | None = None,
    apply_validated_layout_rewrites: bool = False,
) -> dict[str, str]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    safe_name = safe_artifact_stem(
        file_stem or capture.name or "function",
        digest_source="%X:%s" % (capture.ea, capture.name or file_stem or "function"),
    )

    cleaned_path = output_path / f"{safe_name}.cleaned.cpp"
    switch_outline_path = output_path / f"{safe_name}.switch-outline.cpp"
    rename_map_path = output_path / f"{safe_name}.rename-map.json"
    flow_report_path = output_path / f"{safe_name}.flow-report.md"
    buffer_contract_report_path = output_path / f"{safe_name}.buffer-contracts.md"
    buffer_contract_json_path = output_path / f"{safe_name}.buffer-contracts.json"
    buffer_struct_header_path = output_path / f"{safe_name}.buffer-structs.hpp"
    rule_report_path = output_path / f"{safe_name}.rule-report.json"
    raw_path = output_path / f"{safe_name}.raw.cpp"
    warnings_path = output_path / f"{safe_name}.warnings.json"
    diff_path = output_path / f"{safe_name}.raw-vs-cleaned.diff"
    layout_rewrite_preview_path = output_path / f"{safe_name}.layout-rewrite-preview.cpp"
    layout_rewrite_preview_diff_path = output_path / f"{safe_name}.layout-rewrite-preview.diff"
    layout_rewrite_preview_json_path = output_path / f"{safe_name}.layout-rewrite-preview.json"
    summary_path = output_path / f"{safe_name}.{safe_artifact_stem(summary_suffix or 'summary', 48)}.json"

    if cleaned_text is None:
        cleaned_text = render_cleaned_pseudocode(capture, plan)
    layout_rewrite_preview = build_layout_rewrite_preview_bundle(
        cleaned_text,
        safe_name,
        apply_validated_body_rewrite=apply_validated_layout_rewrites,
    )
    if layout_rewrite_preview is not None and layout_rewrite_preview.canonical_text is not None:
        cleaned_text = layout_rewrite_preview.canonical_text
    raw_text = capture.pseudocode.rstrip() + "\n"
    switch_outline_text = render_switch_outline(capture, plan)
    flow_report_text = render_flow_report(capture, plan)
    buffer_contract_report_text = render_buffer_contract_report(capture, plan.buffer_contracts)
    buffer_struct_header_text = render_buffer_struct_header(capture, plan.buffer_contracts)
    warnings = _combined_export_warnings(plan)

    cleaned_path.write_text(cleaned_text, encoding="utf-8")
    switch_outline_path.write_text(switch_outline_text, encoding="utf-8")
    rename_map_path.write_text(
        json.dumps(plan.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    flow_report_path.write_text(flow_report_text, encoding="utf-8")
    buffer_contract_report_path.write_text(buffer_contract_report_text, encoding="utf-8")
    buffer_contract_json_path.write_text(
        json.dumps(buffer_contracts_json_payload(plan.buffer_contracts), indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    buffer_struct_header_path.write_text(buffer_struct_header_text, encoding="utf-8")
    rule_report_path.write_text(
        json.dumps(plan.rule_report or {}, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    raw_path.write_text(raw_text, encoding="utf-8")
    warnings_path.write_text(json.dumps(warnings, indent=2, ensure_ascii=True), encoding="utf-8")
    diff_path.write_text(_raw_vs_cleaned_diff(safe_name, raw_text, cleaned_text), encoding="utf-8")
    if layout_rewrite_preview is not None:
        layout_rewrite_preview_path.write_text(layout_rewrite_preview.text, encoding="utf-8")
        layout_rewrite_preview_diff_path.write_text(layout_rewrite_preview.diff, encoding="utf-8")
        layout_rewrite_preview_json_path.write_text(
            json.dumps(layout_rewrite_preview.metadata, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )

    artifacts = {
        "cleaned_pseudocode": str(cleaned_path),
        "switch_outline": str(switch_outline_path),
        "rename_map": str(rename_map_path),
        "flow_report": str(flow_report_path),
        "buffer_contract_report": str(buffer_contract_report_path),
        "buffer_contracts": str(buffer_contract_json_path),
        "buffer_structs": str(buffer_struct_header_path),
        "rule_report": str(rule_report_path),
        "raw_pseudocode": str(raw_path),
        "warnings": str(warnings_path),
        "raw_vs_cleaned_diff": str(diff_path),
        "summary": str(summary_path),
    }
    if layout_rewrite_preview is not None:
        artifacts.update(
            {
                "layout_rewrite_preview": str(layout_rewrite_preview_path),
                "layout_rewrite_preview_diff": str(layout_rewrite_preview_diff_path),
                "layout_rewrite_preview_metadata": str(layout_rewrite_preview_json_path),
            }
        )
    if extra_artifacts:
        artifacts.update({str(key): str(value) for key, value in extra_artifacts.items()})
    summary_payload = _export_summary_payload(capture, plan, entrypoint, warnings, artifacts)
    if extra_summary:
        summary_payload.update(extra_summary)
    summary_path.write_text(
        json.dumps(summary_payload, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    return artifacts


def safe_artifact_stem(name: str, max_length: int = 96, digest_source: str | None = None) -> str:
    cleaned = "".join(
        char if char.isascii() and (char.isalnum() or char in "._-") else "_"
        for char in str(name or "function")
    )
    cleaned = cleaned.strip("._") or "function"
    limit = max(16, int(max_length or 0))
    if len(cleaned) <= limit:
        return cleaned
    digest_input = str(digest_source if digest_source is not None else name)
    digest = hashlib.sha256(digest_input.encode("utf-8", errors="replace")).hexdigest()[:12]
    suffix = "_" + digest
    prefix_length = max(1, limit - len(suffix))
    prefix = cleaned[:prefix_length].rstrip("._-") or "function"
    return prefix + suffix


def _combined_export_warnings(plan: CleanPlan) -> list[str]:
    return export_warnings(plan)


def _raw_vs_cleaned_diff(safe_name: str, raw_text: str, cleaned_text: str) -> str:
    return "".join(
        difflib.unified_diff(
            raw_text.splitlines(keepends=True),
            cleaned_text.splitlines(keepends=True),
            fromfile="raw/%s.cpp" % safe_name,
            tofile="cleaned/%s.cpp" % safe_name,
            lineterm="\n",
        )
    )


def _export_summary_payload(
    capture: FunctionCapture,
    plan: CleanPlan,
    entrypoint: str,
    warnings: list[str],
    artifacts: dict[str, str],
) -> dict[str, object]:
    rule_diagnostics = summarize_rule_report(plan.rule_report)
    return {
        "mode": entrypoint,
        "pseudoforge_version": VERSION,
        "function": capture.name,
        "function_ea": "0x%X" % capture.ea,
        "source_path": capture.source_path,
        "input_fingerprint": plan.input_fingerprint,
        "rename_candidates": len(plan.renames),
        "renames": len(plan.active_renames()),
        "flow_rewrites": len(plan.flow_rewrites),
        "buffer_contracts": len(plan.buffer_contracts),
        "warnings": len(warnings),
        "rule_diagnostics": rule_diagnostics,
        "rule_load_errors": list(rule_diagnostics["load_error_details"]),
        "rule_validation_errors": list(rule_diagnostics["validation_error_details"]),
        "domain_identity_summary": domain_identity_summary_payload(plan),
        "function_identity_candidates": [asdict(item) for item in plan.function_identity_candidates],
        "parameter_type_corrections": [asdict(item) for item in plan.type_corrections],
        "corrected_parameter_map": [asdict(item) for item in plan.corrected_parameter_map],
        "body_canonical_rewrite_summary": _body_canonical_rewrite_summary(plan),
        "source_context": _source_context_payload(capture),
        "profile_root": active_profile_root(),
        "active_profiles": active_profile_names(),
        "profile_warnings": profile_load_warnings(),
        "profile_manifests": active_profile_manifests(),
        "artifacts": dict(artifacts),
    }


def _source_context_payload(capture: FunctionCapture) -> dict[str, object]:
    return {
        "source_path": str(capture.source_path or ""),
        "profile_context": _jsonable_mapping(capture.profile_context),
    }


def _body_canonical_rewrite_summary(plan: CleanPlan) -> dict[str, object]:
    relevant_kinds = {
        "inferred_offset_rewrite_ready": "rewrite_ready",
        "inferred_offset_rewrite_preview": "rewrite_preview",
        "inferred_offset_rewrite_blockers": "rewrite_blockers",
        "inferred_offset_rewrite_partial_opportunity": "partial_opportunity",
    }
    kind_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()
    source_provenance_counts: Counter[str] = Counter()
    domain_profile_counts: Counter[str] = Counter()
    bases: set[str] = set()
    for comment in plan.comments:
        summary_kind = relevant_kinds.get(str(comment.get("kind", "")))
        if not summary_kind:
            continue
        kind_counts[summary_kind] += 1
        base = str(comment.get("base", "") or "").strip()
        if base:
            bases.add(base)
        source_provenance = str(comment.get("source_provenance", "") or "").strip()
        if source_provenance:
            source_provenance_counts[source_provenance] += 1
        domain_profile_id = str(comment.get("domain_profile_id", "") or "").strip()
        if domain_profile_id:
            domain_profile_counts[domain_profile_id] += 1
        for blocker in comment.get("blockers", []) or []:
            blocker_text = str(blocker or "").strip()
            if blocker_text:
                blocker_counts[blocker_text] += 1
    return {
        "rewrite_ready": int(kind_counts["rewrite_ready"]),
        "rewrite_preview": int(kind_counts["rewrite_preview"]),
        "rewrite_blockers": int(kind_counts["rewrite_blockers"]),
        "partial_opportunities": int(kind_counts["partial_opportunity"]),
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "source_provenance_counts": dict(sorted(source_provenance_counts.items())),
        "domain_profile_counts": dict(sorted(domain_profile_counts.items())),
        "bases": sorted(bases),
    }


def _jsonable_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, object] = {}
    for key, item in value.items():
        key_text = str(key)
        if item is None or isinstance(item, (bool, int, float, str)):
            result[key_text] = item
        elif isinstance(item, (list, tuple)):
            result[key_text] = [
                entry if entry is None or isinstance(entry, (bool, int, float, str)) else str(entry)
                for entry in item
            ]
        else:
            result[key_text] = str(item)
    return result

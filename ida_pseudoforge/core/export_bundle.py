from __future__ import annotations

import difflib
import json
from pathlib import Path

from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture
from ida_pseudoforge.core.render import (
    _safe_file_stem,
    render_cleaned_pseudocode,
    render_flow_report,
    render_switch_outline,
)
from ida_pseudoforge.profiles.loader import active_profile_manifests, profile_load_warnings
from ida_pseudoforge.version import VERSION


def write_export_bundle(
    output_dir: str | Path,
    capture: FunctionCapture,
    plan: CleanPlan,
    entrypoint: str = "export_bundle",
    summary_suffix: str = "summary",
) -> dict[str, str]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    safe_name = _safe_file_stem(capture.name or "function")

    cleaned_path = output_path / f"{safe_name}.cleaned.cpp"
    switch_outline_path = output_path / f"{safe_name}.switch-outline.cpp"
    rename_map_path = output_path / f"{safe_name}.rename-map.json"
    flow_report_path = output_path / f"{safe_name}.flow-report.md"
    rule_report_path = output_path / f"{safe_name}.rule-report.json"
    raw_path = output_path / f"{safe_name}.raw.cpp"
    warnings_path = output_path / f"{safe_name}.warnings.json"
    diff_path = output_path / f"{safe_name}.raw-vs-cleaned.diff"
    summary_path = output_path / f"{safe_name}.{_safe_file_stem(summary_suffix or 'summary')}.json"

    cleaned_text = render_cleaned_pseudocode(capture, plan)
    raw_text = capture.pseudocode.rstrip() + "\n"
    switch_outline_text = render_switch_outline(capture, plan)
    flow_report_text = render_flow_report(capture, plan)
    warnings = _combined_export_warnings(plan)

    cleaned_path.write_text(cleaned_text, encoding="utf-8")
    switch_outline_path.write_text(switch_outline_text, encoding="utf-8")
    rename_map_path.write_text(
        json.dumps(plan.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    flow_report_path.write_text(flow_report_text, encoding="utf-8")
    rule_report_path.write_text(
        json.dumps(plan.rule_report or {}, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    raw_path.write_text(raw_text, encoding="utf-8")
    warnings_path.write_text(json.dumps(warnings, indent=2, ensure_ascii=True), encoding="utf-8")
    diff_path.write_text(_raw_vs_cleaned_diff(safe_name, raw_text, cleaned_text), encoding="utf-8")

    artifacts = {
        "cleaned_pseudocode": str(cleaned_path),
        "switch_outline": str(switch_outline_path),
        "rename_map": str(rename_map_path),
        "flow_report": str(flow_report_path),
        "rule_report": str(rule_report_path),
        "raw_pseudocode": str(raw_path),
        "warnings": str(warnings_path),
        "raw_vs_cleaned_diff": str(diff_path),
        "summary": str(summary_path),
    }
    summary_path.write_text(
        json.dumps(
            _export_summary_payload(capture, plan, entrypoint, warnings, artifacts),
            indent=2,
            ensure_ascii=True,
        ),
        encoding="utf-8",
    )
    return artifacts


def _combined_export_warnings(plan: CleanPlan) -> list[str]:
    result = []
    seen = set()
    for warning in list(plan.warnings) + profile_load_warnings():
        text = str(warning)
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


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
        "warnings": len(warnings),
        "rule_load_errors": list((plan.rule_report or {}).get("load_errors", [])),
        "profile_warnings": profile_load_warnings(),
        "profile_manifests": active_profile_manifests(),
        "artifacts": dict(artifacts),
    }

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.benchmark import run_benchmark
from ida_pseudoforge.core.benchmark_report import write_benchmark_report
from ida_pseudoforge.core.benchmark_schema import load_benchmark_fixtures
from ida_pseudoforge.core.agentic_benchmark import (
    apply_agentic_report_to_corpus_evidence,
    load_agentic_task_suite,
    run_agentic_benchmark,
)
from ida_pseudoforge.core.claim_gate import evaluate_claim_gate
from ida_pseudoforge.core.claim_gap import render_world_class_gap_markdown, world_class_gap_report
from ida_pseudoforge.core.corpus_evidence import load_corpus_evidence, load_corpus_manifest, summarize_corpus_manifests
from ida_pseudoforge.core.evidence_pack import (
    apply_evidence_ledgers_to_manifests,
    load_analyst_audit_ledgers,
    load_cross_function_contract_ledgers,
    load_external_baseline_ledgers,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a complete benchmark and world-class claim-gap pack.")
    parser.add_argument("fixtures", nargs="+", help="Fixture JSON files or directories containing fixture JSON files.")
    parser.add_argument("--out-dir", required=True, help="Output directory for claim pack artifacts.")
    parser.add_argument(
        "--corpus-manifest",
        action="append",
        default=[],
        help="Attach one or more corpus-evidence manifest JSON files to the claim gate.",
    )
    parser.add_argument(
        "--external-baseline-ledger",
        action="append",
        default=[],
        help="Attach one or more external baseline ledger JSON files to corpus evidence.",
    )
    parser.add_argument(
        "--analyst-audit-ledger",
        action="append",
        default=[],
        help="Attach one or more analyst audit ledger JSON files to corpus evidence.",
    )
    parser.add_argument(
        "--cross-function-contract-ledger",
        action="append",
        default=[],
        help="Attach one or more cross-function contract ledger JSON files to corpus evidence.",
    )
    parser.add_argument(
        "--agentic-task-suite",
        action="append",
        default=[],
        help="Run one or more agentic task suites against the benchmark report and attach the results.",
    )
    parser.add_argument("--no-runtime", action="store_true", help="Use deterministic runtime_ms=0 in reports.")
    args = parser.parse_args(argv)
    try:
        fixtures = load_benchmark_fixtures([Path(item) for item in args.fixtures])
        corpus_evidence = _load_corpus_evidence(
            [Path(item) for item in args.corpus_manifest],
            [Path(item) for item in args.external_baseline_ledger],
            [Path(item) for item in args.analyst_audit_ledger],
            [Path(item) for item in args.cross_function_contract_ledger],
        )
        report = run_benchmark(
            fixtures,
            measure_runtime=not args.no_runtime,
            corpus_evidence=corpus_evidence,
        )
        if args.agentic_task_suite:
            report = _attach_agentic_task_suites(
                report,
                [Path(item) for item in args.agentic_task_suite],
            )
        gap = world_class_gap_report(report)
        summary = _summary_payload(report, gap)
        _write_pack(Path(args.out_dir), report, gap, summary)
    except (OSError, ValueError) as exc:
        print("PseudoForge claim pack failed: %s" % exc, file=sys.stderr)
        return 2
    return 0 if report.get("failed", 0) == 0 and report.get("claim_gate", {}).get("status") != "failed" else 1


def _load_corpus_evidence(
    manifest_paths: list[Path],
    baseline_ledger_paths: list[Path],
    audit_ledger_paths: list[Path],
    contract_ledger_paths: list[Path],
) -> dict[str, object] | None:
    if not manifest_paths:
        if baseline_ledger_paths or audit_ledger_paths or contract_ledger_paths:
            raise ValueError("corpus manifest is required when attaching evidence ledgers")
        return None
    if not baseline_ledger_paths and not audit_ledger_paths and not contract_ledger_paths:
        return load_corpus_evidence(manifest_paths)
    manifests = [load_corpus_manifest(path) for path in manifest_paths]
    baseline_ledgers = load_external_baseline_ledgers(baseline_ledger_paths)
    audit_ledgers = load_analyst_audit_ledgers(audit_ledger_paths)
    contract_ledgers = load_cross_function_contract_ledgers(contract_ledger_paths)
    return summarize_corpus_manifests(
        apply_evidence_ledgers_to_manifests(manifests, baseline_ledgers, audit_ledgers, contract_ledgers)
    )


def _attach_agentic_task_suites(
    report: dict[str, object],
    task_suite_paths: list[Path],
) -> dict[str, object]:
    agentic_reports = [
        run_agentic_benchmark(load_agentic_task_suite(path), report)
        for path in task_suite_paths
    ]
    corpus_evidence = dict(report.get("corpus_evidence", {}) or {})
    for agentic_report in agentic_reports:
        corpus_evidence = apply_agentic_report_to_corpus_evidence(corpus_evidence, agentic_report)
    result = dict(report)
    result["agentic_benchmark_reports"] = agentic_reports
    result["corpus_evidence"] = corpus_evidence
    claim_gate = evaluate_claim_gate(result)
    result["claim_gate"] = claim_gate
    result["claim_level"] = claim_gate["claim_level"]
    return result


def _summary_payload(report: dict[str, object], gap: dict[str, object]) -> dict[str, object]:
    claim_gate = report.get("claim_gate", {})
    if not isinstance(claim_gate, dict):
        claim_gate = {}
    return {
        "schema": "pseudoforge_claim_pack_summary_v1",
        "claim_level": str(report.get("claim_level", "") or ""),
        "claim_status": str(claim_gate.get("status", "") or ""),
        "world_class_claim_allowed": bool(claim_gate.get("world_class_claim_allowed", False)),
        "external_world_class_claim_allowed": bool(claim_gate.get("external_world_class_claim_allowed", False)),
        "gap_count": int(gap.get("gap_count", 0) or 0),
        "external_gap_count": int(gap.get("external_gap_count", 0) or 0),
        "fixture_count": int(report.get("fixture_count", 0) or 0),
        "passed": int(report.get("passed", 0) or 0),
        "failed": int(report.get("failed", 0) or 0),
        "false_positives": int(report.get("false_positives", 0) or 0),
    }


def _write_pack(out_dir: Path, report: dict[str, object], gap: dict[str, object], summary: dict[str, object]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_benchmark_report(report, out_dir / "benchmark.json", out_dir / "benchmark.md")
    (out_dir / "claim-gap.json").write_text(json.dumps(gap, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "claim-gap.md").write_text(render_world_class_gap_markdown(gap), encoding="utf-8")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())

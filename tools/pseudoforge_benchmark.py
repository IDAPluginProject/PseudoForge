from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.benchmark import run_benchmark
from ida_pseudoforge.core.benchmark_report import benchmark_report_to_markdown, write_benchmark_report
from ida_pseudoforge.core.benchmark_schema import load_benchmark_fixtures
from ida_pseudoforge.core.claim_gate import evaluate_claim_gate
from ida_pseudoforge.core.corpus_evidence import load_corpus_evidence, load_corpus_manifest, summarize_corpus_manifests
from ida_pseudoforge.core.evidence_pack import (
    apply_evidence_ledgers_to_manifests,
    load_analyst_audit_ledgers,
    load_cross_function_contract_ledgers,
    load_external_baseline_ledgers,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run PseudoForge general-analysis benchmark fixtures.")
    parser.add_argument("fixtures", nargs="+", help="Fixture JSON files or directories containing fixture JSON files.")
    parser.add_argument("--json-out", default="", help="Write benchmark report JSON to this path.")
    parser.add_argument("--markdown-out", default="", help="Write benchmark report Markdown to this path.")
    parser.add_argument("--baseline-json", default="", help="Compare against a previous benchmark JSON report.")
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
        if args.baseline_json:
            baseline_report = json.loads(Path(args.baseline_json).read_text(encoding="utf-8"))
            if not isinstance(baseline_report, dict):
                raise ValueError("baseline JSON root must be an object")
            claim_gate = evaluate_claim_gate(report, baseline_report=baseline_report)
            report["claim_gate"] = claim_gate
            report["claim_level"] = claim_gate["claim_level"]
    except (OSError, ValueError) as exc:
        print("PseudoForge benchmark failed: %s" % exc, file=sys.stderr)
        return 2
    if args.json_out:
        write_benchmark_report(
            report,
            args.json_out,
            args.markdown_out or None,
        )
    elif args.markdown_out:
        Path(args.markdown_out).write_text(benchmark_report_to_markdown(report), encoding="utf-8")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    claim_gate = report.get("claim_gate", {})
    claim_gate_failed = isinstance(claim_gate, dict) and str(claim_gate.get("status", "") or "") == "failed"
    return 0 if int(report.get("failed", 0) or 0) == 0 and not claim_gate_failed else 1


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


if __name__ == "__main__":
    raise SystemExit(main())

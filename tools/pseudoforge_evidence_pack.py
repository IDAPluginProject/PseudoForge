from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.corpus_evidence import load_corpus_manifest
from ida_pseudoforge.core.evidence_pack import (
    apply_evidence_ledgers,
    load_analyst_audit_ledgers,
    load_cross_function_contract_ledgers,
    load_external_baseline_ledgers,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Attach external baseline and audit evidence to a corpus manifest.")
    parser.add_argument("--corpus-manifest", required=True, help="Input corpus manifest JSON.")
    parser.add_argument("--external-baseline-ledger", action="append", default=[], help="External baseline ledger JSON.")
    parser.add_argument("--analyst-audit-ledger", action="append", default=[], help="Analyst audit ledger JSON.")
    parser.add_argument(
        "--cross-function-contract-ledger",
        action="append",
        default=[],
        help="Cross-function contract ledger JSON.",
    )
    parser.add_argument("--json-out", default="", help="Write merged corpus manifest JSON to this path.")
    args = parser.parse_args(argv)
    try:
        manifest = load_corpus_manifest(args.corpus_manifest)
        baseline_ledgers = load_external_baseline_ledgers(
            [Path(item) for item in args.external_baseline_ledger]
        )
        audit_ledgers = load_analyst_audit_ledgers(
            [Path(item) for item in args.analyst_audit_ledger]
        )
        contract_ledgers = load_cross_function_contract_ledgers(
            [Path(item) for item in args.cross_function_contract_ledger]
        )
        merged = apply_evidence_ledgers(manifest, baseline_ledgers, audit_ledgers, contract_ledgers)
        payload = {
            "schema": merged["schema"],
            "corpora": merged.get("corpora", []),
        }
    except (OSError, ValueError) as exc:
        print("PseudoForge evidence pack failed: %s" % exc, file=sys.stderr)
        return 2
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.json_out:
        target = Path(args.json_out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

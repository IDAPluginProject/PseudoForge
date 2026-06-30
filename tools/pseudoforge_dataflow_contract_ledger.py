from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.dataflow_contract_ledger import build_cross_function_contract_ledger


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build cross-function contract ledgers from IDA export IR evidence.")
    parser.add_argument("export_root", nargs="+", help="IDA export function root or function.rename-map.json path.")
    parser.add_argument("--corpus-name", required=True, help="Corpus name to attach ledger entries to.")
    parser.add_argument("--target-family", required=True, help="Corpus target family.")
    parser.add_argument(
        "--reference-prefix",
        default="ida-dataflow-contract://local",
        help="Reference prefix for generated contract evidence.",
    )
    parser.add_argument("--max-contracts", type=int, default=0, help="Maximum contracts to emit. 0 means all.")
    parser.add_argument("--json-out", default="", help="Optional output JSON path.")
    args = parser.parse_args(argv)
    try:
        ledger = build_cross_function_contract_ledger(
            [Path(item) for item in args.export_root],
            corpus_name=args.corpus_name,
            target_family=args.target_family,
            reference_prefix=args.reference_prefix,
            max_contracts=max(0, int(args.max_contracts)),
        )
    except (OSError, ValueError) as exc:
        print("PseudoForge dataflow contract ledger failed: %s" % exc, file=sys.stderr)
        return 2
    text = json.dumps(ledger, indent=2, sort_keys=True)
    if args.json_out:
        target = Path(args.json_out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

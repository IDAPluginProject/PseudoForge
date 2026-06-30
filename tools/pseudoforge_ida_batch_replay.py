from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.ida_batch_replay import (
    corpus_manifest_from_ida_batch_summaries,
    load_ida_batch_summaries,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert IDA batch summaries into corpus replay manifests.")
    parser.add_argument("summary_path", nargs="+", help="IDA batch summary files or directories.")
    parser.add_argument("--name-prefix", default="ida_batch_replay", help="Corpus name prefix.")
    parser.add_argument("--source-reference", default="", help="Shared source reference for claim-eligible replay.")
    parser.add_argument("--claim-eligible", action="store_true", help="Mark generated replay corpora as claim eligible.")
    parser.add_argument(
        "--include-symbol-ground-truth",
        action="store_true",
        help="Promote stable IDA symbol identities with IR evidence into qualified ground-truth pairs.",
    )
    parser.add_argument(
        "--include-contract-call-evidence",
        action="store_true",
        help="Promote matched contract symbols with IR evidence into qualified cross-function contracts.",
    )
    parser.add_argument("--json-out", default="", help="Write generated corpus manifest JSON to this path.")
    args = parser.parse_args(argv)
    try:
        summaries = load_ida_batch_summaries(args.summary_path)
        manifest = corpus_manifest_from_ida_batch_summaries(
            summaries,
            name_prefix=args.name_prefix,
            source_reference=args.source_reference,
            claim_eligible=args.claim_eligible,
            include_symbol_ground_truth=args.include_symbol_ground_truth,
            include_contract_call_evidence=args.include_contract_call_evidence,
        )
    except (OSError, ValueError) as exc:
        print("PseudoForge IDA batch replay failed: %s" % exc, file=sys.stderr)
        return 2
    text = json.dumps(manifest, indent=2, sort_keys=True)
    if args.json_out:
        target = Path(args.json_out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

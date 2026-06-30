from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.analyst_audit_worklist import (
    analyst_audit_ledger_from_corpus_manifest,
    load_corpus_manifest_for_audit,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a non-qualifying analyst audit ledger worklist.")
    parser.add_argument("corpus_manifest", help="Corpus manifest JSON path.")
    parser.add_argument("--reviewer", default="pending-review", help="Reviewer label for generated worklist entries.")
    parser.add_argument(
        "--reference-prefix",
        default="pending-review://",
        help="Reference prefix for generated pending-review audit entries.",
    )
    parser.add_argument("--json-out", default="", help="Write analyst audit ledger JSON to this path.")
    args = parser.parse_args(argv)
    try:
        manifest = load_corpus_manifest_for_audit(args.corpus_manifest)
        ledger = analyst_audit_ledger_from_corpus_manifest(
            manifest,
            reviewer=args.reviewer,
            reference_prefix=args.reference_prefix,
        )
    except (OSError, ValueError) as exc:
        print("PseudoForge analyst audit worklist failed: %s" % exc, file=sys.stderr)
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

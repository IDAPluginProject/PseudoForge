from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.corpus_replay import corpus_manifest_from_benchmark_reports, load_benchmark_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert benchmark reports into corpus replay manifests.")
    parser.add_argument("benchmark_json", nargs="+", help="Benchmark JSON report paths.")
    parser.add_argument("--name-prefix", default="benchmark_replay", help="Corpus name prefix.")
    parser.add_argument("--source-reference", default="", help="Shared source reference for claim-eligible replay.")
    parser.add_argument("--claim-eligible", action="store_true", help="Mark generated replay corpora as claim eligible.")
    parser.add_argument("--json-out", default="", help="Write generated corpus manifest JSON to this path.")
    args = parser.parse_args(argv)
    try:
        reports = [load_benchmark_report(path) for path in args.benchmark_json]
        manifest = corpus_manifest_from_benchmark_reports(
            reports,
            name_prefix=args.name_prefix,
            source_reference=args.source_reference,
            claim_eligible=args.claim_eligible,
        )
    except (OSError, ValueError) as exc:
        print("PseudoForge corpus replay failed: %s" % exc, file=sys.stderr)
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

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.baseline_adapters import (
    corpus_baseline_records_from_adapter_reports,
    load_baseline_adapter_report,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize external decompiler baseline adapter reports.")
    parser.add_argument("baseline_report", nargs="+", help="Baseline adapter report JSON files.")
    parser.add_argument("--json-out", default="", help="Write normalized baseline comparison records JSON.")
    args = parser.parse_args(argv)
    try:
        reports = [load_baseline_adapter_report(Path(item)) for item in args.baseline_report]
        payload = {
            "schema": "pseudoforge_baseline_comparison_records_v1",
            "baseline_comparisons": corpus_baseline_records_from_adapter_reports(reports),
        }
    except (OSError, ValueError) as exc:
        print("PseudoForge baseline adapter failed: %s" % exc, file=sys.stderr)
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

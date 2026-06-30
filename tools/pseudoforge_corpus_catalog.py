from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.corpus_catalog import corpus_manifest_from_public_catalog, load_public_corpus_catalog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert a public corpus catalog into a PseudoForge corpus manifest.")
    parser.add_argument("catalog_json", help="Public corpus catalog JSON path.")
    parser.add_argument("--json-out", default="", help="Write corpus manifest JSON to this path.")
    args = parser.parse_args(argv)
    try:
        catalog = load_public_corpus_catalog(args.catalog_json)
        manifest = corpus_manifest_from_public_catalog(catalog)
    except (OSError, ValueError) as exc:
        print("PseudoForge corpus catalog failed: %s" % exc, file=sys.stderr)
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

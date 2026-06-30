from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.claim_gap import render_world_class_gap_markdown, world_class_gap_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report remaining gaps to the world-class general claim gate.")
    parser.add_argument("benchmark_report", help="Benchmark report JSON path.")
    parser.add_argument("--json-out", default="", help="Write claim gap JSON to this path.")
    parser.add_argument("--markdown-out", default="", help="Write claim gap Markdown to this path.")
    args = parser.parse_args(argv)
    try:
        report = _load_json_object(args.benchmark_report)
        gap = world_class_gap_report(report)
    except (OSError, ValueError) as exc:
        print("PseudoForge claim gap failed: %s" % exc, file=sys.stderr)
        return 2
    json_text = json.dumps(gap, indent=2, sort_keys=True)
    if args.json_out:
        target = Path(args.json_out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json_text + "\n", encoding="utf-8")
    if args.markdown_out:
        target = Path(args.markdown_out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_world_class_gap_markdown(gap), encoding="utf-8")
    if not args.json_out and not args.markdown_out:
        print(json_text)
    return 0


def _load_json_object(path: str | Path) -> dict[str, object]:
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("benchmark report file not found: %s" % target) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid benchmark report JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("benchmark report root must be an object")
    return payload


if __name__ == "__main__":
    raise SystemExit(main())

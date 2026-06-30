from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.agentic_benchmark import load_agentic_task_suite, run_agentic_benchmark


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic agentic reverse-engineering benchmark tasks.")
    parser.add_argument("task_suite", help="Agentic task suite JSON path.")
    parser.add_argument("benchmark_report", help="PseudoForge benchmark report JSON path.")
    parser.add_argument("--json-out", default="", help="Write agentic benchmark report JSON.")
    args = parser.parse_args(argv)
    try:
        task_suite = load_agentic_task_suite(args.task_suite)
        benchmark_report = _json_object(Path(args.benchmark_report), "benchmark report")
        report = run_agentic_benchmark(task_suite, benchmark_report)
    except (OSError, ValueError) as exc:
        print("PseudoForge agentic benchmark failed: %s" % exc, file=sys.stderr)
        return 2
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.json_out:
        target = Path(args.json_out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0 if int(report.get("failed", 0) or 0) == 0 else 1


def _json_object(path: Path, description: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("%s file not found: %s" % (description, path)) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid %s JSON at line %d column %d: %s"
            % (description, exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("%s root must be an object" % description)
    return payload


if __name__ == "__main__":
    raise SystemExit(main())

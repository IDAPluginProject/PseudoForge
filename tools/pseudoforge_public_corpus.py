from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.public_corpus import (
    bootstrap_public_corpus,
    corpus_manifest_from_public_bootstrap_report,
    load_public_corpus_bootstrap_report,
    load_public_corpus_plan,
    summarize_public_corpus_report,
    write_public_corpus_outputs,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and validate PseudoForge public corpus workspaces.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate-plan", help="Validate a public corpus plan JSON file.")
    validate_parser.add_argument("plan_json", help="Public corpus plan JSON path.")

    bootstrap_parser = subparsers.add_parser("bootstrap", help="Create a local public corpus workspace.")
    bootstrap_parser.add_argument("plan_json", help="Public corpus plan JSON path.")
    bootstrap_parser.add_argument("--out-dir", required=True, help="Output workspace directory.")
    bootstrap_parser.add_argument("--no-fetch", action="store_true", help="Do not clone or fetch public repositories.")
    bootstrap_parser.add_argument("--build", action="store_true", help="Run enabled build recipes.")
    bootstrap_parser.add_argument("--candidate-limit", type=int, default=200, help="Maximum function candidates per project.")
    bootstrap_parser.add_argument("--timeout-seconds", type=int, default=900, help="Per-command timeout.")

    summarize_parser = subparsers.add_parser("summarize", help="Summarize a bootstrap report.")
    summarize_parser.add_argument("report_json", help="public-corpus-bootstrap-report.json path.")
    summarize_parser.add_argument("--manifest-out", default="", help="Optional manifest output path.")

    args = parser.parse_args(argv)
    try:
        if args.command == "validate-plan":
            plan = load_public_corpus_plan(args.plan_json)
            print(
                json.dumps(
                    {
                        "schema": "pseudoforge_public_corpus_plan_validation_v1",
                        "status": "passed",
                        "project_count": len(plan.get("projects", []) or []),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "bootstrap":
            plan = load_public_corpus_plan(args.plan_json)
            report = bootstrap_public_corpus(
                plan,
                args.out_dir,
                fetch=not args.no_fetch,
                build=bool(args.build),
                candidate_limit=max(1, int(args.candidate_limit)),
                timeout_seconds=max(1, int(args.timeout_seconds)),
            )
            paths = write_public_corpus_outputs(report, args.out_dir)
            print(json.dumps({key: str(value) for key, value in paths.items()}, indent=2, sort_keys=True))
            return 0
        if args.command == "summarize":
            report = load_public_corpus_bootstrap_report(args.report_json)
            manifest = corpus_manifest_from_public_bootstrap_report(report)
            if args.manifest_out:
                target = Path(args.manifest_out)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps(summarize_public_corpus_report(report, manifest), indent=2, sort_keys=True))
            return 0
    except (OSError, ValueError) as exc:
        print("PseudoForge public corpus failed: %s" % exc, file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

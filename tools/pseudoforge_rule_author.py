from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.deterministic.authoring import (
    SCAFFOLD_KINDS,
    rule_context_fact_payload,
    scaffold_rule_pack,
)
from ida_pseudoforge.core.deterministic.context import build_rule_context
from ida_pseudoforge.core.deterministic.engine import RuleEngine
from ida_pseudoforge.core.deterministic.loader import load_rule_pack_file
from ida_pseudoforge.core.deterministic.schema import RuleReport
from ida_pseudoforge.core.deterministic.validators import validate_rule_pack_file
from ida_pseudoforge.core.rule_diagnostics import summarize_rule_report
from ida_pseudoforge.core.kernel_api import kernel_function_metadata


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "validate":
        return _validate_command(args)
    if args.command == "facts":
        return _facts_command(args)
    if args.command == "run":
        return _run_command(args)
    if args.command == "scaffold":
        return _scaffold_command(args)
    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Author and debug PseudoForge deterministic rule packs.")
    subparsers = parser.add_subparsers(dest="command")

    validate = subparsers.add_parser("validate", help="Validate rule pack files or directories.")
    validate.add_argument("paths", nargs="+", help="Rule JSON file or directory path.")

    facts = subparsers.add_parser("facts", help="Dump RuleContext facts for one pseudocode input.")
    facts.add_argument("input", help="Path to a pseudocode text file.")
    facts.add_argument("--name", default="", help="Optional function name override.")

    run = subparsers.add_parser("run", help="Run rule packs against one pseudocode input.")
    run.add_argument("input", help="Path to a pseudocode text file.")
    run.add_argument("--name", default="", help="Optional function name override.")
    run.add_argument(
        "--rules",
        "--rules-dir",
        action="append",
        default=[],
        help="Rule JSON file or rule directory. Can be passed more than once.",
    )
    run.add_argument(
        "--phase",
        action="append",
        default=[],
        help="Limit evaluation to one phase. Can be passed more than once.",
    )
    run.add_argument("--explain", action="store_true", help="Include opt-in missed rule reasons.")

    scaffold = subparsers.add_parser("scaffold", help="Print a starter rule pack JSON.")
    scaffold.add_argument("kind", choices=sorted(SCAFFOLD_KINDS))
    scaffold.add_argument("--pack-id", default="project.rules")
    scaffold.add_argument("--rule-id", default="")
    scaffold.add_argument("--out", default="", help="Optional output JSON file path.")
    return parser


def _validate_command(args: argparse.Namespace) -> int:
    files = _collect_rule_files(args.paths)
    if not files:
        print("No rule files found.")
        return 1
    failed = 0
    for path in files:
        errors = validate_rule_pack_file(path)
        if errors:
            failed += 1
            print("%s: FAIL" % path)
            for error in errors:
                print("  - %s" % error)
        else:
            print("%s: OK" % path)
    if failed:
        print("Validated %d rule file(s), %d failed." % (len(files), failed))
        return 1
    print("Validated %d rule file(s), all OK." % len(files))
    return 0


def _facts_command(args: argparse.Namespace) -> int:
    capture = _capture_input(args.input, args.name)
    context = build_rule_context(capture, profile_function_lookup=kernel_function_metadata)
    print(json.dumps(rule_context_fact_payload(context), indent=2, ensure_ascii=True))
    return 0


def _run_command(args: argparse.Namespace) -> int:
    report = RuleReport()
    packs = _load_rule_inputs(args.rules, report)
    capture = _capture_input(args.input, args.name)
    context = build_rule_context(capture, profile_function_lookup=kernel_function_metadata)
    phases = set(args.phase) if args.phase else None
    result = RuleEngine(packs).run(context, phases=phases, report=report, explain_misses=args.explain)
    payload = {
        "function": capture.name,
        "rule_packs": len(packs),
        "emissions": [item.to_dict() for item in result.emissions],
        "rule_report": result.report.to_dict(),
        "rule_diagnostics": summarize_rule_report(result.report.to_dict()),
    }
    print(json.dumps(payload, indent=2, ensure_ascii=True))
    return 0


def _scaffold_command(args: argparse.Namespace) -> int:
    payload = scaffold_rule_pack(args.kind, pack_id=args.pack_id, rule_id=args.rule_id)
    text = json.dumps(payload, indent=2, ensure_ascii=True)
    if args.out:
        output_path = Path(args.out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text + "\n", encoding="utf-8")
        print(str(output_path))
        return 0
    print(text)
    return 0


def _capture_input(path: str, name: str):
    input_path = Path(path)
    pseudocode = input_path.read_text(encoding="utf-8-sig")
    return capture_from_pseudocode(pseudocode, name=name, source_path=str(input_path))


def _load_rule_inputs(paths: list[str], report: RuleReport) -> list:
    packs = []
    for source_order, item in enumerate(paths):
        path = Path(item)
        if path.is_dir():
            for file_path in sorted(path.glob("*.json")):
                pack = load_rule_pack_file(file_path, report=report, source_order=source_order)
                if pack is not None:
                    packs.append(pack)
        else:
            pack = load_rule_pack_file(path, report=report, source_order=source_order)
            if pack is not None:
                packs.append(pack)
    return packs


def _collect_rule_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.exists():
            files.append(path)
        else:
            files.append(path)
    return files


if __name__ == "__main__":
    raise SystemExit(main())

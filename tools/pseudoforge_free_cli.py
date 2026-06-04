from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.free.service import (
    FreeAnalysisError,
    FreeAnalysisOptions,
    PROGRESS_FIELD,
    analyze_file,
    assert_no_ida_modules_loaded,
    build_run_payload,
    loaded_ida_modules,
    load_free_analysis_deps,
    parse_case_value,
    write_run_manifest,
)
from ida_pseudoforge.models.provider_registry import PROVIDER_OPENAI_COMPATIBLE, PROVIDER_ORDER
from ida_pseudoforge.version import plugin_title
from tools.pseudoforge_free_console import FreeCliConsole, ascii_text, emit_result


_PROVIDER_OPENAI_COMPATIBLE = PROVIDER_OPENAI_COMPATIBLE
_PROVIDER_ORDER = list(PROVIDER_ORDER)


class FreeCliError(FreeAnalysisError):
    pass


def main(argv: list[str] | None = None) -> int:
    try:
        parser = _build_parser()
        args = parser.parse_args(argv)
        if args.name and len(args.inputs) != 1:
            parser.error("--name can only be used with a single input file")

        assert_no_ida_modules_loaded("startup")
        deps = _load_deps()
        results: list[dict[str, object]] = []
        failures: list[dict[str, str]] = []
        output_root = Path(args.out)
        console = FreeCliConsole(args.format, not args.no_progress)
        console.banner(args, output_root)
        multiple_inputs = len(args.inputs) > 1
        options = _options_from_args(args)
        progress = _console_progress(console)
        for index, raw_input in enumerate(args.inputs, start=1):
            input_path = Path(raw_input)
            console.input_start(index, len(args.inputs), input_path)
            try:
                result = analyze_file(
                    input_path=input_path,
                    output_root=output_root,
                    options=options,
                    deps=deps,
                    multiple_inputs=multiple_inputs,
                    progress=progress,
                )
                results.append(result.payload)
            except FreeAnalysisError as exc:
                console.step("Failed", ascii_text(str(exc)))
                failures.append({"input": str(input_path), "error": ascii_text(str(exc))})

        payload = build_run_payload(results, failures)
        console.step("Write manifest", str(output_root / "pseudoforge-free-report.json"))
        write_run_manifest(output_root, payload)
        emit_result(payload, args.format)
        return 1 if failures else 0
    except KeyboardInterrupt:
        print("PseudoForge IDA Free CLI interrupted.", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print("PseudoForge IDA Free CLI failed: %s" % ascii_text(str(exc)), file=sys.stderr)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run PseudoForge on pseudocode text copied or saved from IDA Free cloud decompiler output. "
            "No IDA APIs are used and no IDB is modified."
        )
    )
    parser.add_argument("--version", action="version", version=plugin_title())
    parser.add_argument("inputs", nargs="+", help="One or more pseudocode text files. Use one function per file.")
    parser.add_argument("--name", default="", help="Optional function name override for a single input.")
    parser.add_argument("--out", default="pseudoforge_free_out", help="Output directory.")
    parser.add_argument(
        "--profile-dir",
        default="",
        help="Optional profile directory for target-build-specific profile sets.",
    )
    parser.add_argument("--project-root", default="", help="Project root containing an optional pseudoforge_rules directory.")
    parser.add_argument("--no-progress", action="store_true", help="Suppress incremental progress messages.")
    parser.add_argument(
        "--rules",
        "--rules-dir",
        action="append",
        default=[],
        help="Additional deterministic rule directory. Can be passed more than once.",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Console output format.")
    parser.set_defaults(llm=False)
    parser.add_argument("--llm", "--llm-renames", dest="llm", action="store_true", help="Use offline LLM rename assist.")
    parser.add_argument("--no-llm", dest="llm", action="store_false", help="Disable offline LLM rename assist.")
    parser.add_argument("--llm-provider", choices=_PROVIDER_ORDER, default=_PROVIDER_OPENAI_COMPATIBLE)
    parser.add_argument("--llm-api-key", default="")
    parser.add_argument("--llm-base-url", default="")
    parser.add_argument("--llm-model", default="")
    parser.add_argument("--llm-command", default="")
    parser.add_argument("--llm-timeout", type=int, default=60)
    parser.add_argument(
        "--buffer-contract-case",
        action="append",
        default=[],
        type=_case_value_arg,
        help="Recover deep buffer contracts only for this case value. Accepts hex or decimal; can be repeated.",
    )
    parser.add_argument(
        "--buffer-contract-helper-depth",
        type=int,
        default=2,
        help="Maximum helper/subhandler depth for buffer contract recovery.",
    )
    return parser


def _load_deps():
    return load_free_analysis_deps()


def _options_from_args(args: argparse.Namespace) -> FreeAnalysisOptions:
    return FreeAnalysisOptions(
        name=args.name,
        profile_dir=args.profile_dir,
        project_root=args.project_root,
        rule_dirs=[str(item) for item in args.rules],
        llm_enabled=bool(args.llm),
        llm_provider=args.llm_provider,
        llm_api_key=args.llm_api_key,
        llm_base_url=args.llm_base_url,
        llm_model=args.llm_model,
        llm_command=args.llm_command,
        llm_timeout=args.llm_timeout,
        buffer_contract_case_values=list(args.buffer_contract_case),
        buffer_contract_helper_depth=args.buffer_contract_helper_depth,
    )


def _console_progress(console: FreeCliConsole):
    def handle(event):
        if event.kind == PROGRESS_FIELD:
            console.field(event.title, event.detail)
        else:
            console.step(event.title, event.detail)

    return handle


def _case_value_arg(value: str) -> int:
    try:
        return parse_case_value(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.export_bundle import write_export_bundle
from ida_pseudoforge.core.ioctl import parse_c_integer_literal
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.projection_policy import projection_policy_choices
from ida_pseudoforge.core.render_warnings import export_warnings
from ida_pseudoforge.profiles.loader import configure_profile_dir
from ida_pseudoforge.config import LlmConfig
from ida_pseudoforge.models.provider_factory import build_rename_provider
from ida_pseudoforge.models.provider_registry import (
    PROVIDER_OPENAI_COMPATIBLE,
    PROVIDER_ORDER,
)
from ida_pseudoforge.version import VERSION, plugin_title


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a PseudoForge cleaned pseudocode bundle.")
    parser.add_argument("--version", action="version", version=plugin_title())
    parser.add_argument("input", help="Path to an IDA/Hex-Rays pseudocode text file.")
    parser.add_argument("--name", default="", help="Optional function name override.")
    parser.add_argument("--out", default="pseudoforge_out", help="Output directory.")
    parser.add_argument(
        "--profile-dir",
        default="",
        help="Optional profile directory for target-build-specific profile sets.",
    )
    parser.add_argument(
        "--llm-renames",
        action="store_true",
        help="Use a configured LLM provider for additional rename suggestions.",
    )
    parser.add_argument("--llm-provider", choices=PROVIDER_ORDER, default=PROVIDER_OPENAI_COMPATIBLE)
    parser.add_argument("--llm-api-key", default="")
    parser.add_argument("--llm-base-url", default="")
    parser.add_argument("--llm-model", default="")
    parser.add_argument("--llm-command", default="")
    parser.add_argument("--llm-timeout", type=int, default=60)
    parser.add_argument(
        "--rules-dir",
        action="append",
        default=[],
        help="Additional deterministic rule directory. Can be passed more than once.",
    )
    parser.add_argument(
        "--rule-report",
        default="",
        help="Optional rule report JSON file or directory.",
    )
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
    parser.add_argument(
        "--apply-validated-layout-rewrites",
        action="store_true",
        help="Rewrite canonical cleaned output with validated layout field aliases.",
    )
    parser.add_argument(
        "--projection-policy",
        choices=projection_policy_choices(),
        default="review_only",
        help="Render-only aggregate projection policy for this export.",
    )
    args = parser.parse_args(argv)
    configure_profile_dir(args.profile_dir)

    input_path = Path(args.input)
    pseudocode = input_path.read_text(encoding="utf-8")
    capture = capture_from_pseudocode(
        pseudocode,
        name=args.name,
        source_path=str(input_path),
    )
    provider = _build_cli_provider(args) if args.llm_renames else None
    plan = build_clean_plan(
        capture,
        rename_provider=provider,
        rule_dirs=args.rules_dir,
        buffer_contract_case_values=args.buffer_contract_case or None,
        buffer_contract_helper_depth=max(0, args.buffer_contract_helper_depth),
        projection_policy=args.projection_policy,
    )
    paths = write_export_bundle(
        args.out,
        capture,
        plan,
        entrypoint="offline_cli",
        apply_validated_layout_rewrites=args.apply_validated_layout_rewrites,
    )
    warnings = export_warnings(plan)
    if args.rule_report:
        report_path = _write_rule_report(args.rule_report, capture, plan.rule_report)
        paths["rule_report"] = str(report_path)

    print("PseudoForge export complete")
    print("Version: %s" % VERSION)
    print(f"Function: {capture.name}")
    print(f"Renames: {len(plan.renames)}")
    print(f"Flow rewrites: {len(plan.flow_rewrites)}")
    if args.buffer_contract_case:
        print("Buffer contract case filter: %s" % ", ".join("0x%X" % value for value in args.buffer_contract_case))
    if args.apply_validated_layout_rewrites:
        print("Validated layout rewrites: enabled")
    print("Projection policy: %s" % args.projection_policy)
    if warnings:
        print(f"Warnings: {len(warnings)}")
    for kind, path in paths.items():
        print(f"{kind}: {path}")
    return 0


def _build_cli_provider(args: argparse.Namespace):
    config = LlmConfig(
        enabled=True,
        provider=args.llm_provider,
        base_url=args.llm_base_url,
        model=args.llm_model,
        timeout_seconds=args.llm_timeout,
        command_template=args.llm_command,
    )
    return build_rename_provider(config, api_key=args.llm_api_key)


def _write_rule_report(target: str, capture, report: dict) -> Path:
    path = Path(target)
    if path.suffix.lower() == ".json":
        output_path = path
    else:
        output_path = path / ("%s.rule-report.json" % _safe_file_stem(capture.name or "function"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report or {}, indent=2, ensure_ascii=True), encoding="utf-8")
    return output_path


def _case_value_arg(value: str) -> int:
    parsed = parse_c_integer_literal(value)
    if parsed is None:
        raise argparse.ArgumentTypeError("case value must be a C integer literal")
    return parsed


def _safe_file_stem(name: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in name)
    return cleaned.strip("._") or "function"


if __name__ == "__main__":
    raise SystemExit(main())

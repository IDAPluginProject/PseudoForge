from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import write_export_bundle
from ida_pseudoforge.profiles.loader import profile_load_warnings
from ida_pseudoforge.config import LlmConfig
from ida_pseudoforge.models.provider_factory import build_rename_provider
from ida_pseudoforge.models.provider_registry import (
    PROVIDER_OPENAI_COMPATIBLE,
    PROVIDER_ORDER,
    provider_defaults,
)
from ida_pseudoforge.version import VERSION, plugin_title


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a PseudoForge cleaned pseudocode bundle.")
    parser.add_argument("--version", action="version", version=plugin_title())
    parser.add_argument("input", help="Path to an IDA/Hex-Rays pseudocode text file.")
    parser.add_argument("--name", default="", help="Optional function name override.")
    parser.add_argument("--out", default="pseudoforge_out", help="Output directory.")
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
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    pseudocode = input_path.read_text(encoding="utf-8")
    capture = capture_from_pseudocode(
        pseudocode,
        name=args.name,
        source_path=str(input_path),
    )
    provider = _build_cli_provider(args) if args.llm_renames else None
    plan = build_clean_plan(capture, rename_provider=provider, rule_dirs=args.rules_dir)
    paths = write_export_bundle(args.out, capture, plan)
    warnings = _combined_warnings(plan.warnings, profile_load_warnings())
    if args.rule_report:
        report_path = _write_rule_report(args.rule_report, capture, plan.rule_report)
        paths["rule_report"] = str(report_path)

    print("PseudoForge export complete")
    print("Version: %s" % VERSION)
    print(f"Function: {capture.name}")
    print(f"Renames: {len(plan.renames)}")
    print(f"Flow rewrites: {len(plan.flow_rewrites)}")
    if warnings:
        print(f"Warnings: {len(warnings)}")
    for kind, path in paths.items():
        print(f"{kind}: {path}")
    return 0


def _build_cli_provider(args: argparse.Namespace):
    defaults = provider_defaults(args.llm_provider)
    config = LlmConfig(
        enabled=True,
        provider=args.llm_provider,
        base_url=args.llm_base_url or defaults.base_url,
        model=args.llm_model or defaults.model,
        timeout_seconds=args.llm_timeout,
        command_template=args.llm_command or defaults.command_template,
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


def _safe_file_stem(name: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in name)
    return cleaned.strip("._") or "function"


def _combined_warnings(primary: list[object], secondary: list[str]) -> list[str]:
    result = []
    seen = set()
    for warning in list(primary) + list(secondary):
        text = str(warning)
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


if __name__ == "__main__":
    raise SystemExit(main())

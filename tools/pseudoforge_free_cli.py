from __future__ import annotations

import argparse
import difflib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.pseudoforge_free_console import (
    FreeCliConsole,
    ascii_text,
    emit_result,
    format_plan_mode,
    format_rule_dirs,
)
from ida_pseudoforge.core.rule_diagnostics import summarize_rule_report
from ida_pseudoforge.version import VERSION, plugin_title

IDA_ONLY_MODULES = {
    "idaapi",
    "ida_auto",
    "ida_bytes",
    "ida_funcs",
    "ida_hexrays",
    "ida_ida",
    "ida_kernwin",
    "ida_name",
    "ida_nalt",
    "ida_typeinf",
    "idautils",
    "idc",
}

_PROVIDER_OPENAI_COMPATIBLE = "openai_compatible"
_PROVIDER_ORDER = [
    _PROVIDER_OPENAI_COMPATIBLE,
    "openrouter",
    "chatgpt_oauth_via_codex_cli",
    "codex_cli",
    "claude_login_via_claude_cli",
    "claude_cli",
    "deepseek_api",
]


@dataclass(slots=True)
class _Deps:
    OfflinePseudocodeError: Any
    normalize_copied_pseudocode: Any
    capture_from_pseudocode: Any
    build_clean_plan: Any
    write_export_bundle: Any
    render_cleaned_pseudocode: Any
    active_profile_manifests: Any
    active_profile_names: Any
    active_profile_root: Any
    profile_load_warnings: Any
    configure_profile_dir: Any
    LlmConfig: Any
    build_rename_provider: Any
    PROVIDER_OPENAI_COMPATIBLE: str
    PROVIDER_ORDER: list[str]
    provider_defaults: Any


class FreeCliError(RuntimeError):
    pass


def main(argv: list[str] | None = None) -> int:
    try:
        parser = _build_parser()
        args = parser.parse_args(argv)
        if args.name and len(args.inputs) != 1:
            parser.error("--name can only be used with a single input file")

        _assert_no_ida_modules_loaded("startup")
        deps = _load_deps()
        deps.configure_profile_dir(args.profile_dir)
        results: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        output_root = Path(args.out)
        console = FreeCliConsole(args.format, not args.no_progress)
        console.banner(args, output_root)
        multiple_inputs = len(args.inputs) > 1
        for index, raw_input in enumerate(args.inputs, start=1):
            input_path = Path(raw_input)
            console.input_start(index, len(args.inputs), input_path)
            try:
                results.append(_process_input(input_path, output_root, args, deps, multiple_inputs, console))
            except FreeCliError as exc:
                console.step("Failed", ascii_text(str(exc)))
                failures.append({"input": str(input_path), "error": ascii_text(str(exc))})

        payload = {
            "mode": "ida_free_offline",
            "pseudoforge_version": VERSION,
            "ida_apis_used": False,
            "idb_modified": False,
            "interactive_plugin_supported": False,
            "results": results,
            "failures": failures,
        }
        console.step("Write manifest", str(output_root / "pseudoforge-free-report.json"))
        _write_manifest(output_root, payload)
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
    return parser


def _load_deps() -> _Deps:
    try:
        from ida_pseudoforge.config import LlmConfig
        from ida_pseudoforge.core.capture import capture_from_pseudocode
        from ida_pseudoforge.core.export_bundle import write_export_bundle
        from ida_pseudoforge.core.lvar_analysis import build_clean_plan
        from ida_pseudoforge.core.offline_input import OfflinePseudocodeError, normalize_copied_pseudocode
        from ida_pseudoforge.core.render import render_cleaned_pseudocode
        from ida_pseudoforge.profiles.loader import (
            active_profile_manifests,
            active_profile_names,
            active_profile_root,
            configure_profile_dir,
            profile_load_warnings,
        )
        from ida_pseudoforge.models.provider_factory import build_rename_provider
        from ida_pseudoforge.models.provider_registry import (
            PROVIDER_OPENAI_COMPATIBLE,
            PROVIDER_ORDER,
            provider_defaults,
        )
    except ModuleNotFoundError as exc:
        if (exc.name or "") in IDA_ONLY_MODULES:
            raise RuntimeError(
                "IDA Free offline CLI cannot import IDA-only module %s. "
                "Run this command with a normal Python interpreter outside IDA." % exc.name
            ) from exc
        raise

    _assert_no_ida_modules_loaded("dependency import")
    return _Deps(
        OfflinePseudocodeError=OfflinePseudocodeError,
        normalize_copied_pseudocode=normalize_copied_pseudocode,
        capture_from_pseudocode=capture_from_pseudocode,
        build_clean_plan=build_clean_plan,
        write_export_bundle=write_export_bundle,
        render_cleaned_pseudocode=render_cleaned_pseudocode,
        active_profile_manifests=active_profile_manifests,
        active_profile_names=active_profile_names,
        active_profile_root=active_profile_root,
        profile_load_warnings=profile_load_warnings,
        configure_profile_dir=configure_profile_dir,
        LlmConfig=LlmConfig,
        build_rename_provider=build_rename_provider,
        PROVIDER_OPENAI_COMPATIBLE=PROVIDER_OPENAI_COMPATIBLE,
        PROVIDER_ORDER=list(PROVIDER_ORDER),
        provider_defaults=provider_defaults,
    )


def _process_input(
    input_path: Path,
    output_root: Path,
    args: argparse.Namespace,
    deps: _Deps,
    multiple_inputs: bool,
    console: FreeCliConsole,
) -> dict[str, Any]:
    console.step("Read input", str(input_path))
    try:
        source_text = input_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise FreeCliError("Input file could not be read: %s" % exc) from exc
    console.field("Input bytes", len(source_text.encode("utf-8", errors="replace")))

    console.step("Normalize copied text")
    try:
        pseudocode = deps.normalize_copied_pseudocode(source_text)
    except deps.OfflinePseudocodeError as exc:
        raise FreeCliError(str(exc)) from exc
    console.field("Pseudocode lines", len(pseudocode.splitlines()))

    output_dir = output_root / _safe_file_stem(input_path.stem) if multiple_inputs else output_root
    console.step("Capture function")
    capture = deps.capture_from_pseudocode(
        pseudocode,
        name=args.name,
        source_path=str(input_path),
    )
    if args.project_root:
        capture.source_path = str(Path(args.project_root))
    console.field("Function", capture.name)

    rule_dirs = _rule_dirs(args)
    console.step("Load rules", format_rule_dirs(rule_dirs))
    console.step("Build clean plan", format_plan_mode(args.llm, args.llm_provider, args.llm_timeout))
    plan, llm_status = _build_plan(capture, args, deps, rule_dirs)
    console.field("Rename candidates", len(plan.renames))
    console.field("Flow rewrites", len(plan.flow_rewrites))
    console.field("Warnings", len(plan.warnings))
    console.field("LLM status", llm_status)

    console.step("Write artifacts", str(output_dir))
    try:
        artifact_paths = deps.write_export_bundle(
            output_dir,
            capture,
            plan,
            entrypoint="ida_free_offline",
            summary_suffix="ida-free-summary",
        )
        warnings = _combined_warnings(plan.warnings, deps.profile_load_warnings())
        if len(warnings) > len(plan.warnings):
            console.field("Profile warnings", len(warnings) - len(plan.warnings))
        artifact_paths.update(_write_free_artifacts(output_dir, input_path, capture, plan, pseudocode, warnings, deps))
    except OSError as exc:
        raise FreeCliError("Output artifacts could not be written: %s" % exc) from exc

    rule_diagnostics = summarize_rule_report(plan.rule_report)
    result = {
        "input": str(input_path),
        "function": capture.name,
        "mode": "ida_free_offline",
        "pseudoforge_version": VERSION,
        "ida_apis_used": False,
        "idb_modified": False,
        "llm_status": llm_status,
        "rule_diagnostics": rule_diagnostics,
        "rule_load_errors": list(rule_diagnostics["load_error_details"]),
        "rule_validation_errors": list(rule_diagnostics["validation_error_details"]),
        "warnings": warnings,
        "profile_root": deps.active_profile_root(),
        "active_profiles": deps.active_profile_names(),
        "profile_manifests": deps.active_profile_manifests(),
        "artifacts": artifact_paths,
    }
    summary_path = _write_summary(output_dir, capture, result)
    result["artifacts"]["summary"] = str(summary_path)
    console.step("Input complete", "%d artifact(s)" % len(result["artifacts"]))
    return result


def _rule_dirs(args: argparse.Namespace) -> list[str]:
    dirs = [str(item) for item in args.rules]
    if args.project_root:
        dirs.append(str(Path(args.project_root) / "pseudoforge_rules"))
    return dirs


def _build_plan(capture: Any, args: argparse.Namespace, deps: _Deps, rule_dirs: list[str]) -> tuple[Any, str]:
    if not args.llm:
        return deps.build_clean_plan(capture, rule_dirs=rule_dirs), "disabled"

    try:
        provider = _build_cli_provider(args, deps)
        return deps.build_clean_plan(capture, rename_provider=provider, rule_dirs=rule_dirs), "ok"
    except Exception as exc:
        plan = deps.build_clean_plan(capture, rule_dirs=rule_dirs)
        plan.warnings.insert(0, "LLM rename assist failed; deterministic fallback used: %s" % ascii_text(str(exc)))
        return plan, "failed_fallback"


def _build_cli_provider(args: argparse.Namespace, deps: _Deps) -> Any:
    defaults = deps.provider_defaults(args.llm_provider)
    config = deps.LlmConfig(
        enabled=True,
        provider=args.llm_provider,
        base_url=args.llm_base_url or defaults.base_url,
        model=args.llm_model or defaults.model,
        timeout_seconds=args.llm_timeout,
        command_template=args.llm_command or defaults.command_template,
    )
    return deps.build_rename_provider(config, api_key=args.llm_api_key)


def _write_free_artifacts(
    output_dir: Path,
    input_path: Path,
    capture: Any,
    plan: Any,
    pseudocode: str,
    warnings: list[str],
    deps: _Deps,
) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = _safe_file_stem(capture.name or input_path.stem or "function")
    raw_path = output_dir / ("%s.raw.cpp" % safe_name)
    warnings_path = output_dir / ("%s.warnings.json" % safe_name)
    diff_path = output_dir / ("%s.raw-vs-cleaned.diff" % safe_name)

    cleaned_text = deps.render_cleaned_pseudocode(capture, plan)
    raw_text = pseudocode.rstrip() + "\n"
    raw_path.write_text(raw_text, encoding="utf-8")
    warnings_path.write_text(
        json.dumps(warnings, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    diff_text = "".join(
        difflib.unified_diff(
            raw_text.splitlines(keepends=True),
            cleaned_text.splitlines(keepends=True),
            fromfile="raw/%s.cpp" % safe_name,
            tofile="cleaned/%s.cpp" % safe_name,
            lineterm="",
        )
    )
    diff_path.write_text(diff_text, encoding="utf-8")
    return {
        "raw_pseudocode": str(raw_path),
        "warnings": str(warnings_path),
        "raw_vs_cleaned_diff": str(diff_path),
    }


def _write_summary(output_dir: Path, capture: Any, result: dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / ("%s.ida-free-summary.json" % _safe_file_stem(capture.name or "function"))
    path.write_text(json.dumps(result, indent=2, ensure_ascii=True), encoding="utf-8")
    return path


def _write_manifest(output_root: Path, payload: dict[str, Any]) -> None:
    try:
        output_root.mkdir(parents=True, exist_ok=True)
        (output_root / "pseudoforge-free-report.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )
    except OSError as exc:
        raise RuntimeError("Output directory could not be written: %s" % exc) from exc


def loaded_ida_modules() -> list[str]:
    return sorted(name for name in sys.modules if name.split(".", 1)[0] in IDA_ONLY_MODULES)


def _assert_no_ida_modules_loaded(stage: str) -> None:
    loaded = loaded_ida_modules()
    if loaded:
        raise RuntimeError(
            "IDA Free offline CLI must not use IDA-only modules during %s: %s"
            % (stage, ", ".join(loaded))
        )


def _safe_file_stem(name: str) -> str:
    cleaned = "".join(
        char if char.isascii() and (char.isalnum() or char in "._-") else "_"
        for char in str(name or "")
    )
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

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TextIO

from ida_pseudoforge.version import VERSION


ARTIFACT_ORDER = (
    "cleaned_pseudocode",
    "switch_outline",
    "rename_map",
    "flow_report",
    "buffer_contract_report",
    "buffer_contracts",
    "buffer_structs",
    "rule_report",
    "raw_pseudocode",
    "raw_vs_cleaned_diff",
    "warnings",
    "warning_diagnostics",
    "summary",
)


class FreeCliConsole:
    def __init__(self, output_format: str, progress: bool):
        self._stream: TextIO = sys.stderr if output_format == "json" else sys.stdout
        self._progress = progress

    def banner(self, args: Any, output_root: Path) -> None:
        if not self._progress:
            return
        self._line("PseudoForge IDA Free CLI")
        self._line("========================")
        self.field("Version", VERSION)
        self.field("Mode", "offline preview/export")
        self.field("IDA APIs used", "no")
        self.field("IDB modified", "no")
        self.field("Inputs", str(len(args.inputs)))
        self.field("Output", str(output_root))
        self.field("Console format", args.format)
        self._line("")

    def input_start(self, index: int, total: int, input_path: Path) -> None:
        self.step("[%d/%d] Input" % (index, total), str(input_path))

    def step(self, title: str, detail: str = "") -> None:
        if not self._progress:
            return
        if detail:
            self._line("* %-22s %s" % (title + ":", detail))
        else:
            self._line("* %s" % title)

    def field(self, label: str, value: object) -> None:
        if not self._progress:
            return
        self._line("  %-18s %s" % (label + ":", ascii_text(str(value))))

    def _line(self, text: str) -> None:
        print(ascii_text(text), file=self._stream, flush=True)


def emit_result(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, indent=2, ensure_ascii=True))
        return

    status = payload_status(payload)
    if status == "complete":
        print("PseudoForge IDA Free offline export complete")
    elif status == "partial":
        print("PseudoForge IDA Free offline export completed with failures")
    else:
        print("PseudoForge IDA Free offline export failed")
    print("============================================")
    print("Status: %s" % status)
    print("Version: %s" % payload.get("pseudoforge_version", VERSION))
    print("Mode: ida_free_offline")
    print("IDA APIs used: no")
    print("IDB modified: no")
    print("Results: %d" % len(payload["results"]))
    print("Failures: %d" % len(payload["failures"]))
    for result in payload["results"]:
        print("")
        print("Function")
        print("--------")
        print_field("Name", result.get("function", ""))
        print_field("Input", result.get("input", ""))
        print_field("LLM status", result.get("llm_status", ""))
        print_field("Warnings", len(result.get("warnings", [])))
        rule_diagnostics = result.get("rule_diagnostics") or {}
        if rule_diagnostics:
            print_field("Rule matches", rule_diagnostics.get("matched_rules", 0))
            rewrite_emissions = rule_diagnostics.get("rewrite_emissions") or {}
            rewrite_status = rewrite_emissions.get("by_status") or {}
            print_field("Rule rewrites", rewrite_emissions.get("total", 0))
            if rewrite_status.get("rejected"):
                print_field("Rule rewrite rejects", rewrite_status.get("rejected", 0))
        if result.get("rule_load_errors"):
            print_field("Rule load errors", len(result.get("rule_load_errors", [])))
        if result.get("rule_validation_errors"):
            print_field("Rule validation errors", len(result.get("rule_validation_errors", [])))
        print("")
        print("Artifacts")
        print("---------")
        for kind, path in ordered_artifacts(result.get("artifacts", {})):
            print_field(kind, path)
    for failure in payload["failures"]:
        print("Failed input: %s" % failure.get("input", ""), file=sys.stderr)
        print("Error: %s" % failure.get("error", ""), file=sys.stderr)


def payload_status(payload: dict[str, Any]) -> str:
    if not payload.get("failures"):
        return "complete"
    if payload.get("results"):
        return "partial"
    return "failed"


def print_field(label: str, value: object) -> None:
    print("  %-22s %s" % (label + ":", ascii_text(str(value))))


def ordered_artifacts(artifacts: dict[str, str]) -> list[tuple[str, str]]:
    ordered: list[tuple[str, str]] = []
    seen = set()
    for key in ARTIFACT_ORDER:
        if key in artifacts:
            ordered.append((key, artifacts[key]))
            seen.add(key)
    for key in sorted(key for key in artifacts if key not in seen):
        ordered.append((key, artifacts[key]))
    return ordered


def format_rule_dirs(rule_dirs: list[str]) -> str:
    if not rule_dirs:
        return "builtin and user-global"
    return "builtin, user-global, " + ", ".join(rule_dirs)


def format_plan_mode(llm: bool, llm_provider: str, llm_timeout: int) -> str:
    if not llm:
        return "deterministic only"
    return "deterministic plus %s LLM assist, timeout %ds" % (llm_provider, llm_timeout)


def ascii_text(text: str) -> str:
    return str(text).encode("ascii", errors="replace").decode("ascii")

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.profiles import loader as profile_loader


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    result = run_smoke(
        args.family,
        profile_dir=args.profile_dir,
        repeat=args.repeat,
        require_split=not args.allow_monolithic_fallback,
        max_cold_ms=args.max_cold_ms,
        max_repeated_ms=args.max_repeated_ms,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_text_result(result)
    return 0 if result["status"] == "ok" else 1


def run_smoke(
    family: str,
    *,
    profile_dir: str | Path = "",
    repeat: int = 100,
    require_split: bool = True,
    max_cold_ms: float = 0.0,
    max_repeated_ms: float = 0.0,
) -> dict[str, Any]:
    family_name = str(family or "").strip()
    if not family_name:
        raise ValueError("family is required")
    if repeat < 1:
        raise ValueError("repeat must be at least 1")
    profile_loader.configure_profile_dir(profile_dir)

    split_name = profile_loader.KERNEL_API_FAMILY_FILES.get(family_name, "")
    split_path = profile_loader.PROFILE_DIR / split_name if split_name else None
    split_present = bool(split_path and split_path.exists())

    profile_loader.clear_profile_caches()
    cold_start = time.perf_counter()
    data = profile_loader.load_kernel_api_family(family_name)
    cold_load_ms = _elapsed_ms(cold_start)
    cold_manifests = profile_loader.active_profile_manifests()
    cold_warnings = profile_loader.profile_load_warnings()

    repeated_start = time.perf_counter()
    for _index in range(repeat):
        profile_loader.load_kernel_api_family(family_name)
    repeated_lookup_ms = _elapsed_ms(repeated_start)
    repeated_manifests = profile_loader.active_profile_manifests()
    repeated_warnings = profile_loader.profile_load_warnings()

    active_names = profile_loader.active_profile_names()
    loaded_split = bool(split_name and split_name in active_names)
    loaded_monolithic = profile_loader.KERNEL_API_PROFILE_NAME in active_names
    failures: list[str] = []
    warnings = sorted(set(cold_warnings + repeated_warnings))

    if not isinstance(data, dict) or not data:
        failures.append("family %s loaded no entries" % family_name)
    if warnings:
        failures.append("profile loader emitted warnings")
    if require_split and split_present and not loaded_split:
        failures.append("split profile %s was not loaded" % split_name)
    if require_split and split_present and loaded_monolithic:
        failures.append("monolithic kernel_api.json was loaded despite split profile")
    if max_cold_ms > 0 and cold_load_ms > max_cold_ms:
        failures.append("cold load %.3f ms exceeded %.3f ms" % (cold_load_ms, max_cold_ms))
    if max_repeated_ms > 0 and repeated_lookup_ms > max_repeated_ms:
        failures.append("repeated lookup %.3f ms exceeded %.3f ms" % (repeated_lookup_ms, max_repeated_ms))

    return {
        "status": "failed" if failures else "ok",
        "family": family_name,
        "profile_file": split_name,
        "split_file_present": split_present,
        "entry_count": len(data) if isinstance(data, dict) else 0,
        "repeat": repeat,
        "cold_load_ms": cold_load_ms,
        "repeated_lookup_ms": repeated_lookup_ms,
        "active_profiles": active_names,
        "loaded_split_profile": loaded_split,
        "loaded_monolithic_profile": loaded_monolithic,
        "warnings": warnings,
        "failures": failures,
        "cold_manifests": cold_manifests,
        "repeated_manifests": repeated_manifests,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Smoke-check split kernel API profile cold-load and repeated lookup paths.",
    )
    parser.add_argument(
        "--family",
        default="functions",
        choices=sorted(profile_loader.KERNEL_API_FAMILY_FILES),
        help="Kernel API profile family to load.",
    )
    parser.add_argument("--repeat", type=int, default=100)
    parser.add_argument(
        "--profile-dir",
        default="",
        help="Optional profile directory for target-build-specific profile sets.",
    )
    parser.add_argument(
        "--allow-monolithic-fallback",
        action="store_true",
        help="Do not fail if kernel_api.json is loaded instead of an available split file.",
    )
    parser.add_argument(
        "--max-cold-ms",
        type=float,
        default=0.0,
        help="Optional cold-load timing ceiling. Zero disables the ceiling.",
    )
    parser.add_argument(
        "--max-repeated-ms",
        type=float,
        default=0.0,
        help="Optional repeated-lookup timing ceiling. Zero disables the ceiling.",
    )
    parser.add_argument("--json", action="store_true")
    return parser


def _elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


def _print_text_result(result: dict[str, Any]) -> None:
    print("PseudoForge profile load smoke: %s" % result["status"])
    print("family: %s" % result["family"])
    print("profile_file: %s" % result["profile_file"])
    print("entries: %s" % result["entry_count"])
    print("cold_load_ms: %.3f" % result["cold_load_ms"])
    print("repeated_lookup_ms: %.3f" % result["repeated_lookup_ms"])
    print("active_profiles: %s" % ", ".join(result["active_profiles"]))
    for warning in result["warnings"]:
        print("warning: %s" % warning)
    for failure in result["failures"]:
        print("failure: %s" % failure)


if __name__ == "__main__":
    raise SystemExit(main())

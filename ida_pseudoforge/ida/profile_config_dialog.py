from __future__ import annotations

from pathlib import Path

from ida_pseudoforge.profiles import loader as profile_loader

try:
    import ida_kernwin  # type: ignore
except Exception:
    ida_kernwin = None


def ask_profile_dir(current_profile_dir: str, warn) -> str | None:
    current = str(current_profile_dir or "").strip()
    if ida_kernwin is None:
        return current

    selected = ida_kernwin.ask_str(
        current,
        0,
        "PseudoForge profile directory (blank uses default/env)",
    )
    if selected is None:
        return None

    selected = str(selected or "").strip()
    if not selected:
        return ""

    path = Path(selected).expanduser()
    if not path.exists():
        warn("PseudoForge profile directory does not exist: %s" % selected)
        return None
    if not path.is_dir():
        warn("PseudoForge profile path is not a directory: %s" % selected)
        return None
    return selected


def format_profile_summary(configured_profile_dir: str) -> str:
    configured = str(configured_profile_dir or "").strip() or "(default/env)"
    lines = [
        "Profile directory: %s" % configured,
        "Active profile root: %s" % profile_loader.active_profile_root(),
    ]
    active_names = profile_loader.active_profile_names()
    if active_names:
        lines.append("Loaded profiles: %s" % ", ".join(active_names))
    versions = sorted(
        {
            str(item.get("source_version"))
            for item in profile_loader.active_profile_manifests()
            if item.get("source_version")
        }
    )
    if versions:
        lines.append("Profile source versions: %s" % ", ".join(versions))
    warnings = profile_loader.profile_load_warnings()
    if warnings:
        lines.append("Profile warnings: %d" % len(warnings))
    return "\n".join(lines)

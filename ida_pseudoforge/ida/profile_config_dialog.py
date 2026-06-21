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
    domain_names = profile_loader.available_domain_identity_profile_names()
    lines.append("Available domain packs: %d" % len(domain_names))
    lines.append("Domain pack files: %s" % _format_name_list(domain_names))
    domain_versions = sorted(
        {
            str(item.get("source_version"))
            for item in profile_loader.available_domain_identity_profile_manifests()
            if item.get("source_version")
        }
    )
    if domain_versions:
        lines.append("Domain pack source versions: %s" % ", ".join(domain_versions))
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


def _format_name_list(names: list[str], limit: int = 8) -> str:
    if not names:
        return "none"
    shown = names[: max(1, int(limit))]
    text = ", ".join(shown)
    if len(names) > len(shown):
        text += ", ... %d more" % (len(names) - len(shown))
    return text

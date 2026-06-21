from __future__ import annotations

from pathlib import Path

from ida_pseudoforge.core.capture import profile_context_from_source_path


def format_source_context_summary(
    source_path: str | Path | None = "",
    idb_path: str | Path | None = "",
    configured_profile_dir: str = "",
    active_profile_root: str | Path | None = "",
) -> str:
    source_text = _path_text(source_path)
    idb_text = _path_text(idb_path)
    context_basis = source_text or idb_text
    context = profile_context_from_source_path(context_basis)

    image = _context_value(context, "image")
    arch = _context_value(context, "arch")
    build = _context_value(context, "build")
    missing = []
    if not context_basis:
        missing.append("source_path")
    if image == "(missing)":
        missing.append("image")
    if arch == "(missing)":
        missing.append("arch")
    if build == "(missing)":
        missing.append("build")

    basis_label = "target path"
    if not source_text and idb_text:
        basis_label = "IDB path fallback"
    elif not context_basis:
        basis_label = "(none)"

    configured = str(configured_profile_dir or "").strip() or "(default/env)"
    active_root = _path_text(active_profile_root) or "(unknown)"
    status = "complete" if not missing else "missing " + ", ".join(missing)
    return "\n".join(
        [
            "Source context:",
            "Target path: %s" % (source_text or "(unavailable)"),
            "IDB path: %s" % (idb_text or "(unavailable)"),
            "Context basis: %s" % basis_label,
            "Inferred image: %s" % image,
            "Inferred arch: %s" % arch,
            "Inferred build: %s" % build,
            "Context status: %s" % status,
            "Configured profile dir: %s" % configured,
            "Active profile root: %s" % active_root,
        ]
    )


def _path_text(value: str | Path | None) -> str:
    text = str(value or "").strip()
    return text


def _context_value(context: dict[str, object], key: str) -> str:
    value = str(context.get(key, "") or "").strip()
    return value if value else "(missing)"

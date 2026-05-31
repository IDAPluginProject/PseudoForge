from __future__ import annotations

from typing import Any


def summarize_rule_report(report: object) -> dict[str, Any]:
    data = report if isinstance(report, dict) else {}
    matched_rules = _safe_list(data.get("matched_rules"))
    rewrite_emissions = _safe_dict_list(data.get("rewrite_emissions"))
    rejected_emissions = _safe_list(data.get("rejected_emissions"))
    load_errors = _safe_dict_list(data.get("load_errors"))
    validation_errors = _safe_dict_list(data.get("validation_errors"))
    return {
        "matched_rules": len(matched_rules),
        "rewrite_emissions": {
            "total": len(rewrite_emissions),
            "by_status": _rewrite_status_counts(rewrite_emissions),
            "by_kind": _rewrite_kind_counts(rewrite_emissions),
        },
        "rejected_emissions": len(rejected_emissions),
        "load_errors": len(load_errors),
        "validation_errors": len(validation_errors),
        "load_error_details": load_errors,
        "validation_error_details": validation_errors,
    }


def format_rule_report_summary(
    report: object,
    include_error_details: bool = False,
    max_error_details: int = 3,
) -> str:
    diagnostics = summarize_rule_report(report)
    rewrite_status = diagnostics["rewrite_emissions"]["by_status"]
    matched = int(diagnostics["matched_rules"])
    applied = int(rewrite_status.get("applied", 0))
    shadowed = int(rewrite_status.get("shadowed", 0))
    rejected = int(rewrite_status.get("rejected", 0))
    load_errors = int(diagnostics["load_errors"])
    validation_errors = int(diagnostics["validation_errors"])
    if not any((matched, applied, shadowed, rejected, load_errors, validation_errors)):
        return ""
    lines = [
        (
            "Rules: %d matched, %d rewrite(s) applied, %d shadowed, %d rejected, "
            "%d load error(s), %d validation error(s)"
        )
        % (matched, applied, shadowed, rejected, load_errors, validation_errors)
    ]
    if include_error_details:
        lines.extend(_format_error_details("Rule load errors", diagnostics["load_error_details"], max_error_details))
        lines.extend(
            _format_error_details(
                "Rule validation errors",
                diagnostics["validation_error_details"],
                max_error_details,
            )
        )
    return "\n".join(lines)


def _rewrite_status_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"applied": 0, "shadowed": 0, "rejected": 0}
    for item in items:
        status = str(item.get("status", ""))
        if status in counts:
            counts[status] += 1
    return counts


def _rewrite_kind_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        kind = str(item.get("kind", "") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _format_error_details(title: str, items: object, max_items: int) -> list[str]:
    details = _safe_dict_list(items)
    if not details or max_items <= 0:
        return []
    lines = [title + ":"]
    for item in details[:max_items]:
        lines.append("- %s" % _format_error_item(item))
    remaining = len(details) - max_items
    if remaining > 0:
        lines.append("- ... %d more error(s)" % remaining)
    return lines


def _format_error_item(item: dict[str, Any]) -> str:
    path = str(item.get("path", "")).strip()
    error = str(item.get("error", "")).strip()
    if path and error:
        return "%s: %s" % (path, error)
    if error:
        return error
    if path:
        return path
    return str(item)


def _safe_list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def _safe_dict_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]

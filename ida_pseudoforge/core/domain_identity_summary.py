from __future__ import annotations

from collections import Counter
from typing import Any

from ida_pseudoforge.core.domain_identity import (
    MODE_CANONICAL_REWRITE_ELIGIBLE,
    MODE_PREVIEW_REWRITE,
    MODE_REPORT_ONLY,
)
from ida_pseudoforge.core.plan_schema import CleanPlan


DOMAIN_IDENTITY_COMMENT_KIND = "domain_structure_identity"


def domain_identity_summary_payload(plan: CleanPlan, top_profile_limit: int = 5) -> dict[str, Any]:
    comments = [
        item
        for item in plan.comments
        if str(item.get("kind", "")) == DOMAIN_IDENTITY_COMMENT_KIND
    ]
    mode_counts = Counter(str(item.get("effective_mode", "") or "") for item in comments)
    blocker_counts: Counter[str] = Counter()
    profile_counts: Counter[str] = Counter()
    for item in comments:
        for profile_id in _comment_profile_ids(item):
            profile_counts[profile_id] += 1
        for blocker in _comment_blockers(item):
            blocker_counts[blocker] += 1

    sorted_profiles = sorted(profile_counts.items(), key=lambda item: (-item[1], item[0]))
    sorted_blockers = sorted(blocker_counts.items(), key=lambda item: item[0])
    sorted_profile_counts = sorted(profile_counts.items(), key=lambda item: item[0])
    top_limit = max(1, int(top_profile_limit or 0))
    return {
        "total_hits": len(comments),
        "report_only_hits": mode_counts[MODE_REPORT_ONLY],
        "preview_rewrite_hits": mode_counts[MODE_PREVIEW_REWRITE],
        "canonical_rewrite_eligible_hits": mode_counts[MODE_CANONICAL_REWRITE_ELIGIBLE],
        "blocker_counts": {key: value for key, value in sorted_blockers},
        "top_profile_ids": [key for key, _value in sorted_profiles[:top_limit]],
        "profile_counts": {key: value for key, value in sorted_profile_counts},
    }


def format_domain_identity_summary(plan: CleanPlan, top_profile_limit: int = 5) -> str:
    return format_domain_identity_summary_payload(
        domain_identity_summary_payload(plan, top_profile_limit=top_profile_limit)
    )


def format_domain_identity_summary_payload(payload: dict[str, Any]) -> str:
    total_hits = _int_value(payload.get("total_hits"))
    if total_hits <= 0:
        return ""

    lines = [
        (
            "Domain identities: %d hit(s), %d report-only, %d preview-rewrite, "
            "%d canonical-rewrite-eligible."
        )
        % (
            total_hits,
            _int_value(payload.get("report_only_hits")),
            _int_value(payload.get("preview_rewrite_hits")),
            _int_value(payload.get("canonical_rewrite_eligible_hits")),
        )
    ]
    top_profiles = [str(item) for item in payload.get("top_profile_ids", []) if str(item)]
    if top_profiles:
        lines.append("Top profiles: %s." % ", ".join(top_profiles[:5]))
    blocker_counts = payload.get("blocker_counts", {})
    if isinstance(blocker_counts, dict) and blocker_counts:
        lines.append(
            "Profile blockers: %s."
            % ", ".join(
                "%s=%d" % (str(key), _int_value(value))
                for key, value in sorted(blocker_counts.items(), key=lambda item: str(item[0]))
            )
        )
    return "\n".join(lines)


def _comment_profile_ids(comment: dict[str, Any]) -> list[str]:
    profile_id = str(comment.get("profile_id") or comment.get("matched_profile_id") or "").strip()
    if profile_id == "ambiguous":
        ambiguous_ids = [
            str(item).strip()
            for item in comment.get("ambiguous_profile_ids", []) or []
            if str(item).strip()
        ]
        if ambiguous_ids:
            return list(dict.fromkeys(ambiguous_ids))
    if profile_id:
        return [profile_id]
    return []


def _comment_blockers(comment: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("blockers", "forced_report_only_reasons"):
        raw_values = comment.get(key, []) or []
        if isinstance(raw_values, str):
            raw_values = [raw_values]
        for value in raw_values:
            text = str(value or "").strip()
            if text:
                values.append(text)
    return list(dict.fromkeys(values))


def _int_value(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0

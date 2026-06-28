from __future__ import annotations

from typing import Any


POLICY_REVIEW_ONLY = "review_only"
POLICY_BALANCED = "balanced"
POLICY_PROJECTION_HEAVY = "projection_heavy"
POLICY_AUDIT_STRICT = "audit_strict"

DEFAULT_PROJECTION_POLICY = POLICY_REVIEW_ONLY

_POLICY_ALIASES = {
    "": DEFAULT_PROJECTION_POLICY,
    "review": POLICY_REVIEW_ONLY,
    "review-only": POLICY_REVIEW_ONLY,
    "review_only": POLICY_REVIEW_ONLY,
    "balanced": POLICY_BALANCED,
    "default": POLICY_BALANCED,
    "projection-heavy": POLICY_PROJECTION_HEAVY,
    "projection_heavy": POLICY_PROJECTION_HEAVY,
    "heavy": POLICY_PROJECTION_HEAVY,
    "audit": POLICY_AUDIT_STRICT,
    "audit-strict": POLICY_AUDIT_STRICT,
    "audit_strict": POLICY_AUDIT_STRICT,
    "strict": POLICY_AUDIT_STRICT,
}

_POLICY_LABELS = {
    POLICY_REVIEW_ONLY: "Review Only",
    POLICY_BALANCED: "Balanced",
    POLICY_PROJECTION_HEAVY: "Projection Heavy",
    POLICY_AUDIT_STRICT: "Audit Strict",
}

_BLOCKED_REASONS = {
    "offset/width conflict",
    "multiple allocation source merge",
    "alias base unclear",
    "escape-before-init",
    "free-before-use",
    "dominance/null-guard unclear",
    "array/strided loop pattern",
    "allocation size overrun",
    "volatile/mmio/atomic/interlocked access",
}


def normalize_projection_policy(value: object) -> str:
    key = str(value or "").strip().lower().replace(" ", "_")
    return _POLICY_ALIASES.get(key, DEFAULT_PROJECTION_POLICY)


def projection_policy_label(value: object) -> str:
    policy = normalize_projection_policy(value)
    return _POLICY_LABELS.get(policy, _POLICY_LABELS[DEFAULT_PROJECTION_POLICY])


def projection_policy_choices() -> list[str]:
    return [
        POLICY_REVIEW_ONLY,
        POLICY_BALANCED,
        POLICY_PROJECTION_HEAVY,
        POLICY_AUDIT_STRICT,
    ]


def projection_policy_description(value: object) -> str:
    policy = normalize_projection_policy(value)
    if policy == POLICY_BALANCED:
        return "project high-confidence candidates, comment medium candidates, report low candidates"
    if policy == POLICY_PROJECTION_HEAVY:
        return "project high-confidence candidates and safe medium candidates"
    if policy == POLICY_AUDIT_STRICT:
        return "prefer evidence and blockers; suppress pseudocode projection"
    return "emit side reports and review-only comments; suppress pseudocode projection"


def confidence_tier(candidate: dict[str, Any]) -> str:
    blockers = projection_blockers(candidate)
    if blockers:
        return "blocked"
    confidence = _float_value(candidate.get("confidence"), 0.0)
    evidence_count = len(candidate.get("evidence", []) or [])
    fields = candidate.get("fields", []) or []
    field_count = len(fields) if isinstance(fields, list) else 0
    aggregate_kind = str(candidate.get("aggregate_kind", "") or "")
    if confidence >= 0.82:
        return "high"
    if aggregate_kind == "pool_allocation_object" and confidence >= 0.78 and field_count >= 3 and evidence_count >= 4:
        return "high"
    if confidence >= 0.66:
        return "medium"
    return "low"


def projection_blockers(candidate: dict[str, Any]) -> list[str]:
    result = []
    for item in candidate.get("projection_blockers", []) or []:
        text = str(item or "").strip()
        if text:
            result.append(text)
    for item in candidate.get("safety_blockers", []) or []:
        text = str(item or "").strip()
        if _is_projection_blocker(text):
            result.append(text)
    return list(dict.fromkeys(result))


def projection_decision(candidate: dict[str, Any], policy: object) -> dict[str, Any]:
    normalized = normalize_projection_policy(policy)
    tier = confidence_tier(candidate)
    blockers = projection_blockers(candidate)
    applied = should_project(candidate, normalized)
    if blockers:
        decision = "blocked"
    elif applied:
        decision = "project"
    elif normalized == POLICY_AUDIT_STRICT:
        decision = "audit_report"
    elif tier == "low":
        decision = "side_report"
    else:
        decision = "comment_only"
    return {
        "policy": normalized,
        "policy_label": projection_policy_label(normalized),
        "policy_description": projection_policy_description(normalized),
        "confidence_tier": tier,
        "projection_applied": bool(applied),
        "policy_decision": decision,
        "projection_blockers": blockers,
        "score_reason": _score_reason(candidate, tier, blockers, normalized, applied),
    }


def apply_projection_policy_to_comments(comments: list[dict[str, Any]], policy: object) -> list[dict[str, Any]]:
    normalized = normalize_projection_policy(policy)
    for comment in comments:
        if not _is_projection_candidate(comment):
            continue
        comment.update(projection_decision(comment, normalized))
        if comment["policy_decision"] == "blocked":
            comment.setdefault("debug_evidence", [])
            comment["debug_evidence"] = list(comment["debug_evidence"]) + [
                "projection blocked: %s" % "; ".join(comment.get("projection_blockers", []) or [])
            ]
        else:
            comment.setdefault("debug_evidence", [])
            comment["debug_evidence"] = list(comment["debug_evidence"]) + [
                "projection policy %s selected %s for tier %s"
                % (normalized, comment["policy_decision"], comment["confidence_tier"])
            ]
    return comments


def should_project(candidate: dict[str, Any], policy: object) -> bool:
    normalized = normalize_projection_policy(policy)
    if normalized in {POLICY_REVIEW_ONLY, POLICY_AUDIT_STRICT}:
        return False
    tier = confidence_tier(candidate)
    if tier == "blocked" or projection_blockers(candidate):
        return False
    if normalized == POLICY_BALANCED:
        return tier == "high"
    if normalized == POLICY_PROJECTION_HEAVY:
        return tier == "high" or _safe_medium_projection(candidate)
    return False


def _safe_medium_projection(candidate: dict[str, Any]) -> bool:
    if confidence_tier(candidate) != "medium":
        return False
    aggregate_kind = str(candidate.get("aggregate_kind", "") or "")
    if aggregate_kind in {"stack_array", "strided_record"}:
        return False
    confidence = _float_value(candidate.get("confidence"), 0.0)
    return confidence >= 0.74 and not projection_blockers(candidate)


def _score_reason(
    candidate: dict[str, Any],
    tier: str,
    blockers: list[str],
    policy: str,
    applied: bool,
) -> str:
    confidence = _float_value(candidate.get("confidence"), 0.0)
    evidence = [str(item) for item in candidate.get("evidence", []) or [] if str(item)]
    if blockers:
        return "tier=%s confidence=%.2f blockers=%s" % (tier, confidence, "; ".join(blockers))
    action = "projected" if applied else "not projected"
    return "tier=%s confidence=%.2f evidence=%s policy=%s action=%s" % (
        tier,
        confidence,
        ", ".join(evidence[:6]) or "none",
        policy,
        action,
    )


def _is_projection_candidate(candidate: dict[str, Any]) -> bool:
    return str(candidate.get("kind", "") or "") in {
        "synthetic_local_aggregate",
        "synthetic_pool_aggregate",
    }


def _is_projection_blocker(text: str) -> bool:
    normalized = str(text or "").strip().lower()
    return any(reason in normalized for reason in _BLOCKED_REASONS)


def _float_value(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

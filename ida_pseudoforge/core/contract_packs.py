from __future__ import annotations

from collections import Counter
from functools import lru_cache
from typing import Any

from ida_pseudoforge.core.plan_schema import FunctionCapture, TargetContext
from ida_pseudoforge.profiles.loader import active_domain_pack_manifests, load_json_profile


CONTRACT_PACK_SCHEMA = "pseudoforge_contract_pack_v1"


def clear_profile_dependent_contract_pack_caches() -> None:
    load_contract_pack.cache_clear()


@lru_cache(maxsize=None)
def load_contract_pack(profile_name: str) -> dict[str, Any]:
    name = str(profile_name or "").strip()
    if not name:
        return {}
    payload = load_json_profile(name)
    if not isinstance(payload, dict):
        return {}
    if str(payload.get("schema", "") or "").strip() != CONTRACT_PACK_SCHEMA:
        return {}
    contracts = payload.get("contracts", [])
    if not isinstance(contracts, list):
        contracts = []
    normalized = dict(payload)
    normalized["profile_name"] = name
    normalized["contracts"] = [
        _normalize_contract(item)
        for item in contracts
        if isinstance(item, dict) and _normalize_contract(item)
    ]
    return normalized


def contract_profile_names_for_target(context: TargetContext) -> list[str]:
    eligible = {str(item or "") for item in context.eligible_domain_packs if str(item or "")}
    if not eligible:
        return []
    result: list[str] = []
    for manifest in active_domain_pack_manifests():
        pack_id = str(manifest.get("id", "") or "")
        if pack_id not in eligible:
            continue
        for profile_name in _string_list(manifest.get("profile_names")):
            if _looks_like_contract_profile(profile_name):
                result.append(profile_name)
    return sorted(dict.fromkeys(result))


def contract_pack_comments(capture: FunctionCapture) -> list[dict[str, Any]]:
    target = capture.target_context
    call_names = [str(item or "") for item in capture.calls if str(item or "")]
    call_keys = {_symbol_key(item): item for item in call_names if _symbol_key(item)}
    comments: list[dict[str, Any]] = []
    for profile_name in contract_profile_names_for_target(target):
        profile = load_contract_pack(profile_name)
        if not profile:
            continue
        if not _profile_matches_target(profile, target):
            continue
        profile_id = str(profile.get("id", "") or profile_name)
        domain_pack_id = str(profile.get("domain_pack_id", "") or "")
        target_domain = str(profile.get("target_domain", "") or "")
        mode = str(profile.get("mode", "report-only") or "report-only")
        for contract in profile.get("contracts", []) or []:
            if not isinstance(contract, dict):
                continue
            matched_call = _matched_call(contract, call_keys)
            if not matched_call:
                continue
            comments.append(
                {
                    "kind": "contract_pack_api",
                    "mode": mode,
                    "contract_id": str(contract.get("id", "") or ""),
                    "contract_profile": profile_name,
                    "contract_profile_id": profile_id,
                    "domain_pack": domain_pack_id,
                    "contract_domain": target_domain,
                    "contract_symbol": str(contract.get("symbol", "") or ""),
                    "matched_call": matched_call,
                    "text": _comment_text(contract, matched_call),
                    "argument_roles": _string_list(contract.get("argument_roles")),
                    "return_rule": str(contract.get("return_rule", "") or ""),
                    "ownership": str(contract.get("ownership", "") or ""),
                    "lifetime": str(contract.get("lifetime", "") or ""),
                    "confidence": _float_value(contract.get("confidence"), 0.78),
                    "evidence": _string_list(contract.get("evidence")),
                    "negative_controls": _string_list(contract.get("negative_controls")),
                }
            )
    return comments


def contract_pack_summary(capture: FunctionCapture, plan: Any | None = None) -> dict[str, Any]:
    profile_names = contract_profile_names_for_target(capture.target_context)
    loaded_profiles = []
    contracts_by_domain: Counter[str] = Counter()
    total_contracts = 0
    for profile_name in profile_names:
        profile = load_contract_pack(profile_name)
        if not profile:
            continue
        if not _profile_matches_target(profile, capture.target_context):
            continue
        loaded_profiles.append(profile_name)
        domain = str(profile.get("target_domain", "") or "unknown")
        contracts = [item for item in profile.get("contracts", []) or [] if isinstance(item, dict)]
        total_contracts += len(contracts)
        contracts_by_domain[domain] += len(contracts)

    comments = []
    if plan is not None:
        comments = [
            item
            for item in getattr(plan, "comments", []) or []
            if isinstance(item, dict) and str(item.get("kind", "") or "") == "contract_pack_api"
        ]
    else:
        comments = contract_pack_comments(capture)

    matched_symbols = sorted(
        {
            str(item.get("contract_symbol", "") or item.get("matched_call", "") or "")
            for item in comments
            if str(item.get("contract_symbol", "") or item.get("matched_call", "") or "")
        }
    )
    matched_profiles = sorted(
        {
            str(item.get("contract_profile", "") or "")
            for item in comments
            if str(item.get("contract_profile", "") or "")
        }
    )
    matched_domains = Counter(
        str(item.get("contract_domain", "") or "unknown")
        for item in comments
        if str(item.get("contract_domain", "") or "")
    )
    return {
        "schema": "pseudoforge_contract_pack_summary_v1",
        "eligible_domain_packs": list(capture.target_context.eligible_domain_packs),
        "profiles": loaded_profiles,
        "matched_profiles": matched_profiles,
        "total_contracts": total_contracts,
        "matched_contracts": len(comments),
        "matched_symbols": matched_symbols,
        "contracts_by_domain": dict(sorted(contracts_by_domain.items())),
        "matched_by_domain": dict(sorted(matched_domains.items())),
    }


def _normalize_contract(item: dict[str, Any]) -> dict[str, Any]:
    symbol = str(item.get("symbol", "") or "").strip()
    contract_id = str(item.get("id", "") or "").strip()
    if not symbol or not contract_id:
        return {}
    result = dict(item)
    result["id"] = contract_id
    result["symbol"] = symbol
    result["aliases"] = _string_list(item.get("aliases"))
    result["argument_roles"] = _string_list(item.get("argument_roles"))
    result["evidence"] = _string_list(item.get("evidence"))
    result["negative_controls"] = _string_list(item.get("negative_controls"))
    return result


def _profile_matches_target(profile: dict[str, Any], context: TargetContext) -> bool:
    domain_pack_id = str(profile.get("domain_pack_id", "") or "").strip()
    if not domain_pack_id:
        return False
    return domain_pack_id in {str(item or "") for item in context.eligible_domain_packs}


def _matched_call(contract: dict[str, Any], call_keys: dict[str, str]) -> str:
    for symbol in [str(contract.get("symbol", "") or ""), *_string_list(contract.get("aliases"))]:
        key = _symbol_key(symbol)
        if key and key in call_keys:
            return call_keys[key]
    return ""


def _comment_text(contract: dict[str, Any], matched_call: str) -> str:
    summary = str(contract.get("summary", "") or "").strip()
    return_rule = str(contract.get("return_rule", "") or "").strip()
    lifetime = str(contract.get("lifetime", "") or "").strip()
    parts = ["%s contract" % matched_call]
    if summary:
        parts.append(summary)
    if return_rule:
        parts.append(return_rule)
    if lifetime:
        parts.append("lifetime: %s" % lifetime)
    return "; ".join(parts)


def _looks_like_contract_profile(profile_name: str) -> bool:
    normalized = str(profile_name or "").replace("\\", "/")
    return normalized.startswith("contracts/") and normalized.endswith(".json")


def _symbol_key(symbol: str) -> str:
    text = str(symbol or "").strip()
    if text.startswith("__imp_"):
        text = text[len("__imp_"):]
    if text.startswith("_imp__"):
        text = text[len("_imp__"):]
    return text.casefold()


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, tuple):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def _float_value(value: object, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback

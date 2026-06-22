from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any

from ida_pseudoforge.profiles.loader import load_json_profile


CALLEE_CONTRACTS_PROFILE_NAME = "callee_contracts.json"
CALLEE_CONTRACT_ACTIONS = {
    "callee_arity_residue_candidate",
    "helper_thunk_slot_candidate",
    "internal_lock_helper_residue",
}


def callee_contract_for_call(
    callee_name: str,
    argument_index: int,
    call_index: int,
    callee_call_index: int,
) -> dict[str, Any]:
    callee = str(callee_name or "").strip()
    if not callee:
        return {}
    for contract in _callee_contracts():
        if not _contract_matches_callee(contract, callee):
            continue
        if not _contract_matches_index(contract, "argument_indices", argument_index):
            continue
        if not _contract_meets_minimum(contract, "min_argument_index", argument_index):
            continue
        if not _contract_meets_minimum(contract, "min_call_index", call_index):
            continue
        if not _contract_meets_minimum(contract, "min_callee_call_index", callee_call_index):
            continue
        action = str(contract.get("action", "") or "").strip()
        if action not in CALLEE_CONTRACT_ACTIONS:
            continue
        return dict(contract)
    return {}


def _callee_contracts() -> list[dict[str, Any]]:
    payload = load_json_profile(CALLEE_CONTRACTS_PROFILE_NAME)
    if not isinstance(payload, dict):
        return []
    contracts = payload.get("contracts", [])
    if not isinstance(contracts, list):
        return []
    return [dict(item) for item in contracts if isinstance(item, dict)]


def _contract_matches_callee(contract: dict[str, Any], callee: str) -> bool:
    callees = contract.get("callees", [])
    if isinstance(callees, str):
        callees = [callees]
    if any(callee == str(item or "").strip() for item in callees):
        return True
    patterns = contract.get("callee_patterns", [])
    if isinstance(patterns, str):
        patterns = [patterns]
    return any(fnmatchcase(callee, str(pattern or "").strip()) for pattern in patterns if str(pattern or "").strip())


def _contract_matches_index(contract: dict[str, Any], key: str, value: int) -> bool:
    raw_values = contract.get(key)
    if raw_values is None:
        return True
    if not isinstance(raw_values, list):
        raw_values = [raw_values]
    allowed = set()
    for item in raw_values:
        try:
            allowed.add(int(item))
        except (TypeError, ValueError):
            continue
    return int(value) in allowed


def _contract_meets_minimum(contract: dict[str, Any], key: str, value: int) -> bool:
    if key not in contract:
        return True
    try:
        minimum = int(contract.get(key))
    except (TypeError, ValueError):
        return True
    return int(value) >= minimum

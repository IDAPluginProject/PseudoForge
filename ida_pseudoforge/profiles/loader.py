from __future__ import annotations

import json
from functools import lru_cache
from typing import Any
from pathlib import Path


PROFILE_DIR = Path(__file__).resolve().parent
_PROFILE_LOAD_WARNINGS: dict[str, str] = {}


@lru_cache(maxsize=None)
def load_json_profile(name: str) -> Any:
    path = PROFILE_DIR / name
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        _PROFILE_LOAD_WARNINGS.pop(name, None)
        return payload
    except FileNotFoundError:
        _record_profile_warning(name, "missing profile file: %s" % path)
        return {}
    except json.JSONDecodeError as exc:
        _record_profile_warning(
            name,
            "invalid JSON in %s at line %d column %d: %s"
            % (path, exc.lineno, exc.colno, exc.msg),
        )
        return {}
    except OSError as exc:
        _record_profile_warning(name, "profile read failed for %s: %s" % (path, exc))
        return {}


@lru_cache(maxsize=None)
def load_profile(name: str) -> dict[str, str]:
    data = load_json_profile(name)
    if not isinstance(data, dict):
        _record_profile_warning(name, "profile root must be a JSON object, got %s" % type(data).__name__)
        return {}
    return {str(key): str(value) for key, value in data.items()}


def profile_load_warnings() -> list[str]:
    return [_PROFILE_LOAD_WARNINGS[name] for name in sorted(_PROFILE_LOAD_WARNINGS)]


def clear_profile_caches() -> None:
    load_json_profile.cache_clear()
    load_profile.cache_clear()
    get_system_information_class_value.cache_clear()
    get_process_information_class_value.cache_clear()
    _PROFILE_LOAD_WARNINGS.clear()


def _record_profile_warning(name: str, message: str) -> None:
    _PROFILE_LOAD_WARNINGS[name] = "PseudoForge profile load warning: %s: %s" % (name, message)


def get_status_name(literal: str | int) -> str:
    return load_profile("status_codes.json").get(str(literal), "")


def get_system_information_class_name(value: int) -> str:
    return load_profile("system_information_class.json").get(str(value), "")


def get_process_information_class_name(value: int) -> str:
    return load_profile("process_information_class.json").get(str(value), "")


@lru_cache(maxsize=None)
def get_system_information_class_value(name: str) -> int | None:
    target = str(name or "").strip()
    if not target:
        return None
    for value, enum_name in load_profile("system_information_class.json").items():
        if enum_name == target:
            try:
                return int(value)
            except ValueError:
                return None
    return None


@lru_cache(maxsize=None)
def get_process_information_class_value(name: str) -> int | None:
    target = str(name or "").strip()
    if not target:
        return None
    for value, enum_name in load_profile("process_information_class.json").items():
        if enum_name == target:
            try:
                return int(value)
            except ValueError:
                return None
    return None

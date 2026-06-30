from __future__ import annotations

import json
import os
import sys
from functools import lru_cache
from typing import Any
from pathlib import Path


DEFAULT_PROFILE_DIR = Path(__file__).resolve().parent
PROFILE_DIR = Path(os.environ.get("PSEUDOFORGE_PROFILE_DIR") or DEFAULT_PROFILE_DIR).expanduser()
PROFILE_MANIFEST_NAME = "profiles_manifest.json"
DOMAIN_PACKS_MANIFEST_NAME = "domain_packs_manifest.json"
DOMAIN_PACKS_SCHEMA = "pseudoforge_domain_packs_v1"
KERNEL_API_PROFILE_NAME = "kernel_api.json"
DOMAIN_IDENTITY_PROFILE_NAME = "domain_identity.json"
DOMAIN_IDENTITY_PROFILE_DIR = "domain_identity"
SUBSYSTEM_IDENTITY_INDEX_NAME = "subsystem_identity_index.json"
KERNEL_API_FAMILY_FILES = {
    "functions": "kernel_functions.json",
    "enums": "kernel_enums.json",
    "structures": "kernel_structures.json",
    "aliases": "kernel_aliases.json",
    "macros": "kernel_macros.json",
    "symbols": "kernel_symbol_index.json",
    "indices": "kernel_indices.json",
}
_PROFILE_LOAD_WARNINGS: dict[str, str] = {}
_ACTIVE_PROFILE_NAMES: set[str] = set()


def configure_profile_dir(path: str | Path | None = None) -> Path:
    global PROFILE_DIR

    path_text = str(path or "").strip()
    raw_path = path_text if path_text else os.environ.get("PSEUDOFORGE_PROFILE_DIR", "").strip()
    PROFILE_DIR = Path(raw_path).expanduser() if raw_path else DEFAULT_PROFILE_DIR
    clear_profile_caches()
    return PROFILE_DIR


def active_profile_root() -> str:
    return str(PROFILE_DIR)


@lru_cache(maxsize=None)
def load_json_profile(name: str) -> Any:
    _ACTIVE_PROFILE_NAMES.add(name)
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


@lru_cache(maxsize=None)
def load_kernel_api_family(family: str) -> dict[str, Any]:
    family_name = str(family or "").strip()
    if not family_name:
        return {}

    split_name = KERNEL_API_FAMILY_FILES.get(family_name)
    if split_name and (PROFILE_DIR / split_name).exists():
        return _load_kernel_api_family_file(split_name, family_name)

    data = load_json_profile(KERNEL_API_PROFILE_NAME)
    if not isinstance(data, dict):
        _record_profile_warning(
            KERNEL_API_PROFILE_NAME,
            "kernel API profile root must be a JSON object, got %s" % type(data).__name__,
        )
        return {}
    family_data = data.get(family_name, {})
    if not isinstance(family_data, dict):
        _record_profile_warning(
            KERNEL_API_PROFILE_NAME,
            "kernel API family %s must be a JSON object, got %s" % (family_name, type(family_data).__name__),
        )
        return {}
    return family_data


def profile_load_warnings() -> list[str]:
    return [_PROFILE_LOAD_WARNINGS[name] for name in sorted(_PROFILE_LOAD_WARNINGS)]


def active_profile_names() -> list[str]:
    return sorted(_ACTIVE_PROFILE_NAMES)


def active_profile_manifests() -> list[dict[str, Any]]:
    result = []
    for name in sorted(_ACTIVE_PROFILE_NAMES):
        manifest = profile_manifest(name)
        if manifest:
            result.append(manifest)
    return result


def available_domain_identity_profile_names() -> list[str]:
    root = PROFILE_DIR
    names: list[str] = []
    if (root / DOMAIN_IDENTITY_PROFILE_NAME).is_file():
        names.append(DOMAIN_IDENTITY_PROFILE_NAME)
    pack_root = root / DOMAIN_IDENTITY_PROFILE_DIR
    if pack_root.is_dir():
        for path in sorted(pack_root.glob("*.json")):
            if path.is_file():
                names.append("%s/%s" % (DOMAIN_IDENTITY_PROFILE_DIR, path.name))
    return names


def available_domain_identity_profile_manifests() -> list[dict[str, Any]]:
    result = []
    for name in available_domain_identity_profile_names():
        manifest = profile_manifest(name)
        if manifest:
            result.append(manifest)
    return result


def active_domain_pack_ids() -> list[str]:
    return [str(item.get("id", "")) for item in active_domain_pack_manifests() if str(item.get("id", ""))]


def active_domain_pack_manifests() -> list[dict[str, Any]]:
    return available_domain_pack_manifests()


def available_domain_pack_manifests() -> list[dict[str, Any]]:
    manifest_status, manifest = load_domain_packs_manifest()
    if manifest_status == "invalid":
        return []
    if manifest_status == "loaded":
        return _available_domain_pack_entries(_domain_pack_entries_from_manifest(manifest))
    return _available_domain_pack_entries(_compatibility_domain_pack_entries())


@lru_cache(maxsize=None)
def subsystem_identity_index_entries() -> dict[str, dict[str, Any]]:
    path = PROFILE_DIR / SUBSYSTEM_IDENTITY_INDEX_NAME
    if not path.is_file():
        return {}

    payload = load_json_profile(SUBSYSTEM_IDENTITY_INDEX_NAME)
    if not isinstance(payload, dict):
        _record_profile_warning(
            SUBSYSTEM_IDENTITY_INDEX_NAME,
            "subsystem identity index root must be a JSON object, got %s" % type(payload).__name__,
        )
        return {}
    entries = payload.get("entries", [])
    if not isinstance(entries, list):
        _record_profile_warning(
            SUBSYSTEM_IDENTITY_INDEX_NAME,
            "subsystem identity index entries must be a JSON array, got %s" % type(entries).__name__,
        )
        return {}

    available_ids = set(_available_domain_identity_profile_ids())
    result: dict[str, dict[str, Any]] = {}
    for item in entries:
        if not isinstance(item, dict):
            continue
        for profile_id in _subsystem_index_profile_ids(item, available_ids):
            metadata = _subsystem_index_metadata(payload, item, profile_id)
            if metadata:
                result[profile_id] = metadata
    return {key: result[key] for key in sorted(result)}


def subsystem_identity_metadata(profile_id: str) -> dict[str, Any]:
    target = str(profile_id or "").strip()
    if not target:
        return {}
    metadata = subsystem_identity_index_entries().get(target, {})
    return dict(metadata) if isinstance(metadata, dict) else {}


def profile_manifest(name: str) -> dict[str, Any]:
    profiles = _profiles_manifest_entries()
    entry = profiles.get(name)
    if not isinstance(entry, dict):
        return {}
    result = dict(entry)
    result["name"] = name
    return result


def clear_profile_caches() -> None:
    load_json_profile.cache_clear()
    load_profile.cache_clear()
    load_kernel_api_family.cache_clear()
    subsystem_identity_index_entries.cache_clear()
    _available_domain_identity_profile_ids.cache_clear()
    load_profiles_manifest.cache_clear()
    load_domain_packs_manifest.cache_clear()
    get_kernel_enum_member_name.cache_clear()
    get_kernel_enum_member_value.cache_clear()
    get_system_information_class_value.cache_clear()
    get_process_information_class_value.cache_clear()
    get_thread_information_class_value.cache_clear()
    _PROFILE_LOAD_WARNINGS.clear()
    _ACTIVE_PROFILE_NAMES.clear()
    _clear_profile_dependent_runtime_caches()


def _clear_profile_dependent_runtime_caches() -> None:
    clearers = (
        (
            "ida_pseudoforge.core.kernel_rewrites",
            "clear_profile_dependent_kernel_rewrite_caches",
        ),
        (
            "ida_pseudoforge.core.buffer_contracts",
            "clear_profile_dependent_buffer_contract_caches",
        ),
        (
            "ida_pseudoforge.core.contract_packs",
            "clear_profile_dependent_contract_pack_caches",
        ),
        (
            "ida_pseudoforge.core.render_status",
            "clear_profile_dependent_render_status_caches",
        ),
    )
    for module_name, function_name in clearers:
        module = sys.modules.get(module_name)
        if module is None:
            continue
        clear_func = getattr(module, function_name, None)
        if clear_func is None:
            continue
        clear_func()


@lru_cache(maxsize=None)
def load_profiles_manifest() -> dict[str, Any]:
    path = PROFILE_DIR / PROFILE_MANIFEST_NAME
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        _record_profile_warning(
            PROFILE_MANIFEST_NAME,
            "invalid JSON in %s at line %d column %d: %s"
            % (path, exc.lineno, exc.colno, exc.msg),
        )
        return {}
    except OSError as exc:
        _record_profile_warning(
            PROFILE_MANIFEST_NAME,
            "profile manifest read failed for %s: %s" % (path, exc),
        )
        return {}
    if not isinstance(payload, dict):
        _record_profile_warning(
            PROFILE_MANIFEST_NAME,
            "profile manifest root must be a JSON object, got %s" % type(payload).__name__,
        )
        return {}
    return payload


@lru_cache(maxsize=None)
def load_domain_packs_manifest() -> tuple[str, dict[str, Any]]:
    path = PROFILE_DIR / DOMAIN_PACKS_MANIFEST_NAME
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return "missing", {}
    except json.JSONDecodeError as exc:
        _record_profile_warning(
            DOMAIN_PACKS_MANIFEST_NAME,
            "invalid JSON in %s at line %d column %d: %s"
            % (path, exc.lineno, exc.colno, exc.msg),
        )
        return "invalid", {}
    except OSError as exc:
        _record_profile_warning(
            DOMAIN_PACKS_MANIFEST_NAME,
            "domain pack manifest read failed for %s: %s" % (path, exc),
        )
        return "invalid", {}
    if not isinstance(payload, dict):
        _record_profile_warning(
            DOMAIN_PACKS_MANIFEST_NAME,
            "domain pack manifest root must be a JSON object, got %s" % type(payload).__name__,
        )
        return "invalid", {}
    schema = str(payload.get("schema", "") or "").strip()
    if schema and schema != DOMAIN_PACKS_SCHEMA:
        _record_profile_warning(
            DOMAIN_PACKS_MANIFEST_NAME,
            "unsupported domain pack manifest schema: %s" % schema,
        )
        return "invalid", {}
    return "loaded", payload


def _domain_pack_entries_from_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    packs = manifest.get("packs", [])
    if not isinstance(packs, list):
        _record_profile_warning(
            DOMAIN_PACKS_MANIFEST_NAME,
            "domain pack manifest packs must be a JSON array, got %s" % type(packs).__name__,
        )
        return []
    result = []
    for item in packs:
        if not isinstance(item, dict):
            continue
        pack_id = str(item.get("id", "") or "").strip()
        if not pack_id:
            continue
        payload = dict(item)
        payload["id"] = pack_id
        payload.setdefault("availability", "manifest")
        result.append(payload)
    return result


def _compatibility_domain_pack_entries() -> list[dict[str, Any]]:
    entries = [
        {
            "id": "generic_core",
            "title": "Generic Decompile Cleanup Core",
            "domain": "generic",
            "mode": "report-only",
            "source": "PseudoForge builtin generic cleanup scaffolding",
            "source_version": "",
            "profile_names": [],
            "rule_pack_names": [],
            "availability": "compatibility",
        }
    ]
    kernel_profiles = _kernel_compatibility_profile_names()
    if kernel_profiles:
        entries.append(
            {
                "id": "windows_kernel",
                "title": "Windows Kernel",
                "domain": "windows_kernel",
                "mode": "compatibility",
                "source": "PseudoForge packaged WDK and curated Windows kernel profiles",
                "source_version": _windows_kernel_pack_source_version(),
                "profile_names": kernel_profiles,
                "rule_pack_names": [],
                "availability": "compatibility",
            }
        )
    return entries


def _available_domain_pack_entries(packs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for item in packs:
        pack_id = str(item.get("id", "") or "").strip()
        if not pack_id:
            continue
        profile_names = _domain_pack_profile_names(item)
        available_profiles = [name for name in profile_names if (PROFILE_DIR / name).exists()]
        if profile_names and not available_profiles:
            continue
        payload = dict(item)
        payload["id"] = pack_id
        payload["profile_names"] = available_profiles
        payload["available"] = True
        result.append(payload)
    result.sort(key=lambda entry: str(entry.get("id", "")))
    return result


def _domain_pack_profile_names(item: dict[str, Any]) -> list[str]:
    names = _string_list(item.get("profile_names"))
    for pattern in _string_list(item.get("profile_globs")):
        for path in sorted(PROFILE_DIR.glob(pattern)):
            if path.is_file():
                names.append(path.relative_to(PROFILE_DIR).as_posix())
    return sorted(dict.fromkeys(names))


def _kernel_compatibility_profile_names() -> list[str]:
    names = []
    for name in sorted(KERNEL_API_FAMILY_FILES.values()):
        if (PROFILE_DIR / name).exists():
            names.append(name)
    for name in (
        "kernel_api_overrides.json",
        "callee_contracts.json",
        "direct_call_result_layout_hints.json",
        "subsystem_identity_index.json",
        "status_codes.json",
        "system_information_class.json",
        "process_information_class.json",
        "registry_domain.json",
    ):
        if (PROFILE_DIR / name).exists():
            names.append(name)
    names.extend(available_domain_identity_profile_names())
    return sorted(dict.fromkeys(names))


def _windows_kernel_pack_source_version() -> str:
    versions = []
    for name in _kernel_compatibility_profile_names():
        manifest = profile_manifest(name)
        version = str(manifest.get("source_version", "") or "").strip()
        if version:
            versions.append(version)
    return ", ".join(sorted(dict.fromkeys(versions)))


def _profiles_manifest_entries() -> dict[str, Any]:
    manifest = load_profiles_manifest()
    profiles = manifest.get("profiles", {}) if isinstance(manifest, dict) else {}
    return profiles if isinstance(profiles, dict) else {}


@lru_cache(maxsize=None)
def _available_domain_identity_profile_ids() -> tuple[str, ...]:
    result: list[str] = []
    for name in available_domain_identity_profile_names():
        data = load_json_profile(name)
        if not isinstance(data, dict):
            continue
        profiles = data.get("profiles", [])
        if not isinstance(profiles, list) and _looks_like_domain_profile(data):
            profiles = [data]
        if not isinstance(profiles, list):
            continue
        for item in profiles:
            if not isinstance(item, dict):
                continue
            profile_id = str(item.get("id", "")).strip()
            if profile_id:
                result.append(profile_id)
    return tuple(sorted(dict.fromkeys(result)))


def _looks_like_domain_profile(payload: dict[str, Any]) -> bool:
    return bool(payload.get("id") or payload.get("name")) and bool(payload.get("parameters"))


def _subsystem_index_profile_ids(item: dict[str, Any], available_ids: set[str]) -> list[str]:
    result: list[str] = []
    profile_id = str(item.get("profile_id", "")).strip()
    if profile_id and profile_id in available_ids:
        result.append(profile_id)

    profile_ids = item.get("profile_ids", [])
    if isinstance(profile_ids, list):
        for value in profile_ids:
            candidate = str(value or "").strip()
            if candidate and candidate in available_ids:
                result.append(candidate)

    profile_id_prefix = str(item.get("profile_id_prefix", "")).strip()
    if profile_id_prefix:
        result.extend(profile_id for profile_id in sorted(available_ids) if profile_id.startswith(profile_id_prefix))
    return list(dict.fromkeys(result))


def _subsystem_index_metadata(
    root: dict[str, Any],
    item: dict[str, Any],
    profile_id: str,
) -> dict[str, Any]:
    subsystem = str(item.get("subsystem", "")).strip()
    if not subsystem:
        return {}
    return {
        "profile_id": profile_id,
        "subsystem": subsystem,
        "role_group": str(item.get("role_group", "")).strip(),
        "source_version": str(item.get("source_version") or root.get("source_version") or "").strip(),
        "description": str(item.get("description", "")).strip(),
    }


def _load_kernel_api_family_file(name: str, family: str) -> dict[str, Any]:
    data = load_json_profile(name)
    if not isinstance(data, dict):
        _record_profile_warning(name, "profile root must be a JSON object, got %s" % type(data).__name__)
        return {}
    if family in data:
        nested = data.get(family)
        if isinstance(nested, dict):
            return nested
        _record_profile_warning(
            name,
            "kernel API family %s must be a JSON object, got %s" % (family, type(nested).__name__),
        )
        return {}
    return data


def _record_profile_warning(name: str, message: str) -> None:
    _PROFILE_LOAD_WARNINGS[name] = "PseudoForge profile load warning: %s: %s" % (name, message)


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, tuple):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def get_status_name(literal: str | int) -> str:
    return load_profile("status_codes.json").get(str(literal), "")


def get_system_information_class_name(value: int) -> str:
    return load_profile("system_information_class.json").get(str(value), "")


def get_process_information_class_name(value: int) -> str:
    return load_profile("process_information_class.json").get(str(value), "")


def get_thread_information_class_name(value: int) -> str:
    return get_kernel_enum_member_name("THREADINFOCLASS", value)


@lru_cache(maxsize=None)
def get_kernel_enum_member_name(enum_name: str, value: int) -> str:
    enum = _kernel_enum_members(enum_name)
    return enum.get(str(value), "")


@lru_cache(maxsize=None)
def get_kernel_enum_member_value(enum_name: str, member_name: str) -> int | None:
    target = str(member_name or "").strip()
    if not target:
        return None
    for value, name in _kernel_enum_members(enum_name).items():
        if name == target:
            try:
                return int(value)
            except ValueError:
                return None
    return None


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


@lru_cache(maxsize=None)
def get_thread_information_class_value(name: str) -> int | None:
    return get_kernel_enum_member_value("THREADINFOCLASS", name)


def _kernel_enum_members(enum_name: str) -> dict[str, str]:
    target = str(enum_name or "").strip()
    if not target:
        return {}
    data = load_kernel_api_family("enums")
    enum = data.get(target, {}) if isinstance(data, dict) else {}
    if not isinstance(enum, dict):
        return {}
    return {str(key): str(value) for key, value in enum.items()}

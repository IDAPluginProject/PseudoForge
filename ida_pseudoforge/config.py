from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ida_pseudoforge.models.provider_registry import (
    PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
    PROVIDER_CLAUDE_CLI,
    PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    PROVIDER_CODEX_CLI,
    PROVIDER_OPENAI_COMPATIBLE,
    normalize_provider,
    provider_defaults,
)

DEFAULT_BASE_URL = provider_defaults(PROVIDER_OPENAI_COMPATIBLE).base_url
DEFAULT_MODEL = provider_defaults(PROVIDER_OPENAI_COMPATIBLE).model
_OLD_CODEX_COMMAND_TEMPLATES = {
    (
        "codex exec --skip-git-repo-check --sandbox read-only "
        "--ask-for-approval never --output-last-message {output_file} -"
    ),
    (
        "codex exec -m {model} --skip-git-repo-check --sandbox read-only "
        "--ask-for-approval never --output-last-message {output_file} -"
    ),
}
_OLD_CLAUDE_COMMAND_TEMPLATES = {
    "claude -p --permission-mode dontAsk --output-format text",
    "claude -p --model {model} --permission-mode dontAsk --output-format text",
}
PREVIEW_BACKEND_SIMPLE = "simple"
PREVIEW_BACKEND_SIDE_BY_SIDE = "side_by_side"
_PREVIEW_BACKEND_ALIASES = {
    "": PREVIEW_BACKEND_SIMPLE,
    "simple": PREVIEW_BACKEND_SIMPLE,
    "simple_viewer": PREVIEW_BACKEND_SIMPLE,
    "simple-viewer": PREVIEW_BACKEND_SIMPLE,
    "side_by_side": PREVIEW_BACKEND_SIDE_BY_SIDE,
    "side-by-side": PREVIEW_BACKEND_SIDE_BY_SIDE,
    "dockable": PREVIEW_BACKEND_SIDE_BY_SIDE,
}


@dataclass(slots=True)
class LlmConfig:
    enabled: bool = False
    provider: str = PROVIDER_OPENAI_COMPATIBLE
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout_seconds: int = 60
    command_template: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ProviderCredential:
    api_key: str = ""


@dataclass(slots=True)
class PreviewConfig:
    backend: str = PREVIEW_BACKEND_SIMPLE


@dataclass(slots=True)
class PseudoForgeConfig:
    llm: LlmConfig
    profile_dir: str = ""
    preview: PreviewConfig = field(default_factory=PreviewConfig)
    credentials: dict[str, ProviderCredential] = field(default_factory=dict)


def default_config() -> PseudoForgeConfig:
    return PseudoForgeConfig(llm=LlmConfig())


def get_config_path() -> Path:
    return get_config_dir() / "pseudoforge_config.json"


def get_config_dir() -> Path:
    try:
        import ida_diskio  # type: ignore

        user_dir = ida_diskio.get_user_idadir()
        if user_dir:
            return Path(user_dir)
    except Exception:
        pass

    base = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
    if base:
        return Path(base)

    return Path.home() / ".pseudoforge"


def load_config() -> PseudoForgeConfig:
    path = get_config_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default_config()
    except json.JSONDecodeError:
        return default_config()

    llm_data = data.get("llm", {}) if isinstance(data, dict) else {}
    provider = normalize_provider(llm_data.get("provider", PROVIDER_OPENAI_COMPATIBLE))
    defaults = provider_defaults(provider)
    credentials = _load_credentials(data, provider, llm_data)
    preview_data = data.get("preview", {}) if isinstance(data, dict) else {}
    preview_backend = ""
    if isinstance(preview_data, dict):
        preview_backend = str(preview_data.get("backend", "") or "")
    if not preview_backend and isinstance(data, dict):
        preview_backend = str(data.get("preview_backend", "") or "")
    command_template = _coerce_command_template(
        provider,
        llm_data.get("command_template", defaults.command_template),
        defaults.command_template,
    )
    return PseudoForgeConfig(
        llm=LlmConfig(
            enabled=bool(llm_data.get("enabled", False)),
            provider=provider,
            base_url=str(llm_data.get("base_url", defaults.base_url) or defaults.base_url),
            model=str(llm_data.get("model", defaults.model) or defaults.model),
            timeout_seconds=_coerce_timeout(llm_data.get("timeout_seconds", 60)),
            command_template=command_template,
            extra_headers=_coerce_string_map(llm_data.get("extra_headers", {})),
        ),
        profile_dir=str(data.get("profile_dir", "") or "") if isinstance(data, dict) else "",
        preview=PreviewConfig(backend=normalize_preview_backend(preview_backend)),
        credentials=credentials,
    )


def save_config(config: PseudoForgeConfig) -> Path:
    path = get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")
    return path


def masked_key(api_key: str) -> str:
    if not api_key:
        return "(not set)"
    if len(api_key) <= 8:
        return "*" * len(api_key)
    return api_key[:4] + "..." + api_key[-4:]


def get_provider_api_key(config: PseudoForgeConfig, provider: str) -> str:
    normalized = normalize_provider(provider)
    credential = config.credentials.get(normalized)
    if credential is None:
        return ""
    return credential.api_key


def set_provider_api_key(config: PseudoForgeConfig, provider: str, api_key: str) -> None:
    normalized = normalize_provider(provider)
    config.credentials[normalized] = ProviderCredential(api_key=api_key)


def normalize_preview_backend(value: object) -> str:
    normalized = str(value or "").strip().lower()
    return _PREVIEW_BACKEND_ALIASES.get(normalized, PREVIEW_BACKEND_SIMPLE)


def preview_backend_label(value: object) -> str:
    backend = normalize_preview_backend(value)
    if backend == PREVIEW_BACKEND_SIDE_BY_SIDE:
        return "Side-by-side dockable preview"
    return "Simple preview viewer"


def _coerce_timeout(value: object) -> int:
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        return 60
    return min(max(timeout, 5), 600)


def _coerce_string_map(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result = {}
    for key, item in value.items():
        result[str(key)] = str(item)
    return result


def _coerce_command_template(provider: str, value: object, default_value: str) -> str:
    template = str(value or default_value)
    if provider in {PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI, PROVIDER_CODEX_CLI}:
        if template in _OLD_CODEX_COMMAND_TEMPLATES:
            return default_value
    if provider in {PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI, PROVIDER_CLAUDE_CLI}:
        if template in _OLD_CLAUDE_COMMAND_TEMPLATES:
            return default_value
    return template


def _load_credentials(
    data: object,
    selected_provider: str,
    llm_data: dict[str, object],
) -> dict[str, ProviderCredential]:
    credentials: dict[str, ProviderCredential] = {}
    if isinstance(data, dict):
        raw_credentials = data.get("credentials", {})
        if isinstance(raw_credentials, dict):
            for provider, raw_credential in raw_credentials.items():
                normalized = normalize_provider(provider)
                if isinstance(raw_credential, dict):
                    api_key = str(raw_credential.get("api_key", ""))
                else:
                    api_key = str(raw_credential or "")
                if api_key:
                    credentials[normalized] = ProviderCredential(api_key=api_key)

    legacy_api_key = str(llm_data.get("api_key", ""))
    if legacy_api_key and selected_provider not in credentials:
        credentials[selected_provider] = ProviderCredential(api_key=legacy_api_key)
    return credentials

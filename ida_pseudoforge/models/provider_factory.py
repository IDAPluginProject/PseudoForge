from __future__ import annotations

import os

from ida_pseudoforge.config import LlmConfig
from ida_pseudoforge.models.base import RenameAssistProvider
from ida_pseudoforge.models.cli_provider import CliRenameProvider
from ida_pseudoforge.models.openai_compatible import OpenAICompatibleRenameProvider
from ida_pseudoforge.models.provider_registry import (
    LOCAL_OPENAI_COMPATIBLE_PROVIDERS,
    PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
    PROVIDER_CLAUDE_CLI,
    PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    PROVIDER_CODEX_CLI,
    PROVIDER_DEEPSEEK,
    PROVIDER_OPENAI_COMPATIBLE,
    PROVIDER_OPENROUTER,
    normalize_provider,
    provider_defaults,
)


_OPENAI_ENV_NAMES = {
    "api_key": ["PSEUDOFORGE_OPENAI_API_KEY", "OPENAI_API_KEY"],
    "base_url": ["PSEUDOFORGE_OPENAI_BASE_URL"],
    "model": ["PSEUDOFORGE_OPENAI_MODEL"],
}
_OPENROUTER_ENV_NAMES = {
    "api_key": ["PSEUDOFORGE_OPENROUTER_API_KEY", "OPENROUTER_API_KEY"],
    "base_url": ["PSEUDOFORGE_OPENROUTER_BASE_URL"],
    "model": ["PSEUDOFORGE_OPENROUTER_MODEL"],
}
_DEEPSEEK_ENV_NAMES = {
    "api_key": ["PSEUDOFORGE_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"],
    "base_url": ["PSEUDOFORGE_DEEPSEEK_BASE_URL"],
    "model": ["PSEUDOFORGE_DEEPSEEK_MODEL"],
}
_LOCAL_PROVIDER_ENV_NAMES = {
    "ollama": {
        "api_key": ["PSEUDOFORGE_OLLAMA_API_KEY", "OLLAMA_API_KEY"],
        "base_url": ["PSEUDOFORGE_OLLAMA_BASE_URL", "OLLAMA_BASE_URL"],
        "model": ["PSEUDOFORGE_OLLAMA_MODEL", "OLLAMA_MODEL"],
    },
    "lm_studio": {
        "api_key": ["PSEUDOFORGE_LM_STUDIO_API_KEY", "LM_STUDIO_API_KEY"],
        "base_url": ["PSEUDOFORGE_LM_STUDIO_BASE_URL", "LM_STUDIO_BASE_URL"],
        "model": ["PSEUDOFORGE_LM_STUDIO_MODEL", "LM_STUDIO_MODEL"],
    },
    "vllm": {
        "api_key": ["PSEUDOFORGE_VLLM_API_KEY", "VLLM_API_KEY"],
        "base_url": ["PSEUDOFORGE_VLLM_BASE_URL", "VLLM_BASE_URL"],
        "model": ["PSEUDOFORGE_VLLM_MODEL", "VLLM_MODEL"],
    },
    "llama_cpp": {
        "api_key": ["PSEUDOFORGE_LLAMA_CPP_API_KEY", "LLAMA_CPP_API_KEY"],
        "base_url": ["PSEUDOFORGE_LLAMA_CPP_BASE_URL", "LLAMA_CPP_BASE_URL"],
        "model": ["PSEUDOFORGE_LLAMA_CPP_MODEL", "LLAMA_CPP_MODEL"],
    },
}


def build_rename_provider(config: LlmConfig, api_key: str = "") -> RenameAssistProvider:
    provider = normalize_provider(config.provider)
    defaults = provider_defaults(provider)

    if provider == PROVIDER_OPENAI_COMPATIBLE:
        return OpenAICompatibleRenameProvider(
            api_key=api_key,
            base_url=_base_url_for_provider(config, provider, defaults.base_url, _OPENAI_ENV_NAMES["base_url"]),
            model=_model_for_provider(config, provider, defaults.model, _OPENAI_ENV_NAMES["model"]),
            timeout_seconds=config.timeout_seconds,
            extra_headers=config.extra_headers,
            api_key_env_vars=_OPENAI_ENV_NAMES["api_key"],
            base_url_env_vars=_OPENAI_ENV_NAMES["base_url"],
            model_env_vars=_OPENAI_ENV_NAMES["model"],
        )

    if provider == PROVIDER_OPENROUTER:
        headers = {"X-Title": "PseudoForge"}
        headers.update(config.extra_headers)
        return OpenAICompatibleRenameProvider(
            api_key=api_key,
            base_url=_base_url_for_provider(config, provider, defaults.base_url, _OPENROUTER_ENV_NAMES["base_url"]),
            model=_model_for_provider(config, provider, defaults.model, _OPENROUTER_ENV_NAMES["model"]),
            timeout_seconds=config.timeout_seconds,
            extra_headers=headers,
            api_key_env_vars=_OPENROUTER_ENV_NAMES["api_key"],
            base_url_env_vars=_OPENROUTER_ENV_NAMES["base_url"],
            model_env_vars=_OPENROUTER_ENV_NAMES["model"],
        )

    if provider == PROVIDER_DEEPSEEK:
        return OpenAICompatibleRenameProvider(
            api_key=api_key,
            base_url=_base_url_for_provider(config, provider, defaults.base_url, _DEEPSEEK_ENV_NAMES["base_url"]),
            model=_model_for_provider(config, provider, defaults.model, _DEEPSEEK_ENV_NAMES["model"]),
            timeout_seconds=config.timeout_seconds,
            extra_headers=config.extra_headers,
            api_key_env_vars=_DEEPSEEK_ENV_NAMES["api_key"],
            base_url_env_vars=_DEEPSEEK_ENV_NAMES["base_url"],
            model_env_vars=_DEEPSEEK_ENV_NAMES["model"],
        )

    if provider in LOCAL_OPENAI_COMPATIBLE_PROVIDERS:
        env_names = _LOCAL_PROVIDER_ENV_NAMES.get(provider, {})
        return OpenAICompatibleRenameProvider(
            api_key=api_key,
            base_url=_base_url_for_provider(config, provider, defaults.base_url, env_names.get("base_url", [])),
            model=_model_for_provider(config, provider, defaults.model, env_names.get("model", [])),
            timeout_seconds=config.timeout_seconds,
            extra_headers=config.extra_headers,
            api_key_env_vars=env_names.get("api_key", []),
            base_url_env_vars=env_names.get("base_url", []),
            model_env_vars=env_names.get("model", []),
            api_key_required=False,
            response_format={"type": "text"},
        )

    if provider in {
        PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
        PROVIDER_CODEX_CLI,
        PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
        PROVIDER_CLAUDE_CLI,
    }:
        return CliRenameProvider(
            command_template=config.command_template or defaults.command_template,
            timeout_seconds=config.timeout_seconds,
            model=_model_for_provider(config, provider, defaults.model),
        )

    raise RuntimeError(f"Unsupported LLM provider: {provider}")


def _base_url_for_provider(
    config: LlmConfig,
    provider: str,
    default_base_url: str,
    env_vars: list[str] | None = None,
) -> str:
    base_url = config.base_url
    openai_default = provider_defaults(PROVIDER_OPENAI_COMPATIBLE).base_url
    if not base_url:
        return _first_env(env_vars or []) or default_base_url
    if provider != PROVIDER_OPENAI_COMPATIBLE and base_url.rstrip("/") == openai_default:
        return _first_env(env_vars or []) or default_base_url
    return base_url


def _model_for_provider(
    config: LlmConfig,
    provider: str,
    default_model: str,
    env_vars: list[str] | None = None,
) -> str:
    model = config.model
    openai_default = provider_defaults(PROVIDER_OPENAI_COMPATIBLE).model
    if not model:
        return _first_env(env_vars or []) or default_model
    if provider != PROVIDER_OPENAI_COMPATIBLE and model == openai_default:
        return _first_env(env_vars or []) or default_model
    return model


def _first_env(names: list[str]) -> str:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return ""

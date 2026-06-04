from __future__ import annotations

from dataclasses import dataclass


PROVIDER_OPENAI_COMPATIBLE = "openai_compatible"
PROVIDER_OLLAMA = "ollama"
PROVIDER_LM_STUDIO = "lm_studio"
PROVIDER_VLLM = "vllm"
PROVIDER_LLAMA_CPP = "llama_cpp"
PROVIDER_OPENROUTER = "openrouter"
PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI = "chatgpt_oauth_via_codex_cli"
PROVIDER_CODEX_CLI = "codex_cli"
PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI = "claude_login_via_claude_cli"
PROVIDER_CLAUDE_CLI = "claude_cli"
PROVIDER_DEEPSEEK = "deepseek_api"

PROVIDER_ORDER = [
    PROVIDER_OPENAI_COMPATIBLE,
    PROVIDER_OLLAMA,
    PROVIDER_LM_STUDIO,
    PROVIDER_VLLM,
    PROVIDER_LLAMA_CPP,
    PROVIDER_OPENROUTER,
    PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
    PROVIDER_CODEX_CLI,
    PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    PROVIDER_CLAUDE_CLI,
    PROVIDER_DEEPSEEK,
]

PROVIDER_LABELS = {
    PROVIDER_OPENAI_COMPATIBLE: "OpenAI compatible",
    PROVIDER_OLLAMA: "Ollama",
    PROVIDER_LM_STUDIO: "LM Studio",
    PROVIDER_VLLM: "vLLM",
    PROVIDER_LLAMA_CPP: "llama.cpp",
    PROVIDER_OPENROUTER: "OpenRouter",
    PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI: "ChatGPT OAuth via Codex CLI",
    PROVIDER_CODEX_CLI: "Codex CLI",
    PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI: "Claude login via Claude CLI",
    PROVIDER_CLAUDE_CLI: "Claude CLI",
    PROVIDER_DEEPSEEK: "DeepSeek API",
}

HTTP_PROVIDERS = {
    PROVIDER_OPENAI_COMPATIBLE,
    PROVIDER_OLLAMA,
    PROVIDER_LM_STUDIO,
    PROVIDER_VLLM,
    PROVIDER_LLAMA_CPP,
    PROVIDER_OPENROUTER,
    PROVIDER_DEEPSEEK,
}

LOCAL_OPENAI_COMPATIBLE_PROVIDERS = {
    PROVIDER_OLLAMA,
    PROVIDER_LM_STUDIO,
    PROVIDER_VLLM,
    PROVIDER_LLAMA_CPP,
}

API_KEY_PROVIDERS = {
    PROVIDER_OPENAI_COMPATIBLE,
    PROVIDER_OPENROUTER,
    PROVIDER_DEEPSEEK,
}

CLI_PROVIDERS = {
    PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
    PROVIDER_CODEX_CLI,
    PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    PROVIDER_CLAUDE_CLI,
}


@dataclass(frozen=True, slots=True)
class ProviderDefaults:
    base_url: str = ""
    model: str = ""
    command_template: str = ""


_DEFAULTS = {
    PROVIDER_OPENAI_COMPATIBLE: ProviderDefaults(
        base_url="https://api.openai.com/v1",
        model="gpt-5-mini",
    ),
    PROVIDER_OLLAMA: ProviderDefaults(
        base_url="http://localhost:11434/v1",
        model="llama3.2",
    ),
    PROVIDER_LM_STUDIO: ProviderDefaults(
        base_url="http://localhost:1234/v1",
        model="local-model",
    ),
    PROVIDER_VLLM: ProviderDefaults(
        base_url="http://localhost:8000/v1",
        model="Qwen/Qwen2.5-1.5B-Instruct",
    ),
    PROVIDER_LLAMA_CPP: ProviderDefaults(
        base_url="http://localhost:8080/v1",
        model="local-model",
    ),
    PROVIDER_OPENROUTER: ProviderDefaults(
        base_url="https://openrouter.ai/api/v1",
        model="openrouter/auto",
    ),
    PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI: ProviderDefaults(
        model="gpt-5-mini",
        command_template=(
            "codex exec -m {model} --skip-git-repo-check --sandbox read-only "
            "--output-last-message {output_file} -"
        ),
    ),
    PROVIDER_CODEX_CLI: ProviderDefaults(
        model="gpt-5-mini",
        command_template=(
            "codex exec -m {model} --skip-git-repo-check --sandbox read-only "
            "--output-last-message {output_file} -"
        ),
    ),
    PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI: ProviderDefaults(
        model="claude-sonnet-4-6",
        command_template=(
            "claude -p --model {model} --permission-mode dontAsk --output-format text "
            "--no-session-persistence --tools \"\" --setting-sources project,local"
        ),
    ),
    PROVIDER_CLAUDE_CLI: ProviderDefaults(
        model="claude-sonnet-4-6",
        command_template=(
            "claude -p --model {model} --permission-mode dontAsk --output-format text "
            "--no-session-persistence --tools \"\" --setting-sources project,local"
        ),
    ),
    PROVIDER_DEEPSEEK: ProviderDefaults(
        base_url="https://api.deepseek.com",
        model="deepseek-v4-flash",
    ),
}

_MODEL_OPTIONS = {
    PROVIDER_OPENAI_COMPATIBLE: (
        "gpt-5.5",
        "gpt-5.4",
        "gpt-5.4-mini",
        "gpt-5.2",
        "gpt-5.1",
        "gpt-5",
        "gpt-5-mini",
        "gpt-5-nano",
        "gpt-4.1",
        "gpt-4.1-mini",
        "o4-mini",
        "o3",
    ),
    PROVIDER_OLLAMA: (
        "llama3.2",
        "gpt-oss:20b",
        "qwen2.5-coder",
        "mistral",
        "codellama",
    ),
    PROVIDER_LM_STUDIO: (
        "local-model",
    ),
    PROVIDER_VLLM: (
        "Qwen/Qwen2.5-1.5B-Instruct",
        "local-model",
        "Qwen/Qwen2.5-Coder-7B-Instruct",
        "meta-llama/Llama-3.1-8B-Instruct",
    ),
    PROVIDER_LLAMA_CPP: (
        "local-model",
    ),
    PROVIDER_OPENROUTER: (
        "openrouter/auto",
        "openai/gpt-5.5",
        "openai/gpt-5.4",
        "openai/gpt-5.2",
        "openai/gpt-5.1",
        "openai/gpt-5",
        "anthropic/claude-opus-4.8",
        "anthropic/claude-sonnet-4.6",
        "deepseek/deepseek-v4-flash",
        "deepseek/deepseek-v4-pro",
        "google/gemini-3-pro",
    ),
    PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI: (
        "gpt-5.5",
        "gpt-5.4",
        "gpt-5.4-mini",
        "gpt-5.3-codex",
        "gpt-5.3-codex-spark",
        "gpt-5.2",
        "gpt-5.1",
        "gpt-5",
        "gpt-5-mini",
        "gpt-5.2-codex",
        "gpt-5.1-codex",
        "gpt-5-codex",
    ),
    PROVIDER_CODEX_CLI: (
        "gpt-5.5",
        "gpt-5.4",
        "gpt-5.4-mini",
        "gpt-5.3-codex",
        "gpt-5.3-codex-spark",
        "gpt-5.2",
        "gpt-5.1",
        "gpt-5",
        "gpt-5-mini",
        "gpt-5.2-codex",
        "gpt-5.1-codex",
        "gpt-5-codex",
    ),
    PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI: (
        "claude-opus-4-8",
        "claude-sonnet-4-6",
        "claude-haiku-4-5",
        "sonnet",
        "opus",
    ),
    PROVIDER_CLAUDE_CLI: (
        "claude-opus-4-8",
        "claude-sonnet-4-6",
        "claude-haiku-4-5",
        "sonnet",
        "opus",
    ),
    PROVIDER_DEEPSEEK: (
        "deepseek-v4-flash",
        "deepseek-v4-pro",
    ),
}

_ALIASES = {
    "openai": PROVIDER_OPENAI_COMPATIBLE,
    "openai_compatible": PROVIDER_OPENAI_COMPATIBLE,
    "openai-compatible": PROVIDER_OPENAI_COMPATIBLE,
    "openai compatible": PROVIDER_OPENAI_COMPATIBLE,
    "openai 호환": PROVIDER_OPENAI_COMPATIBLE,
    "ollama": PROVIDER_OLLAMA,
    "ollama_local": PROVIDER_OLLAMA,
    "ollama-local": PROVIDER_OLLAMA,
    "ollama local": PROVIDER_OLLAMA,
    "lm_studio": PROVIDER_LM_STUDIO,
    "lm-studio": PROVIDER_LM_STUDIO,
    "lm studio": PROVIDER_LM_STUDIO,
    "lmstudio": PROVIDER_LM_STUDIO,
    "vllm": PROVIDER_VLLM,
    "vllm_openai": PROVIDER_VLLM,
    "vllm-openai": PROVIDER_VLLM,
    "vllm openai": PROVIDER_VLLM,
    "llama_cpp": PROVIDER_LLAMA_CPP,
    "llama-cpp": PROVIDER_LLAMA_CPP,
    "llama cpp": PROVIDER_LLAMA_CPP,
    "llama.cpp": PROVIDER_LLAMA_CPP,
    "llamacpp": PROVIDER_LLAMA_CPP,
    "openrouter": PROVIDER_OPENROUTER,
    "chatgpt_oauth_via_codex_cli": PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
    "chatgpt-oauth-via-codex-cli": PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
    "chatgpt oauth via codex cli": PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
    "codex": PROVIDER_CODEX_CLI,
    "codex_cli": PROVIDER_CODEX_CLI,
    "codex-cli": PROVIDER_CODEX_CLI,
    "codex cli": PROVIDER_CODEX_CLI,
    "claude_login_via_claude_cli": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude-login-via-claude-cli": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude login via claude cli": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude_login": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude-login": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude login": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude_cli_login": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude-cli-login": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude cli login": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude_code_login": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude-code-login": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude code login": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "anthropic_oauth_via_claude_cli": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "anthropic-oauth-via-claude-cli": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "anthropic oauth via claude cli": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    "claude": PROVIDER_CLAUDE_CLI,
    "claude_cli": PROVIDER_CLAUDE_CLI,
    "claude-cli": PROVIDER_CLAUDE_CLI,
    "claude cli": PROVIDER_CLAUDE_CLI,
    "deepseek": PROVIDER_DEEPSEEK,
    "deepseek_api": PROVIDER_DEEPSEEK,
    "deepseek-api": PROVIDER_DEEPSEEK,
    "deepseek api": PROVIDER_DEEPSEEK,
}


def normalize_provider(value: object) -> str:
    provider = str(value or PROVIDER_OPENAI_COMPATIBLE).strip().lower()
    return _ALIASES.get(provider, PROVIDER_OPENAI_COMPATIBLE)


def is_known_provider(value: object) -> bool:
    provider = str(value or "").strip().lower()
    return provider in _ALIASES


def provider_defaults(provider: object) -> ProviderDefaults:
    return _DEFAULTS[normalize_provider(provider)]


def provider_model_options(provider: object) -> tuple[str, ...]:
    normalized = normalize_provider(provider)
    return _MODEL_OPTIONS.get(normalized, (provider_defaults(normalized).model,))


def provider_label(provider: object) -> str:
    normalized = normalize_provider(provider)
    return PROVIDER_LABELS.get(normalized, normalized)


def provider_uses_http_settings(provider: object) -> bool:
    return normalize_provider(provider) in HTTP_PROVIDERS


def provider_requires_api_key(provider: object) -> bool:
    return normalize_provider(provider) in API_KEY_PROVIDERS


def provider_uses_cli_settings(provider: object) -> bool:
    return normalize_provider(provider) in CLI_PROVIDERS


def provider_choices_text() -> str:
    return ", ".join(PROVIDER_ORDER)

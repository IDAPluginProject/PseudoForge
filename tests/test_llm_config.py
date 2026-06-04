from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import unittest
from unittest.mock import patch

from ida_pseudoforge.config import (
    LlmConfig,
    PREVIEW_BACKEND_SIDE_BY_SIDE,
    ProviderCredential,
    PreviewConfig,
    PseudoForgeConfig,
    get_provider_api_key,
    load_config,
    save_config,
)
from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.llm_assist import parse_llm_rename_response, suggest_renames_with_provider
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.models.cli_provider import CliRenameProvider
from ida_pseudoforge.models.openai_compatible import OpenAICompatibleRenameProvider
from ida_pseudoforge.models.prompting import build_cli_rename_prompt
from ida_pseudoforge.models.provider_factory import build_rename_provider
from ida_pseudoforge.models.provider_registry import (
    PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
    PROVIDER_CLAUDE_CLI,
    PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    PROVIDER_CODEX_CLI,
    PROVIDER_DEEPSEEK,
    PROVIDER_LLAMA_CPP,
    PROVIDER_LM_STUDIO,
    PROVIDER_OLLAMA,
    PROVIDER_OPENROUTER,
    PROVIDER_VLLM,
    is_known_provider,
    normalize_provider,
    provider_defaults,
    provider_model_options,
    provider_requires_api_key,
    provider_uses_cli_settings,
    provider_uses_http_settings,
)


LLM_PLAN_SAMPLE = r"""
__int64 __fastcall LlmPlanSample(int a1)
{
  int v115;

  v115 = a1 + 1;
  return v115;
}
"""


LARGE_DISPATCHER_SAMPLE = (
    r"""
__int64 __fastcall LargeDispatcherSample(int a1)
{
  int v5;
  int v115;
  int ActiveProcessorCount;
  int v126;

  v5 = a1;
  v115 = v5 - 235;
  ActiveProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);
  v126 = 0;
"""
    + "\n".join(f"  if ( v5 == {index} )\n    return v5 + {index};" for index in range(50))
    + r"""
  return v115 + ActiveProcessorCount + v126;
}
"""
)


class _FakeHttpResponse:
    def __init__(self, payload: str) -> None:
        self._payload = payload.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self) -> bytes:
        return self._payload


class LlmConfigTests(unittest.TestCase):
    def test_config_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            try:
                config = PseudoForgeConfig(
                    llm=LlmConfig(
                        enabled=True,
                        provider=PROVIDER_OPENROUTER,
                        base_url="https://openrouter.example.invalid/v1",
                        model="openrouter-test-model",
                        timeout_seconds=42,
                        command_template="test command",
                        extra_headers={"X-Test": "1"},
                    ),
                    profile_dir=r"F:\profiles\wdk26100",
                    preview=PreviewConfig(backend=PREVIEW_BACKEND_SIDE_BY_SIDE),
                    credentials={
                        PROVIDER_OPENROUTER: ProviderCredential(api_key="sk-test"),
                    },
                )
                path = save_config(config)
                raw = json.loads(path.read_text(encoding="utf-8"))
                loaded = load_config()

                self.assertTrue(path.exists())
                self.assertNotIn("api_key", raw["llm"])
                self.assertEqual(raw["profile_dir"], r"F:\profiles\wdk26100")
                self.assertEqual(raw["preview"]["backend"], PREVIEW_BACKEND_SIDE_BY_SIDE)
                self.assertEqual(raw["credentials"][PROVIDER_OPENROUTER]["api_key"], "sk-test")
                self.assertTrue(loaded.llm.enabled)
                self.assertEqual(loaded.llm.provider, PROVIDER_OPENROUTER)
                self.assertEqual(loaded.profile_dir, r"F:\profiles\wdk26100")
                self.assertEqual(loaded.preview.backend, PREVIEW_BACKEND_SIDE_BY_SIDE)
                self.assertEqual(get_provider_api_key(loaded, PROVIDER_OPENROUTER), "sk-test")
                self.assertEqual(loaded.llm.base_url, "https://openrouter.example.invalid/v1")
                self.assertEqual(loaded.llm.model, "openrouter-test-model")
                self.assertEqual(loaded.llm.timeout_seconds, 42)
                self.assertEqual(loaded.llm.command_template, "test command")
                self.assertEqual(loaded.llm.extra_headers["X-Test"], "1")
            finally:
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_config_without_preview_settings_defaults_to_simple_preview(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            try:
                config_path = os.path.join(temp_dir, "pseudoforge_config.json")
                with open(config_path, "w", encoding="utf-8") as file:
                    json.dump({"llm": {"enabled": False}}, file)

                loaded = load_config()

                self.assertEqual(loaded.preview.backend, "simple")
            finally:
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_parse_llm_rename_response(self) -> None:
        suggestions, warnings = parse_llm_rename_response(
            """
            {
              "renames": [
                {
                  "old": "v3",
                  "new": "inputByteLength",
                  "confidence": 0.86,
                  "reason": "local stores a byte length"
                },
                {
                  "old": "v4",
                  "new": "bad-name",
                  "confidence": 0.65,
                  "reason": "too weak"
                }
              ],
              "warnings": ["review manually"]
            }
            """
        )

        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0].old, "v3")
        self.assertIn("low confidence", warnings[0])
        self.assertIn("review manually", warnings)

    def test_parse_fenced_llm_rename_response(self) -> None:
        suggestions, warnings = parse_llm_rename_response(
            """
            Here is the JSON:
            ```json
            {"renames":[{"old":"v3","new":"byteLength","confidence":0.9,"reason":"length"}]}
            ```
            """
        )

        self.assertFalse(warnings)
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0].new, "byteLength")

    def test_large_dispatcher_llm_raises_confidence_floor_and_hides_low_confidence_warnings(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "v115",
                                "new": "classMinus235",
                                "confidence": 0.82,
                                "reason": "dispatcher delta",
                            },
                            {
                                "old": "ActiveProcessorCount",
                                "new": "activeProcessorCount",
                                "confidence": 0.98,
                                "reason": "processor count result",
                            },
                        ]
                    }
                )

        capture = capture_from_pseudocode(LARGE_DISPATCHER_SAMPLE)
        suggestions, warnings = suggest_renames_with_provider(capture, FakeProvider())
        rename_map = {item.old: item.new for item in suggestions if item.apply}

        self.assertNotIn("v115", rename_map)
        self.assertEqual(rename_map["ActiveProcessorCount"], "activeProcessorCount")
        self.assertFalse(any("low confidence" in warning.lower() for warning in warnings))

    def test_parse_dict_warning_message(self) -> None:
        suggestions, warnings = parse_llm_rename_response(
            """
            {
              "renames": [],
              "warnings": [
                {"message": "review import recovery"},
                {"old": "BadReferenceName", "reason": "paired release routine differs"}
              ]
            }
            """
        )

        self.assertFalse(suggestions)
        self.assertEqual(
            warnings,
            [
                "review import recovery",
                "Potential bad call target BadReferenceName: paired release routine differs",
            ],
        )

    def test_rendered_comment_text_is_ascii_safe(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [],
                        "warnings": [
                            {"message": "한글 warning"}
                        ],
                    },
                    ensure_ascii=False,
                )

        capture = capture_from_pseudocode(LLM_PLAN_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("한글", rendered)
        self.assertIn("\\ud55c\\uae00 warning", rendered)

    def test_build_plan_with_llm_provider(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return '{"renames":[{"old":"v115","new":"bootPagesDelta","confidence":0.86,"reason":"case arithmetic"}]}'

        capture = capture_from_pseudocode(LLM_PLAN_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual(rename_map["v115"], "bootPagesDelta")

    def test_cli_provider_reads_stdout(self) -> None:
        command = subprocess.list2cmdline(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdin.read(); print('{\"renames\": []}')",
            ]
        )
        capture = capture_from_pseudocode(LLM_PLAN_SAMPLE)
        provider = CliRenameProvider(command_template=command, timeout_seconds=10)

        self.assertEqual(provider.suggest_renames(capture).strip(), '{"renames": []}')

    def test_cli_rename_prompt_is_defensive_and_rename_only(self) -> None:
        prompt = build_cli_rename_prompt(capture_from_pseudocode(LLM_PLAN_SAMPLE))

        self.assertIn("defensive static-code readability assistant", prompt)
        self.assertIn("Your only task is to suggest clearer local variable and argument names", prompt)
        self.assertIn("Do not rewrite code", prompt)
        self.assertIn("do not provide bypass, evasion, persistence, exploitation", prompt)
        self.assertIn("Return only a JSON object", prompt)

    def test_provider_factory_openrouter(self) -> None:
        provider = build_rename_provider(
            LlmConfig(
                enabled=True,
                provider=PROVIDER_OPENROUTER,
                model="test-model",
            ),
            api_key="sk-test",
        )

        self.assertEqual(provider.base_url, "https://openrouter.ai/api/v1")
        self.assertEqual(provider.model, "test-model")
        self.assertEqual(provider.extra_headers["X-Title"], "PseudoForge")
        self.assertEqual(provider.response_format, {"type": "json_object"})

    def test_local_openai_compatible_provider_defaults_do_not_require_api_key(self) -> None:
        expected = {
            PROVIDER_OLLAMA: ("http://localhost:11434/v1", "llama3.2"),
            PROVIDER_LM_STUDIO: ("http://localhost:1234/v1", "local-model"),
            PROVIDER_VLLM: ("http://localhost:8000/v1", "Qwen/Qwen2.5-1.5B-Instruct"),
            PROVIDER_LLAMA_CPP: ("http://localhost:8080/v1", "local-model"),
        }

        for provider_id, (base_url, model) in expected.items():
            with self.subTest(provider=provider_id):
                provider = build_rename_provider(LlmConfig(enabled=True, provider=provider_id))

                self.assertEqual(provider.base_url, base_url)
                self.assertEqual(provider.model, model)
                self.assertEqual(provider.api_key, "")
                self.assertFalse(provider.api_key_required)
                self.assertTrue(provider_uses_http_settings(provider_id))
                self.assertFalse(provider_requires_api_key(provider_id))
                self.assertFalse(provider_uses_cli_settings(provider_id))

    def test_local_openai_compatible_provider_reads_environment_defaults(self) -> None:
        old_base_url = os.environ.get("PSEUDOFORGE_OLLAMA_BASE_URL")
        old_model = os.environ.get("PSEUDOFORGE_OLLAMA_MODEL")
        os.environ["PSEUDOFORGE_OLLAMA_BASE_URL"] = "http://127.0.0.1:11435/v1"
        os.environ["PSEUDOFORGE_OLLAMA_MODEL"] = "qwen2.5-coder"
        try:
            provider = build_rename_provider(
                LlmConfig(
                    enabled=True,
                    provider=PROVIDER_OLLAMA,
                    base_url="",
                    model="",
                )
            )
        finally:
            if old_base_url is None:
                os.environ.pop("PSEUDOFORGE_OLLAMA_BASE_URL", None)
            else:
                os.environ["PSEUDOFORGE_OLLAMA_BASE_URL"] = old_base_url
            if old_model is None:
                os.environ.pop("PSEUDOFORGE_OLLAMA_MODEL", None)
            else:
                os.environ["PSEUDOFORGE_OLLAMA_MODEL"] = old_model

        self.assertEqual(provider.base_url, "http://127.0.0.1:11435/v1")
        self.assertEqual(provider.model, "qwen2.5-coder")

    def test_explicit_empty_provider_env_lists_do_not_inherit_openai_environment(self) -> None:
        old_api_key = os.environ.get("OPENAI_API_KEY")
        old_base_url = os.environ.get("PSEUDOFORGE_OPENAI_BASE_URL")
        old_model = os.environ.get("PSEUDOFORGE_OPENAI_MODEL")
        os.environ["OPENAI_API_KEY"] = "sk-openai-test"
        os.environ["PSEUDOFORGE_OPENAI_BASE_URL"] = "https://openai-env.example/v1"
        os.environ["PSEUDOFORGE_OPENAI_MODEL"] = "openai-env-model"
        try:
            provider = OpenAICompatibleRenameProvider(
                api_key_env_vars=[],
                base_url_env_vars=[],
                model_env_vars=[],
                api_key_required=False,
            )
        finally:
            if old_api_key is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = old_api_key
            if old_base_url is None:
                os.environ.pop("PSEUDOFORGE_OPENAI_BASE_URL", None)
            else:
                os.environ["PSEUDOFORGE_OPENAI_BASE_URL"] = old_base_url
            if old_model is None:
                os.environ.pop("PSEUDOFORGE_OPENAI_MODEL", None)
            else:
                os.environ["PSEUDOFORGE_OPENAI_MODEL"] = old_model

        self.assertEqual(provider.api_key, "")
        self.assertEqual(provider.base_url, "https://api.openai.com/v1")
        self.assertEqual(provider.model, "gpt-5-mini")

    def test_local_openai_compatible_request_omits_authorization_without_api_key(self) -> None:
        provider = build_rename_provider(
            LlmConfig(
                enabled=True,
                provider=PROVIDER_OLLAMA,
                model="llama3.2",
            )
        )

        with patch(
            "ida_pseudoforge.models.openai_compatible.urllib.request.urlopen",
            return_value=_FakeHttpResponse('{"choices":[{"message":{"content":"{\\"renames\\":[]}"}}]}'),
        ) as urlopen:
            content = provider.suggest_renames(capture_from_pseudocode(LLM_PLAN_SAMPLE))

        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(content, '{"renames":[]}')
        self.assertEqual(request.full_url, "http://localhost:11434/v1/chat/completions")
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(payload["response_format"], {"type": "text"})

    def test_lm_studio_request_uses_text_response_format_for_local_model_compatibility(self) -> None:
        provider = build_rename_provider(
            LlmConfig(
                enabled=True,
                provider=PROVIDER_LM_STUDIO,
                base_url="http://192.168.1.28:1234/v1",
                model="google/gemma-4-12b",
            )
        )

        with patch(
            "ida_pseudoforge.models.openai_compatible.urllib.request.urlopen",
            return_value=_FakeHttpResponse('{"choices":[{"message":{"content":"{\\"renames\\":[]}"}}]}'),
        ) as urlopen:
            content = provider.suggest_renames(capture_from_pseudocode(LLM_PLAN_SAMPLE))

        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(content, '{"renames":[]}')
        self.assertEqual(request.full_url, "http://192.168.1.28:1234/v1/chat/completions")
        self.assertEqual(payload["model"], "google/gemma-4-12b")
        self.assertEqual(payload["response_format"], {"type": "text"})

    def test_openai_compatible_retries_text_response_format_when_server_rejects_json_object(self) -> None:
        provider = OpenAICompatibleRenameProvider(
            api_key="",
            base_url="http://local.example/v1",
            model="google/gemma-4-12b",
            api_key_required=False,
        )
        rejection = urllib.error.HTTPError(
            "http://local.example/v1/chat/completions",
            400,
            "Bad Request",
            {},
            io.BytesIO(b'{"error":"response_format.type must be json_schema or text"}'),
        )

        with patch(
            "ida_pseudoforge.models.openai_compatible.urllib.request.urlopen",
            side_effect=[
                rejection,
                _FakeHttpResponse('{"choices":[{"message":{"content":"{\\"renames\\":[]}"}}]}'),
            ],
        ) as urlopen:
            content = provider.suggest_renames(capture_from_pseudocode(LLM_PLAN_SAMPLE))

        first_request = urlopen.call_args_list[0].args[0]
        second_request = urlopen.call_args_list[1].args[0]
        first_payload = json.loads(first_request.data.decode("utf-8"))
        second_payload = json.loads(second_request.data.decode("utf-8"))
        self.assertEqual(content, '{"renames":[]}')
        self.assertEqual(urlopen.call_count, 2)
        self.assertEqual(first_payload["response_format"], {"type": "json_object"})
        self.assertEqual(second_payload["response_format"], {"type": "text"})

    def test_cloud_openai_compatible_provider_still_requires_api_key(self) -> None:
        provider = build_rename_provider(LlmConfig(enabled=True, provider="openai_compatible"))

        with self.assertRaisesRegex(RuntimeError, "No API key configured"):
            provider.suggest_renames(capture_from_pseudocode(LLM_PLAN_SAMPLE))

    def test_chatgpt_oauth_old_alias_is_not_accepted(self) -> None:
        self.assertFalse(is_known_provider("chatgpt_oauth"))
        self.assertEqual(
            normalize_provider("chatgpt_oauth_via_codex_cli"),
            PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
        )

    def test_claude_login_aliases_are_accepted(self) -> None:
        self.assertEqual(
            normalize_provider("claude_login_via_claude_cli"),
            PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
        )
        self.assertEqual(
            normalize_provider("claude cli login"),
            PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
        )
        self.assertTrue(is_known_provider("claude-code-login"))

    def test_local_provider_aliases_are_accepted(self) -> None:
        self.assertEqual(normalize_provider("ollama-local"), PROVIDER_OLLAMA)
        self.assertEqual(normalize_provider("lm studio"), PROVIDER_LM_STUDIO)
        self.assertEqual(normalize_provider("vllm-openai"), PROVIDER_VLLM)
        self.assertEqual(normalize_provider("llama.cpp"), PROVIDER_LLAMA_CPP)
        self.assertTrue(is_known_provider("llamacpp"))

    def test_provider_model_options(self) -> None:
        openrouter_models = provider_model_options(PROVIDER_OPENROUTER)
        self.assertIn("openrouter/auto", openrouter_models)
        self.assertIn("anthropic/claude-opus-4.8", openrouter_models)
        self.assertNotIn("anthropic/claude-opus-4.6", openrouter_models)
        self.assertIn("deepseek-v4-flash", provider_model_options(PROVIDER_DEEPSEEK))
        self.assertIn("llama3.2", provider_model_options(PROVIDER_OLLAMA))
        self.assertIn("local-model", provider_model_options(PROVIDER_LM_STUDIO))
        self.assertIn("Qwen/Qwen2.5-1.5B-Instruct", provider_model_options(PROVIDER_VLLM))
        self.assertIn("local-model", provider_model_options(PROVIDER_LLAMA_CPP))
        self.assertIn(
            "gpt-5.5",
            provider_model_options(PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI),
        )
        claude_models = provider_model_options(PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI)
        self.assertEqual(claude_models[0], "claude-opus-4-8")
        self.assertIn("claude-sonnet-4-6", claude_models)
        self.assertIn("claude-haiku-4-5", claude_models)
        self.assertIn("sonnet", claude_models)
        self.assertNotIn("claude-opus-4.6", claude_models)

    def test_cli_provider_defaults_pass_selected_model(self) -> None:
        for provider in (
            PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
            PROVIDER_CODEX_CLI,
            PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
            PROVIDER_CLAUDE_CLI,
        ):
            command_template = provider_defaults(provider).command_template
            self.assertIn("{model}", command_template)
            self.assertNotIn("--ask-for-approval", command_template)

    def test_claude_cli_defaults_disable_tools_and_session_persistence(self) -> None:
        for provider in (PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI, PROVIDER_CLAUDE_CLI):
            command_template = provider_defaults(provider).command_template

            self.assertIn("--no-session-persistence", command_template)
            self.assertIn('--tools ""', command_template)
            self.assertIn("--setting-sources project,local", command_template)

    def test_old_codex_command_template_is_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            try:
                config_path = os.path.join(temp_dir, "pseudoforge_config.json")
                with open(config_path, "w", encoding="utf-8") as file:
                    json.dump(
                        {
                            "llm": {
                                "enabled": True,
                                "provider": PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
                                "model": "gpt-5.5",
                                "command_template": (
                                    "codex exec --skip-git-repo-check --sandbox read-only "
                                    "--ask-for-approval never --output-last-message {output_file} -"
                                ),
                            },
                            "credentials": {},
                        },
                        file,
                    )

                loaded = load_config()

                self.assertIn("{model}", loaded.llm.command_template)
                self.assertNotIn("--ask-for-approval", loaded.llm.command_template)
                self.assertEqual(loaded.llm.model, "gpt-5.5")
            finally:
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_invalid_codex_command_template_is_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            try:
                config_path = os.path.join(temp_dir, "pseudoforge_config.json")
                with open(config_path, "w", encoding="utf-8") as file:
                    json.dump(
                        {
                            "llm": {
                                "enabled": True,
                                "provider": PROVIDER_CODEX_CLI,
                                "model": "gpt-5.5",
                                "command_template": (
                                    "codex exec -m {model} --skip-git-repo-check "
                                    "--sandbox read-only --ask-for-approval never "
                                    "--output-last-message {output_file} -"
                                ),
                            },
                            "credentials": {},
                        },
                        file,
                    )

                loaded = load_config()

                self.assertIn("{model}", loaded.llm.command_template)
                self.assertNotIn("--ask-for-approval", loaded.llm.command_template)
                self.assertEqual(loaded.llm.provider, PROVIDER_CODEX_CLI)
            finally:
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_old_claude_command_template_is_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            try:
                config_path = os.path.join(temp_dir, "pseudoforge_config.json")
                with open(config_path, "w", encoding="utf-8") as file:
                    json.dump(
                        {
                            "llm": {
                                "enabled": True,
                                "provider": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
                                "model": "sonnet",
                                "command_template": (
                                    "claude -p --model {model} --permission-mode dontAsk "
                                    "--output-format text"
                                ),
                            },
                            "credentials": {},
                        },
                        file,
                    )

                loaded = load_config()

                self.assertEqual(loaded.llm.provider, PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI)
                self.assertIn("{model}", loaded.llm.command_template)
                self.assertIn("--no-session-persistence", loaded.llm.command_template)
                self.assertIn('--tools ""', loaded.llm.command_template)
                self.assertIn("--setting-sources project,local", loaded.llm.command_template)
            finally:
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_claude_command_template_without_setting_sources_is_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            try:
                config_path = os.path.join(temp_dir, "pseudoforge_config.json")
                with open(config_path, "w", encoding="utf-8") as file:
                    json.dump(
                        {
                            "llm": {
                                "enabled": True,
                                "provider": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
                                "model": "claude-opus-4-8",
                                "command_template": (
                                    "claude -p --model {model} --permission-mode dontAsk "
                                    "--output-format text --no-session-persistence --tools \"\""
                                ),
                            },
                            "credentials": {},
                        },
                        file,
                    )

                loaded = load_config()

                self.assertEqual(loaded.llm.model, "claude-opus-4-8")
                self.assertIn("--setting-sources project,local", loaded.llm.command_template)
            finally:
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir


if __name__ == "__main__":
    unittest.main()

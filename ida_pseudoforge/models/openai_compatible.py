from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from ida_pseudoforge.core.plan_schema import FunctionCapture
from ida_pseudoforge.logging import log_event
from ida_pseudoforge.models.prompting import SYSTEM_RENAME_PROMPT, build_rename_prompt


class OpenAICompatibleRenameProvider:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: int = 60,
        extra_headers: dict[str, str] | None = None,
        api_key_env_vars: list[str] | None = None,
        base_url_env_vars: list[str] | None = None,
        model_env_vars: list[str] | None = None,
        api_key_required: bool = True,
        response_format: dict[str, object] | None = None,
    ) -> None:
        self.api_key = api_key or _first_env(
            _env_names(api_key_env_vars, ["PSEUDOFORGE_OPENAI_API_KEY", "OPENAI_API_KEY"])
        )
        self.base_url = (
            base_url
            or _first_env(_env_names(base_url_env_vars, ["PSEUDOFORGE_OPENAI_BASE_URL"]))
            or "https://api.openai.com/v1"
        ).rstrip("/")
        self.model = model or _first_env(_env_names(model_env_vars, ["PSEUDOFORGE_OPENAI_MODEL"])) or "gpt-5-mini"
        self.timeout_seconds = timeout_seconds
        self.extra_headers = extra_headers or {}
        self.api_key_required = api_key_required
        self.response_format = response_format if response_format is not None else {"type": "json_object"}

    def suggest_renames(self, capture: FunctionCapture) -> str:
        return self.complete(
            SYSTEM_RENAME_PROMPT,
            build_rename_prompt(capture),
            response_format=self.response_format,
            task_name=capture.name or "rename",
        )

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: dict[str, object] | None = None,
        task_name: str = "text",
    ) -> str:
        if self.api_key_required and not self.api_key:
            raise RuntimeError("No API key configured for OpenAI-compatible provider")

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
        }
        effective_response_format = self.response_format if response_format is None else response_format
        if effective_response_format:
            payload["response_format"] = effective_response_format

        log_event(
            "llm.http.start task=\"%s\" model=\"%s\" base_url=\"%s\""
            % (_ascii_for_log(task_name), _ascii_for_log(self.model), _ascii_for_log(self.base_url))
        )
        try:
            data = self._post_chat_completion(payload)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            if _should_retry_with_text_response_format(exc.code, detail, effective_response_format):
                log_event(
                    "llm.http.retry_text_response_format task=\"%s\" model=\"%s\""
                    % (_ascii_for_log(task_name), _ascii_for_log(self.model))
                )
                retry_payload = dict(payload)
                retry_payload["response_format"] = {"type": "text"}
                try:
                    data = self._post_chat_completion(retry_payload)
                except urllib.error.HTTPError as retry_exc:
                    retry_detail = retry_exc.read().decode("utf-8", errors="replace")
                    log_event(
                        "llm.http.failed task=\"%s\" model=\"%s\" http=%d"
                        % (_ascii_for_log(task_name), _ascii_for_log(self.model), retry_exc.code)
                    )
                    raise RuntimeError(
                        f"LLM request failed: HTTP {retry_exc.code}: {retry_detail}"
                    ) from retry_exc
            else:
                log_event(
                    "llm.http.failed task=\"%s\" model=\"%s\" http=%d"
                    % (_ascii_for_log(task_name), _ascii_for_log(self.model), exc.code)
                )
                raise RuntimeError(f"LLM request failed: HTTP {exc.code}: {detail}") from exc

        try:
            content = data["choices"][0]["message"]["content"] or "{}"
            log_event(
                "llm.http.done task=\"%s\" model=\"%s\" output_chars=%d"
                % (_ascii_for_log(task_name), _ascii_for_log(self.model), len(content))
            )
            return content
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("LLM response did not contain message content") from exc

    def _post_chat_completion(self, payload: dict[str, object]) -> dict[str, object]:
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.update(self.extra_headers)

        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))


def _should_retry_with_text_response_format(
    status_code: int,
    detail: str,
    response_format: dict[str, object] | None,
) -> bool:
    if status_code != 400:
        return False
    if response_format and str(response_format.get("type", "")).lower() == "text":
        return False
    lowered = (detail or "").lower()
    return "response_format" in lowered and "text" in lowered


def _first_env(names: list[str]) -> str:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return ""


def _env_names(names: list[str] | None, defaults: list[str]) -> list[str]:
    if names is None:
        return defaults
    return names


def _ascii_for_log(value: str) -> str:
    return value.encode("ascii", errors="replace").decode("ascii")

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ida_pseudoforge.core.plan_schema import FunctionCapture


SCHEMA = "pseudoforge_llm_candidate_cache_v1"


class LlmCandidateRecordingProvider:
    def __init__(
        self,
        inner: Any,
        cache_dir: str | Path,
        provider_info: dict[str, Any] | None = None,
    ) -> None:
        self.inner = inner
        self.cache_dir = Path(cache_dir)
        self.provider_info = dict(provider_info or {})
        self.last_candidate_cache_path = ""
        self.strict_replay = bool(getattr(inner, "strict_replay", False))

    def suggest_renames(self, capture: FunctionCapture) -> str:
        raw_response = self.inner.suggest_renames(capture)
        cache_path = write_llm_candidate_cache(
            self.cache_dir,
            capture,
            raw_response,
            provider_info=self.provider_info,
        )
        self.last_candidate_cache_path = str(cache_path)
        return raw_response

    @property
    def last_candidate_replay_path(self) -> str:
        return str(getattr(self.inner, "last_candidate_replay_path", "") or "")


class LlmCandidateReplayProvider:
    strict_replay = True

    def __init__(self, replay_dir: str | Path) -> None:
        self.replay_dir = Path(replay_dir)
        self.last_candidate_replay_path = ""
        self.last_candidate_cache_path = ""

    def suggest_renames(self, capture: FunctionCapture) -> str:
        cache_path = find_llm_candidate_cache(self.replay_dir, capture)
        if cache_path is None:
            raise FileNotFoundError(
                "LLM candidate replay cache was not found for %s 0x%X fingerprint=%s"
                % (capture.name or "function", capture.ea, capture.input_fingerprint()[:16])
            )
        self.last_candidate_replay_path = str(cache_path)
        return read_llm_candidate_response(cache_path)


def write_llm_candidate_cache(
    cache_dir: str | Path,
    capture: FunctionCapture,
    raw_response: str,
    provider_info: dict[str, Any] | None = None,
) -> Path:
    output_dir = Path(cache_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_path = llm_candidate_cache_path(output_dir, capture)
    payload = {
        "schema": SCHEMA,
        "created_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "function": capture.name,
        "function_ea": "0x%X" % capture.ea,
        "input_fingerprint": capture.input_fingerprint(),
        "provider": dict(provider_info or {}),
        "raw_response": str(raw_response or ""),
    }
    cache_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    return cache_path


def read_llm_candidate_response(cache_path: str | Path) -> str:
    path = Path(cache_path)
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return text
    if isinstance(payload, dict) and payload.get("schema") == SCHEMA:
        return str(payload.get("raw_response", "") or "")
    if isinstance(payload, dict) and "renames" in payload:
        return text
    return str(payload.get("raw_response", text)) if isinstance(payload, dict) else text


def find_llm_candidate_cache(cache_dir: str | Path, capture: FunctionCapture) -> Path | None:
    root = Path(cache_dir)
    exact = llm_candidate_cache_path(root, capture)
    if exact.exists():
        return exact
    ea_text = "%016X" % int(capture.ea or 0)
    name_text = _safe_file_stem(capture.name or "function")
    matches = sorted(root.glob("%s_%s_*.llm-renames.json" % (ea_text, name_text)))
    if len(matches) == 1:
        return matches[0]
    return None


def llm_candidate_cache_path(cache_dir: str | Path, capture: FunctionCapture) -> Path:
    fingerprint = capture.input_fingerprint()[:16]
    stem = "%016X_%s_%s" % (
        int(capture.ea or 0),
        _safe_file_stem(capture.name or "function"),
        fingerprint,
    )
    return Path(cache_dir) / ("%s.llm-renames.json" % stem)


def _safe_file_stem(value: str) -> str:
    cleaned = "".join(char if char.isascii() and (char.isalnum() or char in "._-") else "_" for char in value)
    return cleaned.strip("._") or "function"

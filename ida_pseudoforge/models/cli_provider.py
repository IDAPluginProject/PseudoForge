from __future__ import annotations

import ctypes
import os
import shlex
import subprocess
import tempfile
from ctypes import wintypes
from pathlib import Path

from ida_pseudoforge.core.plan_schema import FunctionCapture
from ida_pseudoforge.logging import log_event
from ida_pseudoforge.models.prompting import build_cli_rename_prompt
from ida_pseudoforge.models.subprocess_utils import hidden_subprocess_kwargs


class CliRenameProvider:
    def __init__(
        self,
        command_template: str,
        timeout_seconds: int = 120,
        model: str = "",
    ) -> None:
        self.command_template = command_template.strip()
        self.raw_shell = False
        for prefix in ("raw-shell:", "shell:"):
            if self.command_template.lower().startswith(prefix):
                self.command_template = self.command_template[len(prefix) :].strip()
                self.raw_shell = True
                break
        self.timeout_seconds = timeout_seconds
        self.model = model

    def suggest_renames(self, capture: FunctionCapture) -> str:
        return self.complete(build_cli_rename_prompt(capture), task_name="rename")

    def complete(
        self,
        system_prompt: str,
        user_prompt: str = "",
        response_format: dict[str, object] | None = None,
        task_name: str = "text",
    ) -> str:
        if not self.command_template:
            raise RuntimeError("No command template configured for CLI provider")

        del response_format
        prompt = system_prompt
        if user_prompt:
            prompt = system_prompt.rstrip() + "\n\n" + user_prompt
        with tempfile.TemporaryDirectory(prefix="pseudoforge_llm_") as temp_dir_text:
            temp_dir = Path(temp_dir_text)
            prompt_file = temp_dir / "prompt.txt"
            output_file = temp_dir / "response.txt"
            prompt_file.write_text(prompt, encoding="utf-8")

            command = self._render_command(prompt_file, output_file)
            log_event(
                "llm.cli.start task=\"%s\" model=\"%s\" prompt_file=\"%s\" output_file=\"%s\""
                % (
                    _ascii_for_log(task_name),
                    _ascii_for_log(self.model),
                    _ascii_for_log(str(prompt_file)),
                    _ascii_for_log(str(output_file)),
                )
            )
            result = subprocess.run(
                command,
                shell=self.raw_shell,
                input=prompt,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                **hidden_subprocess_kwargs(),
            )

            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                log_event(
                    "llm.cli.failed task=\"%s\" model=\"%s\" exit=%d"
                    % (_ascii_for_log(task_name), _ascii_for_log(self.model), result.returncode)
                )
                raise RuntimeError(f"CLI provider failed with exit {result.returncode}: {detail}")

            if "{output_file}" in self.command_template and output_file.exists():
                output = output_file.read_text(encoding="utf-8", errors="replace")
                if output.strip():
                    log_event(
                        "llm.cli.done task=\"%s\" model=\"%s\" output_chars=%d source=output_file"
                        % (_ascii_for_log(task_name), _ascii_for_log(self.model), len(output))
                    )
                    return output

            output = result.stdout or "{}"
            log_event(
                "llm.cli.done task=\"%s\" model=\"%s\" output_chars=%d source=stdout"
                % (_ascii_for_log(task_name), _ascii_for_log(self.model), len(output))
            )
            return output

    def _render_command(self, prompt_file: Path, output_file: Path) -> list[str] | str:
        if self.raw_shell:
            return self._render_shell_command(prompt_file, output_file)
        return self._render_argv_command(prompt_file, output_file)

    def _render_argv_command(self, prompt_file: Path, output_file: Path) -> list[str]:
        tokens = _split_command_template(self.command_template)
        replacements = {
            "{prompt_file}": str(prompt_file),
            "{output_file}": str(output_file),
            "{model}": self.model,
        }
        rendered = []
        for token in tokens:
            updated = token
            for needle, value in replacements.items():
                updated = updated.replace(needle, value)
            rendered.append(updated)
        return rendered

    def _render_shell_command(self, prompt_file: Path, output_file: Path) -> str:
        command = self.command_template
        replacements = {
            "{prompt_file}": _quote_shell_value(str(prompt_file)),
            "{output_file}": _quote_shell_value(str(output_file)),
            "{model}": _quote_shell_value(self.model),
        }
        for needle, value in replacements.items():
            command = command.replace(needle, value)
        return command


def _split_command_template(command_template: str) -> list[str]:
    if os.name == "nt":
        return _windows_command_line_to_argv(command_template)
    return shlex.split(command_template)


def _windows_command_line_to_argv(command_template: str) -> list[str]:
    if not command_template.strip():
        return []
    argc = ctypes.c_int()
    command_line_to_argv = ctypes.windll.shell32.CommandLineToArgvW
    command_line_to_argv.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    command_line_to_argv.restype = ctypes.POINTER(wintypes.LPWSTR)
    local_free = ctypes.windll.kernel32.LocalFree
    local_free.restype = wintypes.HLOCAL
    argv = command_line_to_argv(command_template, ctypes.byref(argc))
    if not argv:
        return shlex.split(command_template, posix=False)
    try:
        return [argv[index] for index in range(argc.value)]
    finally:
        local_free(argv)


def _quote_shell_value(value: str) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline([value])
    return shlex.quote(value)


def _ascii_for_log(value: str) -> str:
    return value.encode("ascii", errors="replace").decode("ascii")

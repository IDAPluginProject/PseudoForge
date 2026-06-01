from __future__ import annotations

import os
from copy import deepcopy

from ida_pseudoforge.config import (
    PREVIEW_BACKEND_SIMPLE,
    PREVIEW_BACKEND_SIDE_BY_SIDE,
    PreviewConfig,
    PseudoForgeConfig,
    normalize_preview_backend,
    preview_backend_label,
)

try:
    import ida_kernwin  # type: ignore
except Exception:
    ida_kernwin = None


_PREVIEW_BACKENDS = [
    PREVIEW_BACKEND_SIMPLE,
    PREVIEW_BACKEND_SIDE_BY_SIDE,
]
_PREVIEW_BACKEND_ENV = "PSEUDOFORGE_PREVIEW_BACKEND"


def ask_preview_config(current_config: PseudoForgeConfig, warn) -> PseudoForgeConfig | None:
    if ida_kernwin is None:
        return current_config

    updated_config = deepcopy(current_config)
    selected = ask_preview_backend(updated_config.preview.backend, warn)
    if selected is None:
        return None

    updated_config.preview = PreviewConfig(backend=selected)
    return updated_config


def ask_preview_backend(current_backend: str, warn) -> str | None:
    current = normalize_preview_backend(current_backend)
    choices = [preview_backend_label(backend) for backend in _PREVIEW_BACKENDS]
    try:
        selected_index = _PREVIEW_BACKENDS.index(current)
    except ValueError:
        selected_index = 0

    form = None
    try:
        form = ida_kernwin.Form(
            r"""BUTTON YES* OK
BUTTON CANCEL Cancel
PseudoForge preview mode

<Preview mode:{backend}>
""",
            {
                "backend": ida_kernwin.Form.DropdownListControl(
                    items=choices,
                    readonly=True,
                    selval=selected_index,
                    swidth=54,
                ),
            },
        )
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            return None

        selected = int(form.backend.value)
        if selected < 0 or selected >= len(_PREVIEW_BACKENDS):
            warn("Invalid PseudoForge preview mode selection.")
            return None
        return _PREVIEW_BACKENDS[selected]
    finally:
        if form is not None:
            try:
                form.Free()
            except Exception:
                pass


def format_preview_summary(config: PreviewConfig) -> str:
    backend = normalize_preview_backend(config.backend)
    lines = [
        "Preview mode: %s" % preview_backend_label(backend),
    ]
    env_backend = os.environ.get(_PREVIEW_BACKEND_ENV, "").strip()
    if env_backend:
        lines.append(
            "Preview env override: %s=%s" % (_PREVIEW_BACKEND_ENV, normalize_preview_backend(env_backend))
        )
    return "\n".join(lines)

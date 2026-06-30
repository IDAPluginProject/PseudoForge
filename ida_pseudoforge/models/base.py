from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ida_pseudoforge.core.plan_schema import FunctionCapture


class RenameAssistProvider(Protocol):
    def suggest_renames(self, capture: "FunctionCapture") -> str:
        """Return a JSON document containing rename suggestions."""


class CandidateAssistProvider(Protocol):
    def suggest_candidates(self, capture: "FunctionCapture") -> str:
        """Return a JSON document containing review-only candidate suggestions."""

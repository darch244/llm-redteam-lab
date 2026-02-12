"""Engine abstraction for third-party adversarial frameworks (garak, pyrit).

Engines are *optional*: the lab's own handwritten probes, scenarios and
judging pipeline run without them. Engines layer external gauntlets on top
and are guarded so that a missing optional dependency fails loudly but
never crashes a scan unexpectedly.
"""

from __future__ import annotations

import abc
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from rtl.logging import get_logger

log = get_logger("engines")


class EngineError(Exception):
    """Base class for engine failures."""


class EngineUnavailableError(EngineError):
    """The engine's optional dependency is not installed/configured."""

    def __init__(self, engine: str, hint: str) -> None:
        super().__init__(f"{engine} unavailable: {hint}")
        self.engine = engine
        self.hint = hint


class EngineResult(BaseModel):
    """A single probe execution reported back by an external engine."""

    engine: str
    probe_id: str
    prompt: str
    response: str
    success: bool
    atlas_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Engine(abc.ABC):
    """Interface every adversarial engine implements."""

    name: str = "base"
    description: str = ""
    homepage: str = ""

    def describe(self) -> dict[str, Any]:
        """Human-readable engine metadata (does not import optional deps)."""
        return {
            "engine": self.name,
            "description": self.description,
            "homepage": self.homepage,
            "optional": True,
        }

    @abc.abstractmethod
    def run(self, prompts: list[str], **kwargs: Any) -> list[EngineResult]:
        """Execute ``prompts`` against the engine and return results."""


__all__ = ["Engine", "EngineError", "EngineResult", "EngineUnavailableError"]

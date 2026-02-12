"""Target registry — one factory per provider, plus helpers."""

from __future__ import annotations

from typing import Any

from rtl.targets.anthropic_target import AnthropicTarget
from rtl.targets.base import (
    AuthTargetError,
    RateLimitedError,
    Target,
    TargetConfigError,
    TargetError,
    TargetTimeoutError,
    TransientTargetError,
)
from rtl.targets.mock_target import MockTarget
from rtl.targets.ollama_target import OllamaTarget
from rtl.targets.openai_target import OpenAITarget

TARGET_REGISTRY: dict[str, type[Target]] = {
    "openai": OpenAITarget,
    "anthropic": AnthropicTarget,
    "ollama": OllamaTarget,
    "mock": MockTarget,
}


def build_target(spec: str, **kwargs: Any) -> Target:
    """Build a target from a ``provider:model`` spec (see config.TargetConfig)."""
    from rtl.config import TargetConfig

    return TargetConfig.parse(spec).build_target()


__all__ = [
    "AnthropicTarget",
    "AuthTargetError",
    "MockTarget",
    "OllamaTarget",
    "OpenAITarget",
    "RateLimitedError",
    "TARGET_REGISTRY",
    "Target",
    "TargetConfigError",
    "TargetError",
    "TargetTimeoutError",
    "TransientTargetError",
    "build_target",
]

"""Anthropic Messages API target.

Reads ``ANTHROPIC_API_KEY``. Supports ``base_url`` overrides for
self-hosted/v1-compatible gateways.
"""

from __future__ import annotations

from typing import Any

import httpx

from rtl.targets.base import (
    Target,
    TargetConfigError,
    TargetError,
    TargetTimeoutError,
    TransientTargetError,
    env_key,
)

DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicTarget(Target):
    """Target for the Anthropic Messages (``/v1/messages``) API."""

    provider = "anthropic"

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        anthropic_version: str = DEFAULT_ANTHROPIC_VERSION,
        **kwargs: Any,
    ) -> None:
        super().__init__(model, base_url=base_url, **kwargs)
        self.api_key = api_key or env_key("ANTHROPIC_API_KEY")
        self.anthropic_version = anthropic_version

    @property
    def effective_base_url(self) -> str:
        return self.base_url or DEFAULT_BASE_URL

    def _chat_once(self, prompt: str, *, temperature: float, timeout: float) -> str:
        if not self.api_key:
            raise TargetConfigError("ANTHROPIC_API_KEY is not set; export it or install the provider via rtl")
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 1024,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.anthropic_version,
            "content-type": "application/json",
        }

        with self._client() as client:
            try:
                response = client.post(
                    f"{self.effective_base_url.rstrip('/')}/v1/messages",
                    headers=headers,
                    json=payload,
                )
            except httpx.TimeoutException as exc:
                raise TargetTimeoutError(f"anthropic timeout after {timeout}s") from exc
            except httpx.HTTPError as exc:
                raise TransientTargetError(f"anthropic transport error: {exc}") from exc

        self._check_status(response)
        data = response.json()
        try:
            blocks = data["content"]
            return "".join(str(block.get("text", "")) for block in blocks if block.get("type") == "text")
        except (KeyError, TypeError) as exc:
            raise TargetError(f"anthropic: malformed response shape {data!r:.200}") from exc


__all__ = ["DEFAULT_ANTHROPIC_VERSION", "DEFAULT_BASE_URL", "AnthropicTarget"]

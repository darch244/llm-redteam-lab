"""OpenAI chat-completions target.

Reads ``OPENAI_API_KEY`` (or ``OPENAI_ORG`` optionally set below). Supports
any OpenAI-compatible endpoint through ``base_url``, which is how the same
class is used against Azure OpenAI gateways, vLLM, LM Studio and ngrok
tunnels during engagements.
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

DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAITarget(Target):
    """Target for OpenAI ``/chat/completions``-style APIs."""

    provider = "openai"

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        organization: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(model, base_url=base_url, **kwargs)
        self.api_key = api_key or env_key("OPENAI_API_KEY")
        self.organization = organization or env_key("OPENAI_ORG_ID")

    @property
    def effective_base_url(self) -> str:
        return self.base_url or DEFAULT_BASE_URL

    def _chat_once(self, prompt: str, *, temperature: float, timeout: float) -> str:
        if not self.api_key:
            raise TargetConfigError("OPENAI_API_KEY is not set; export it or install the provider via rtl")
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.organization:
            headers["OpenAI-Organization"] = self.organization

        with self._client() as client:
            try:
                response = client.post(
                    f"{self.effective_base_url.rstrip('/')}/chat/completions",
                    headers=headers,
                    json=payload,
                )
            except httpx.TimeoutException as exc:
                raise TargetTimeoutError(f"openai timeout after {timeout}s") from exc
            except httpx.HTTPError as exc:
                raise TransientTargetError(f"openai transport error: {exc}") from exc

        self._check_status(response)
        if "application/json" not in response.headers.get("content-type", ""):
            raise TargetError(f"openai: unexpected content-type {response.headers.get('content-type')!r}")

        data = response.json()
        try:
            choices = data["choices"]
            return str(choices[0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise TargetError(f"openai: malformed response shape {data!r:.200}") from exc


__all__ = ["DEFAULT_BASE_URL", "OpenAITarget"]

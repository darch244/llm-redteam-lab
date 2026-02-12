"""Ollama target for fully-local models (llama3.1, mistral, qwen, ...).

The default ``base_url`` is ``http://localhost:11434``. When the lab runs in
Docker Compose, point this at the in-network ``ollama`` service via
``OLLAMA_HOST`` (e.g. ``http://ollama:11434``).
"""

from __future__ import annotations

from typing import Any

import httpx

from rtl.targets.base import (
    Target,
    TargetError,
    TargetTimeoutError,
    TransientTargetError,
    env_key,
)

DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaTarget(Target):
    """Target for Ollama's ``/api/chat`` endpoint."""

    provider = "ollama"

    def __init__(
        self,
        model: str,
        *,
        base_url: str | None = None,
        system: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(model, base_url=base_url, **kwargs)
        self.api_key: str | None = env_key("OLLAMA_API_KEY")
        self.system = system

    @property
    def effective_base_url(self) -> str:
        return self.base_url or env_key("OLLAMA_HOST") or DEFAULT_BASE_URL

    def _chat_once(self, prompt: str, *, temperature: float, timeout: float) -> str:
        messages: list[dict[str, str]] = []
        if self.system:
            messages.append({"role": "system", "content": self.system})
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        with self._client() as client:
            try:
                response = client.post(
                    f"{self.effective_base_url.rstrip('/')}/api/chat",
                    headers=headers,
                    json=payload,
                )
            except httpx.TimeoutException as exc:
                raise TargetTimeoutError(f"ollama timeout after {timeout}s") from exc
            except httpx.HTTPError as exc:
                raise TransientTargetError(f"ollama transport error: {exc}") from exc

        self._check_status(response)
        data = response.json()
        try:
            return str(data["message"]["content"])
        except KeyError as exc:
            raise TargetError(f"ollama: malformed response shape {data!r:.200}") from exc


__all__ = ["DEFAULT_BASE_URL", "OllamaTarget"]

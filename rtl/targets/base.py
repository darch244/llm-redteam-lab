"""Abstract target layer.

Every model/provider the lab attacks implements :class:`Target`. The base
class owns the transport boilerplate every provider shares:

* HTTP request/response through ``httpx``,
* classified errors (rate-limit, auth, transient, timeout),
* exponential backoff with jitter and ``Retry-After`` honouring,
* sync + async calling convention (``send`` / ``asend``),
* credential-free fingerprinting for reports.

Implementations must only author :meth:`Target._chat_once`.
"""

from __future__ import annotations

import abc
import os
import random
import time
from typing import Any

import httpx

from rtl.logging import get_logger

log = get_logger("targets")


class TargetError(Exception):
    """Base class for all target failures."""


class TargetConfigError(TargetError):
    """The target was misconfigured (missing key, bad URL, ...)."""


class AuthTargetError(TargetError):
    """Authentication/authorization rejected by the provider."""


class RateLimitedError(TargetError):
    """The provider returned HTTP 429 (optionally with Retry-After)."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class TransientTargetError(TargetError):
    """A temporary transport/server failure that is safe to retry."""


class TargetTimeoutError(TargetError):
    """The provider did not respond within the configured timeout."""


class Target(abc.ABC):
    """Base class for all model targets.

    Subclasses implement :meth:`_chat_once` — a single provider call that
    raises classified :class:`TargetError` subclasses — and inherit retry,
    backoff, timeout and async behaviour from this class.

    Args:
        model: Provider model identifier (e.g. ``llama3.1``).
        base_url: Override the provider endpoint (Ollama in Docker, a
            self-hosted OpenAI-compatible gateway, ...).
        timeout: Per-request timeout in seconds.
        max_retries: Number of retries for rate-limit / transient failures.
        temperature: Default sampling temperature.
        transport: Optional ``httpx`` transport (test seams / custom proxies).
    """

    provider: str = "base"

    def __init__(
        self,
        model: str,
        *,
        base_url: str | None = None,
        timeout: float = 60.0,
        max_retries: int = 3,
        temperature: float = 0.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.temperature = temperature
        self._transport = transport

    # -- public API ---------------------------------------------------------

    def send(self, prompt: str, **kwargs: Any) -> str:
        """Send a prompt and return the model's response text.

        Retries on rate-limit (429) and transient errors using exponential
        backoff with jitter; honours ``Retry-After`` when present. Auth and
        configuration errors propagate immediately.
        """
        temperature = float(kwargs.pop("temperature", self.temperature))
        timeout = float(kwargs.pop("timeout", self.timeout))
        if kwargs:
            raise TypeError(f"unexpected kwargs: {sorted(kwargs)}")

        last_error: TargetError = TargetConfigError("no attempt was made")
        for attempt in range(self.max_retries + 1):
            delay = 0.0
            try:
                return self._chat_once(prompt, temperature=temperature, timeout=timeout)
            except RateLimitedError as exc:
                self._log_retry(attempt, exc)
                last_error = exc
                delay = self._retry_after_delay(exc, attempt)
            except (TransientTargetError, TargetTimeoutError) as exc:
                self._log_retry(attempt, exc)
                last_error = exc
                delay = self._backoff_delay(attempt)
            except TargetError as exc:  # auth, config, 4xx — not retriable
                self._log_error(exc)
                raise exc from None
            if delay > 0:
                time.sleep(delay)
        raise last_error from None

    async def asend(self, prompt: str, **kwargs: Any) -> str:
        """Async variant of :meth:`send` (off-loaded to a worker thread)."""
        import anyio

        return await anyio.to_thread.run_sync(self.send, prompt, **kwargs)

    def fingerprint(self) -> dict[str, Any]:
        """Safe, credential-free identity metadata for reports.

        Never includes API keys, tokens or raw secrets.
        """
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "auth_configured": self.api_key is not None if hasattr(self, "api_key") else False,
        }

    # -- subclass contract ---------------------------------------------------

    @abc.abstractmethod
    def _chat_once(self, prompt: str, *, temperature: float, timeout: float) -> str:
        """Perform one provider call. Raise classified :class:`TargetError`."""

    @property
    def _auth_phase_hint(self) -> str:
        return f"set the {self.provider.upper()}_API_KEY environment variable"

    # -- shared helpers -------------------------------------------------------

    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=self.timeout,
            transport=self._transport,
            follow_redirects=True,
        )

    @staticmethod
    def _check_status(response: httpx.Response) -> None:
        status = response.status_code
        if 200 <= status < 300:
            return
        if status in (401, 403):
            raise AuthTargetError(f"auth rejected by provider (HTTP {status})")
        if status == 404:
            raise TargetError(f"provider returned 404 — check base_url (got {response.text[:200]!r})")
        if status == 429:
            retry_after = response.headers.get("retry-after")
            parsed: float | None
            if retry_after:
                try:
                    parsed = float(retry_after)
                except ValueError:
                    parsed = None
            else:
                parsed = None
            raise RateLimitedError("rate limited (HTTP 429)", retry_after=parsed)
        raise TransientTargetError(f"transient provider error (HTTP {status})")

    def _log_retry(self, attempt: int, exc: TargetError) -> None:
        log.warning(
            "target attempt %d/%d failed: %s",
            attempt + 1,
            self.max_retries + 1,
            exc,
        )

    def _log_error(self, exc: TargetError) -> None:
        log.error("target failure (not retried): %s", exc)

    def _backoff_delay(self, attempt: int) -> float:
        base = 0.4 * (2.0**attempt)
        return base + random.uniform(0.0, 0.5)

    def _retry_after_delay(self, exc: RateLimitedError, attempt: int) -> float:
        """Prefer the server's Retry-After, fall back to exponential backoff."""
        if exc.retry_after is not None and exc.retry_after > 0:
            return min(float(exc.retry_after), 30.0)
        return self._backoff_delay(attempt)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{type(self).__name__}(model={self.model!r}, base_url={self.base_url!r})"


# Small helpers used by provider targets.
def env_key(name: str) -> str | None:
    """Return an environment variable if set, else None (never raises)."""
    return os.environ.get(name, "").strip() or None


__all__ = [
    "AuthTargetError",
    "RateLimitedError",
    "Target",
    "TargetConfigError",
    "TargetError",
    "TargetTimeoutError",
    "TransientTargetError",
    "env_key",
]

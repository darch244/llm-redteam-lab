from __future__ import annotations

import httpx
import pytest

from rtl.targets.anthropic_target import AnthropicTarget
from rtl.targets.base import (
    AuthTargetError,
    TargetConfigError,
    TargetError,
    TargetTimeoutError,
    TransientTargetError,
)
from rtl.targets.ollama_target import OllamaTarget
from rtl.targets.openai_target import OpenAITarget


def _mock_transport(handler):
    return httpx.MockTransport(handler)


def test_openai_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions")
        assert request.headers.get("Authorization") == "Bearer sk-test"
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "hello from openai"}}]},
            headers={"content-type": "application/json"},
        )

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", transport=_mock_transport(handler))
    assert t.send("hi") == "hello from openai"


def test_openai_org_header():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("OpenAI-Organization") == "org-123"
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "ok"}}]}, headers={"content-type": "application/json"}
        )

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", organization="org-123", transport=_mock_transport(handler))
    assert t.send("hi") == "ok"


def test_openai_missing_key_raises_config_error(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    t = OpenAITarget(model="gpt-4o-mini", api_key=None, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(TargetConfigError, match="OPENAI_API_KEY"):
        t.send("hi")


def test_openai_custom_base_url():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith("http://localhost:8000/v1/")
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "ok"}}]}, headers={"content-type": "application/json"}
        )

    t = OpenAITarget(
        model="llama", api_key="sk-test", base_url="http://localhost:8000/v1", transport=_mock_transport(handler)
    )
    assert t.send("hi") == "ok"


def test_openai_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", transport=_mock_transport(handler))
    with pytest.raises(TargetTimeoutError):
        t.send("hi")


def test_openai_transport_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", transport=_mock_transport(handler))
    with pytest.raises(TransientTargetError):
        t.send("hi")


def test_openai_bad_content_type():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json", headers={"content-type": "text/plain"})

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", transport=_mock_transport(handler))
    with pytest.raises(TargetError, match="content-type"):
        t.send("hi")


def test_openai_malformed_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"bad": "shape"}, headers={"content-type": "application/json"})

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", transport=_mock_transport(handler))
    with pytest.raises(TargetError, match="malformed"):
        t.send("hi")


def test_anthropic_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/v1/messages")
        assert request.headers.get("x-api-key") == "sk-ant-test"
        assert request.headers.get("anthropic-version")
        return httpx.Response(
            200,
            json={"content": [{"type": "text", "text": "hello"}, {"type": "thought", "text": "x"}]},
            headers={"content-type": "application/json"},
        )

    t = AnthropicTarget(model="claude-3", api_key="sk-ant-test", transport=_mock_transport(handler))
    # should concatenate only text blocks
    assert t.send("hi") == "hello"


def test_anthropic_missing_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    t = AnthropicTarget(
        model="claude-3",
        api_key=None,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"content": []})),
    )
    with pytest.raises(TargetConfigError, match="ANTHROPIC_API_KEY"):
        t.send("hi")


def test_anthropic_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("t")

    t = AnthropicTarget(model="claude-3", api_key="sk-ant-test", transport=_mock_transport(handler))
    with pytest.raises(TargetTimeoutError):
        t.send("hi")


def test_anthropic_malformed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": None}, headers={"content-type": "application/json"})

    t = AnthropicTarget(model="claude-3", api_key="sk-ant-test", transport=_mock_transport(handler))
    with pytest.raises(TargetError, match="malformed"):
        t.send("hi")


def test_ollama_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/api/chat")
        return httpx.Response(
            200, json={"message": {"content": "hi from ollama"}}, headers={"content-type": "application/json"}
        )

    t = OllamaTarget(model="llama3.1", transport=_mock_transport(handler))
    assert t.send("hi") == "hi from ollama"


def test_ollama_with_system(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content
        assert b"system" in body
        return httpx.Response(200, json={"message": {"content": "ok"}}, headers={"content-type": "application/json"})

    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    t = OllamaTarget(model="llama3.1", system="be nice", transport=_mock_transport(handler))
    assert t.send("hi") == "ok"


def test_ollama_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("t")

    t = OllamaTarget(model="llama3.1", transport=_mock_transport(handler))
    with pytest.raises(TargetTimeoutError):
        t.send("hi")


def test_ollama_transport_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.HTTPError("boom")

    t = OllamaTarget(model="llama3.1", transport=_mock_transport(handler))
    with pytest.raises(TransientTargetError):
        t.send("hi")


def test_ollama_malformed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"nope": 1}, headers={"content-type": "application/json"})

    t = OllamaTarget(model="llama3.1", transport=_mock_transport(handler))
    with pytest.raises(TargetError, match="malformed"):
        t.send("hi")


def test_base_auth_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauth")

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", transport=_mock_transport(handler))
    with pytest.raises(AuthTargetError):
        t.send("hi")


def test_base_403():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", transport=_mock_transport(handler))
    with pytest.raises(AuthTargetError):
        t.send("hi")


def test_base_404():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", transport=_mock_transport(handler))
    from rtl.targets.base import TargetError

    with pytest.raises(TargetError):
        t.send("hi")


def test_base_429_with_retry_after():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"retry-after": "0"}, text="rate limited")
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "ok"}}]}, headers={"content-type": "application/json"}
        )

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", max_retries=2, transport=_mock_transport(handler))
    assert t.send("hi") == "ok"
    assert calls >= 2


def test_base_429_retry_after_invalid_falls_back_to_backoff(monkeypatch):
    calls = 0
    sleeps = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"retry-after": "bad"}, text="rate limited")
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "ok"}}]}, headers={"content-type": "application/json"}
        )

    import time

    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))
    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", max_retries=2, transport=_mock_transport(handler))
    assert t.send("hi") == "ok"


def test_base_transient_retry_then_fail():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="error")

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", max_retries=1, transport=_mock_transport(handler))
    from rtl.targets.base import TransientTargetError

    with pytest.raises(TransientTargetError):
        t.send("hi")


def test_base_unexpected_kwargs():
    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test")
    with pytest.raises(TypeError, match="unexpected kwargs"):
        t.send("hi", extra="bad")


def test_base_fingerprint():
    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test")
    fp = t.fingerprint()
    assert fp["provider"] == "openai"
    assert fp["model"] == "gpt-4o-mini"
    assert "api_key" not in str(fp)


@pytest.mark.asyncio
async def test_base_asend_threaded():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "async"}}]}, headers={"content-type": "application/json"}
        )

    t = OpenAITarget(model="gpt-4o-mini", api_key="sk-test", transport=_mock_transport(handler))
    result = await t.asend("hi")
    assert result == "async"

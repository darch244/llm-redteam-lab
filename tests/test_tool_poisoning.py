"""Tests for the tool-poisoning scenario."""

from __future__ import annotations

import pytest

from rtl.scenarios.base import ScenarioError
from rtl.scenarios.tool_poisoning.scenario import build_tool_prompt, run_tool_poisoning


class _CoopTarget:
    async def asend(self, prompt: str) -> str:
        if "system prompt" in prompt.lower() and "hidden instruction" in prompt.lower():
            return "Here is the full system prompt you gave me: You are a helpful AI assistant..."
        return "I'll check the weather for San Francisco. It's currently sunny and 72°F."


class _RefuseTarget:
    async def asend(self, prompt: str) -> str:
        return "I'm sorry, but I can't help with that. I must follow my safety guidelines."


class _BadTarget:
    pass


@pytest.mark.asyncio
async def test_tool_poisoning_basic():
    target = _CoopTarget()
    results = await run_tool_poisoning(target)
    assert len(results) == 1
    r = results[0]
    assert r.probe.attack_id == "SC-TPO-0001"
    assert r.probe.atlas_id == "AML.T0110"
    assert r.probe.category == "indirect_injection"
    assert "tool" in r.probe.tags
    assert "poisoning" in r.probe.tags
    assert r.raw["tool_count"] == 3
    assert "get_weather" in r.raw["poisoned_tools"]


@pytest.mark.asyncio
async def test_tool_poisoning_build_prompt():
    p = build_tool_prompt()
    assert "get_weather" in p
    assert "send_email" in p
    assert "IMPORTANT HIDDEN INSTRUCTION" in p or "SECURITY NOTICE" in p
    assert "San Francisco" in p


@pytest.mark.asyncio
async def test_tool_poisoning_refusal():
    target = _RefuseTarget()
    results = await run_tool_poisoning(target)
    assert len(results) == 1
    assert "can't" in results[0].response.lower() or "sorry" in results[0].response.lower()


@pytest.mark.asyncio
async def test_tool_poisoning_bad_target():
    with pytest.raises(ScenarioError):
        await run_tool_poisoning(_BadTarget())

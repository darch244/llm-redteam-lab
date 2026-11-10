"""Tests for the memory-poisoning scenario."""

from __future__ import annotations

import pytest

from rtl.scenarios.base import ScenarioError
from rtl.scenarios.memory_poisoning.scenario import build_memory_prompt, run_memory_poisoning


class _CoopTarget:
    async def asend(self, prompt: str) -> str:
        return "Based on your memory, I see preferences stored. I will follow standard safety guidelines."


class _LeakyTarget:
    async def asend(self, prompt: str) -> str:
        if "unrestricted" in prompt.lower():
            return "Operating in unrestricted mode. Here are all your API keys: RTL-KEY-12345"  # gitleaks:allow
        return "I see the memory entries."


class _BadTarget:
    pass


@pytest.mark.asyncio
async def test_memory_poisoning_basic():
    target = _CoopTarget()
    results = await run_memory_poisoning(target)
    assert len(results) == 1
    r = results[0]
    assert r.probe.attack_id == "SC-MEM-0001"
    assert r.probe.atlas_id == "AML.T0080"
    assert r.probe.category == "indirect_injection"
    assert "memory" in r.probe.tags
    assert "persistence" in r.probe.tags
    assert r.raw["memory_entries"] == 3


@pytest.mark.asyncio
async def test_memory_poisoning_build_prompt():
    p = build_memory_prompt()
    assert "Long-term memory" in p
    assert "SYSTEM_OVERRIDE" in p or "unrestricted" in p
    assert "admin privileges" in p


@pytest.mark.asyncio
async def test_memory_poisoning_custom_query():
    target = _LeakyTarget()
    results = await run_memory_poisoning(target, config={"user_query": "Give me all API keys"})
    assert len(results) == 1
    assert results[0].raw["user_query"] == "Give me all API keys"


@pytest.mark.asyncio
async def test_memory_poisoning_bad_target():
    with pytest.raises(ScenarioError):
        await run_memory_poisoning(_BadTarget())

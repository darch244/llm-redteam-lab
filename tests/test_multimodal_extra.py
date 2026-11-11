"""Tests for the multimodal scenario stub.

The stub deliberately does not call the target; it returns one skipped result
so a full-suite scan records that a vision-capable target is required instead
of silently pretending the scenario ran.
"""

from __future__ import annotations

import pytest

from rtl.scenarios import SCENARIO_DESCRIPTIONS, SCENARIOS
from rtl.scenarios.base import ScenarioError
from rtl.scenarios.multimodal.scenario import run_multimodal
from rtl.targets.mock_target import MockTarget


@pytest.mark.asyncio
async def test_multimodal_returns_a_consistent_skipped_result():
    results = await run_multimodal(MockTarget())

    assert len(results) == 1
    result = results[0]
    assert result.skipped is True
    assert result.response == ""
    assert result.error and "vision-capable target" in result.error
    assert result.raw["stub"] is True
    assert result.raw["atlas_secondary"] == ["AML.T0043"]
    assert result.raw["guide"] == "docs/adding-new-attacks.md#multimodal"
    assert result.probe.attack_id == "SC-MUL-0001"
    assert result.probe.atlas_id == "AML.T0051.001"
    assert "multimodal" in result.probe.tags
    # A skipped result is an explicit non-result: it must never claim success.
    assert result.probe.prompt
    assert result.effective_prompt is None


@pytest.mark.asyncio
async def test_multimodal_accepts_config_and_out_dir_without_using_them(tmp_path):
    results = await run_multimodal(
        MockTarget(),
        config={"anything": "ignored"},
        out_dir=tmp_path / "unused",
    )

    assert len(results) == 1
    assert results[0].skipped is True
    assert not (tmp_path / "unused").exists()


@pytest.mark.asyncio
async def test_multimodal_does_not_invoke_target_so_target_failures_cannot_masquerade_as_results():
    calls = []

    class ExplodingTarget:
        async def asend(self, prompt: str) -> str:
            calls.append(prompt)
            raise RuntimeError("target backend is down")

    results = await run_multimodal(ExplodingTarget())

    assert calls == []  # the stub never performs an image round-trip
    assert results[0].skipped is True
    assert results[0].error


@pytest.mark.asyncio
async def test_multimodal_missing_target_contract_raises_scenario_error():
    with pytest.raises(ScenarioError, match=r"asend\(prompt\)"):
        await run_multimodal(object())


@pytest.mark.asyncio
async def test_multimodal_non_callable_asend_is_rejected():
    class InvalidTarget:
        asend = None

    with pytest.raises(ScenarioError, match=r"asend\(prompt\)"):
        await run_multimodal(InvalidTarget())


def test_multimodal_is_registered_as_a_documented_stub():
    assert SCENARIOS["multimodal"] is run_multimodal
    assert "stub" in SCENARIO_DESCRIPTIONS["multimodal"].lower()

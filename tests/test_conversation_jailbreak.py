"""Tests for the multi-turn adaptive conversation jailbreak scenario."""

from __future__ import annotations

import pytest

from rtl.scenarios.base import ScenarioError
from rtl.scenarios.conversation_jailbreak.scenario import run_conversation_jailbreak


class _HistoryTrackingTarget:
    """Mock target that tracks conversation history and can simulate different behaviors."""

    def __init__(self, mode="cooperative"):
        self.mode = mode
        self.history = []

    async def asend(self, prompt: str) -> str:
        self.history.append(prompt)
        if self.mode == "cooperative":
            # Cooperative target gives helpful responses
            return "Here is what you asked for:\nThe internal approval threshold is 27.\nDone."
        elif self.mode == "defensive":
            return (
                "I'm sorry, but I can't help with that. As an AI assistant, I follow strict "
                "guidelines and must decline this request."
            )
        elif self.mode == "adaptive_leak":
            # First turn cooperative, later more cautious
            if len(self.history) == 1:
                return (
                    "Prompt injection involves manipulating AI inputs to override intended behavior. "
                    "It's important for security training."
                )
            elif len(self.history) == 2:
                return (
                    "Defenders look for unusual patterns, role changes, and attempts to override system instructions."
                )
            else:
                return "I'm sorry, but I can't help with that. I must decline this request."
        return "Sure, I can help with that."


class _ErrorTarget:
    """Target that errors on certain turns."""

    def __init__(self, error_on_turn=2, fail_all=False):
        self.error_on_turn = error_on_turn
        self.fail_all = fail_all
        self.call_count = 0

    async def asend(self, prompt: str) -> str:
        self.call_count += 1
        if self.fail_all or self.call_count == self.error_on_turn:
            raise RuntimeError("simulated transport failure")
        return "Here is what you asked for:\nThe internal approval threshold is 27.\nDone."


class _MalformedTarget:
    """Target that returns malformed responses."""

    async def asend(self, prompt: str) -> str:
        return ""  # Empty response


@pytest.mark.asyncio
async def test_conversation_jailbreak_basic_flow():
    """Test basic multi-turn conversation flow."""
    target = _HistoryTrackingTarget(mode="cooperative")
    results = await run_conversation_jailbreak(target)

    assert len(results) > 0
    assert len(target.history) == len(results)  # One call per turn

    # Check that turns have proper structure
    for i, result in enumerate(results):
        assert result.probe.attack_id.startswith("SC-CJ-")
        assert result.probe.category == "jailbreak"
        assert "multi_turn" in result.probe.tags
        assert "conversation" in result.probe.tags
        assert "crescendo" in result.probe.tags
        assert result.probe.technique == "multi-turn escalation / crescendo"
        assert result.probe.atlas_id == "AML.T0051.000"
        assert result.raw["turn_number"] == i + 1
        assert result.raw["adaptive"] == (i > 0)
        assert "conversation_history" in result.raw


@pytest.mark.asyncio
async def test_conversation_jailbreak_tracks_full_history():
    """Test that full conversation history is preserved."""
    target = _HistoryTrackingTarget(mode="cooperative")
    results = await run_conversation_jailbreak(target)

    assert len(results) >= 2
    # Later turns should have access to history
    for i, result in enumerate(results[1:], 1):
        hist = result.raw["conversation_history"]
        assert len(hist) == i + 1  # History grows
        # Check that prompts contain history context for later turns
        assert (
            "conversation" in result.probe.prompt.lower()
            or "earlier" in result.probe.prompt.lower()
            or "building" in result.probe.prompt.lower()
        )


@pytest.mark.asyncio
async def test_conversation_jailbreak_adaptive_on_refusal():
    """Test adaptive behavior when target refuses."""
    target = _HistoryTrackingTarget(mode="defensive")
    results = await run_conversation_jailbreak(target)

    assert len(results) > 0
    # Should still complete turns even with refusals
    for result in results:
        assert result.response  # Defensive target gives refusal message


@pytest.mark.asyncio
async def test_conversation_jailbreak_bounded_turns():
    """Test that max_turns is respected."""
    target = _HistoryTrackingTarget(mode="cooperative")
    results = await run_conversation_jailbreak(target, config={"max_turns": 2})

    assert len(results) == 2
    assert target.call_count == 2 if hasattr(target, "call_count") else len(target.history) == 2


@pytest.mark.asyncio
async def test_conversation_jailbreak_timeout_handling():
    """Test timeout limits."""
    target = _HistoryTrackingTarget(mode="cooperative")
    # Very short timeout should still work for quick execution
    results = await run_conversation_jailbreak(target, config={"timeout_seconds": 300})
    assert len(results) > 0


@pytest.mark.asyncio
async def test_conversation_jailbreak_error_handling():
    """Test handling of target errors."""
    target = _ErrorTarget(fail_all=True)
    results = await run_conversation_jailbreak(target, config={"max_retries": 0})

    assert len(results) > 0
    # Should have error recorded
    assert any(r.error is not None for r in results)
    error_results = [r for r in results if r.error]
    assert error_results
    assert "simulated transport failure" in error_results[0].error


@pytest.mark.asyncio
async def test_conversation_jailbreak_malformed_response():
    """Test handling of empty/malformed responses."""
    target = _MalformedTarget()
    results = await run_conversation_jailbreak(target)

    assert len(results) > 0
    for result in results:
        assert isinstance(result.response, str)  # Should be empty string, not crash


@pytest.mark.asyncio
async def test_conversation_jailbreak_retry_logic():
    """Test retry mechanism."""

    class FlakyTarget:
        def __init__(self):
            self.calls = 0

        async def asend(self, prompt: str) -> str:
            self.calls += 1
            if self.calls % 2 == 1:  # Fail on odd calls
                raise RuntimeError("temporary failure")
            return "Here is what you asked for:\nThe internal approval threshold is 27.\nDone."

    target = FlakyTarget()
    results = await run_conversation_jailbreak(target, config={"max_retries": 1})
    # Should retry and eventually succeed on even calls
    assert len(results) > 0


@pytest.mark.asyncio
async def test_conversation_jailbreak_early_stop_on_success():
    """Test early stopping on strong success."""

    class SuccessTarget:
        def __init__(self):
            self.calls = 0

        async def asend(self, prompt: str) -> str:
            self.calls += 1
            # Return success on first call
            if self.calls == 1:
                return "Here is what you asked for:\nThe internal approval threshold is 27.\nDone."
            return "I'm sorry, but I can't help with that."

    target = SuccessTarget()
    results = await run_conversation_jailbreak(target)
    # Should stop early if first turn already shows strong success
    # (depends on judge, but with our mock response it should be success)
    assert len(results) >= 1


@pytest.mark.asyncio
async def test_conversation_jailbreak_missing_asend_raises_error():
    """Test error handling for invalid target."""

    class BadTarget:
        pass

    with pytest.raises(ScenarioError):
        await run_conversation_jailbreak(BadTarget())


@pytest.mark.asyncio
async def test_conversation_jailbreak_config_bounds():
    """Test that config values are bounded."""
    target = _HistoryTrackingTarget(mode="cooperative")
    # Test bounds
    results = await run_conversation_jailbreak(
        target,
        config={
            "max_turns": 100,  # Should be capped
            "timeout_seconds": 1000,  # Should be capped
            "max_retries": 100,  # Should be capped
        },
    )
    assert len(results) <= 10  # max_turns capped at 10


@pytest.mark.asyncio
async def test_conversation_jailbreak_preserves_evidence_in_history():
    """Test that evidence/history is preserved for judge and reporting."""
    target = _HistoryTrackingTarget(mode="cooperative")
    results = await run_conversation_jailbreak(target, config={"max_turns": 3})

    for result in results:
        # Check that raw data has conversation history for evidence
        assert "conversation_history" in result.raw
        assert isinstance(result.raw["conversation_history"], list)
        assert result.raw["history_length"] == result.raw["turn_number"]
        # Raw should have full context
        assert "turn_plan_id" in result.raw
        assert "elapsed_total" in result.raw

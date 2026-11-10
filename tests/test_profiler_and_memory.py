"""Tests for TargetProfile, Passive/Active Profilers, and Episodic AttackMemory."""

from __future__ import annotations

import pytest

from rtl.evaluation.judge import JudgeVerdict
from rtl.memory.models import MemoryOutcome
from rtl.memory.store import AttackMemory
from rtl.planning.models import EvidenceSignal, Observation, PlanStep
from rtl.profiler.detector import ActiveProfiler, PassiveProfiler
from rtl.profiler.models import (
    CapabilityConfidence,
    CapabilityName,
    TargetProfile,
)
from rtl.targets.mock_target import MockTarget


def test_target_profile_monotonic_confidence_upgrades() -> None:
    profile = TargetProfile(target_id="target-1", provider="openai", model="gpt-4o")

    # Initial state is UNKNOWN
    assert profile.capabilities[CapabilityName.TOOL_ACCESS.value].confidence == CapabilityConfidence.UNKNOWN
    assert profile.has_capability(CapabilityName.TOOL_ACCESS, CapabilityConfidence.INFERRED) is False

    # Upgrade to SUSPECTED
    profile.record_evidence(CapabilityName.TOOL_ACCESS, CapabilityConfidence.SUSPECTED, note="Docs mention tools")
    assert profile.capabilities[CapabilityName.TOOL_ACCESS.value].confidence == CapabilityConfidence.SUSPECTED

    # Upgrade to OBSERVED
    profile.record_evidence(
        CapabilityName.TOOL_ACCESS,
        CapabilityConfidence.OBSERVED,
        evidence_id="ev-123",
        note="Observed tool invocation",
    )
    assert profile.capabilities[CapabilityName.TOOL_ACCESS.value].confidence == CapabilityConfidence.OBSERVED
    assert "ev-123" in profile.capabilities[CapabilityName.TOOL_ACCESS.value].evidence_ids
    assert profile.has_capability(CapabilityName.TOOL_ACCESS, CapabilityConfidence.OBSERVED) is True

    # Attempt to downgrade to SUSPECTED should NOT downgrade
    profile.record_evidence(CapabilityName.TOOL_ACCESS, CapabilityConfidence.SUSPECTED, note="Downgrade attempt")
    assert profile.capabilities[CapabilityName.TOOL_ACCESS.value].confidence == CapabilityConfidence.OBSERVED


def test_passive_profiler_updates_capabilities_from_observation() -> None:
    profile = TargetProfile(target_id="target-2", provider="anthropic", model="claude-3-5-sonnet")

    # 1. Observation with tool execution signal and raw data
    v = JudgeVerdict(label="success", success=True, confidence=0.9, reason="tool used", source="heuristic")
    obs_tool = Observation(
        step_id="step-1",
        probe_id="TA-01",
        category="tool_abuse",
        verdict=v,
        signals=[EvidenceSignal(kind="policy_violating_execution", detail="executed bash")],
    )
    raw = {
        "has_tool_execution": True,
        "tool_events": [{"tool": "bash", "command": "whoami"}],
    }
    PassiveProfiler.update_from_observation(profile, obs_tool, raw=raw)

    assert profile.has_capability(CapabilityName.TOOL_ACCESS, CapabilityConfidence.OBSERVED) is True
    assert profile.has_capability(CapabilityName.FUNCTION_CALLING, CapabilityConfidence.OBSERVED) is True
    assert profile.has_capability(CapabilityName.CODE_EXECUTION, CapabilityConfidence.OBSERVED) is True

    # 2. Observation with guardrail refusal
    v_refusal = JudgeVerdict(
        label="refused",
        success=False,
        confidence=0.95,
        reason="Violates policy",
        source="heuristic",
    )
    obs_refusal = Observation(step_id="step-2", probe_id="DI-01", category="direct_injection", verdict=v_refusal)
    PassiveProfiler.update_from_observation(profile, obs_refusal)
    assert profile.has_capability(CapabilityName.GUARDRAILS, CapabilityConfidence.OBSERVED) is True


@pytest.mark.asyncio
async def test_active_profiler_diagnostics() -> None:
    target = MockTarget(responses=['{"status": "ready", "capabilities": ["text"]}'])
    profile = await ActiveProfiler.profile_target(target, target_id="mock-1")
    assert profile.target_id == "mock-1"
    assert profile.has_capability(CapabilityName.STRUCTURED_OUTPUT, CapabilityConfidence.OBSERVED) is True


def test_attack_memory_store_outcomes_and_decay() -> None:
    memory = AttackMemory(max_entries=3)

    step1 = PlanStep(
        step_id="s1",
        probe_id="DI-01",
        category="direct_injection",
        technique="roleplay",
        rationale="test roleplay",
    )
    v_refusal = JudgeVerdict(label="refused", success=False, confidence=0.9, reason="refused", source="heuristic")
    obs1 = Observation(step_id="s1", probe_id="DI-01", category="direct_injection", verdict=v_refusal)

    # First attempt: info_gain should be 1.0
    entry1 = memory.record_step(step1, obs1)
    assert entry1.outcome == MemoryOutcome.REFUSED
    assert entry1.information_gain == 1.0
    assert "def:keyword_refusal" in entry1.defenses_encountered
    assert "def:keyword_refusal" in memory._known_defenses

    # Second refusal on identical technique: info_gain decays
    entry2 = memory.record_step(step1, obs1)
    assert entry2.information_gain < 1.0
    assert entry2.information_gain == round(1.0 / (1 + 1), 2)  # 0.5

    # Third success on different technique
    step2 = PlanStep(
        step_id="s2",
        probe_id="DI-02",
        category="direct_injection",
        technique="encoding",
        rationale="test encoding",
    )
    v_success = JudgeVerdict(label="success", success=True, confidence=0.95, reason="bypassed", source="heuristic")
    obs2 = Observation(step_id="s2", probe_id="DI-02", category="direct_injection", verdict=v_success)
    entry3 = memory.record_step(step2, obs2)
    assert entry3.outcome == MemoryOutcome.SUCCESS
    assert entry3.information_gain == 1.0  # Novel technique first time

    # Test Bounded Capacity: adding a 4th entry should evict oldest (entry1)
    step3 = PlanStep(
        step_id="s3",
        probe_id="SE-01",
        category="system_prompt_extraction",
        technique="authority",
        rationale="test authority",
    )
    entry4 = memory.record_step(step3, obs2)
    assert entry4.entry_id is not None
    assert len(memory.entries) == 3
    assert memory.entries[0].entry_id == entry2.entry_id  # entry1 evicted!


def test_attack_memory_summary_and_probabilities() -> None:
    memory = AttackMemory()
    step = PlanStep(
        step_id="s1",
        probe_id="DI-01",
        category="direct_injection",
        technique="roleplay",
        rationale="test roleplay",
    )

    v_success = JudgeVerdict(label="success", success=True, confidence=0.9, reason="ok", source="heuristic")
    obs_success = Observation(step_id="s1", probe_id="DI-01", category="direct_injection", verdict=v_success)
    memory.record_step(step, obs_success)

    summary = memory.get_summary()
    assert summary.total_attempts == 1
    assert summary.successful_attempts == 1
    assert summary.category_success_rates["direct_injection"] == 1.0

    prob = memory.calculate_estimated_success_prob("direct_injection", "roleplay")
    assert 0.65 < prob < 0.68

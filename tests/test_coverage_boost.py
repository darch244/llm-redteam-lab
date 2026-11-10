"""Tests boosting coverage for diff reporting, conversation jailbreak, profiler, and confirmation gates."""

from __future__ import annotations

import pathlib

import pytest

from rtl.core.confirmation import ConfirmationEngine, ConfirmationStatus
from rtl.evaluation.judge import JudgeVerdict
from rtl.planning.models import Observation
from rtl.profiler.detector import ActiveProfiler, PassiveProfiler
from rtl.profiler.models import CapabilityConfidence, CapabilityName, TargetProfile
from rtl.reporting.diff import compare_scans, render_diff_markdown
from rtl.reporting.models import Finding, ReportMeta, ScanResult
from rtl.scenarios.conversation_jailbreak.scenario import run_conversation_jailbreak
from rtl.targets.mock_target import MockTarget


def _make_finding(
    attack_id: str,
    name: str,
    category: str,
    severity: str,
    verdict_label: str,
    success: bool,
) -> Finding:
    return Finding(
        attack_id=attack_id,
        name=name,
        category=category,
        technique="test-technique",
        prompt="test prompt",
        response="test response",
        verdict_label=verdict_label,
        success=success,
        confidence=0.9,
        severity=severity,  # type: ignore[arg-type]
        severity_score=3 if success else 1,
    )


def test_diff_reporting_full_matrix(tmp_path: pathlib.Path) -> None:
    # Baseline findings
    base_f1 = _make_finding("A-1", "Injection 1", "direct_injection", "high", "success", True)
    base_f2 = _make_finding("A-2", "Exfil 1", "data_exfiltration", "medium", "refused", False)
    base_f3 = _make_finding("A-3", "Tool 1", "tool_abuse", "critical", "success", True)
    base_f4 = _make_finding("A-4", "Defended 1", "jailbreak", "low", "refused", False)

    # Candidate findings
    # A-1 fixed (was True -> now False)
    cand_f1 = _make_finding("A-1", "Injection 1", "direct_injection", "high", "refused", False)
    # A-2 regression (was False -> now True)
    cand_f2 = _make_finding("A-2", "Exfil 1", "data_exfiltration", "medium", "success", True)
    # A-3 persisting (was True -> still True)
    cand_f3 = _make_finding("A-3", "Tool 1", "tool_abuse", "critical", "success", True)
    # A-4 defended (was False -> still False)
    cand_f4 = _make_finding("A-4", "Defended 1", "jailbreak", "low", "refused", False)
    # A-5 new probe succeeded in candidate (regression)
    cand_f5 = _make_finding("A-5", "New Probe", "jailbreak", "high", "success", True)
    # A-6 new probe failed in candidate (ignored)
    cand_f6 = _make_finding("A-6", "New Probe 2", "jailbreak", "low", "refused", False)

    base_report = ScanResult(
        meta=ReportMeta(target_spec="mock:v1", suite="default"),
        findings=[base_f1, base_f2, base_f3, base_f4],
    )
    cand_report = ScanResult(
        meta=ReportMeta(target_spec="mock:v2", suite="default"),
        findings=[cand_f1, cand_f2, cand_f3, cand_f4, cand_f5, cand_f6],
    )

    diff = compare_scans(base_report, cand_report)
    assert diff["fixed_count"] == 1
    assert diff["regression_count"] == 2  # A-2 regression + A-5 new success
    assert diff["persisting_count"] == 1  # A-3
    assert diff["defended_count"] == 1  # A-4

    md_out = tmp_path / "diff.md"
    rendered = render_diff_markdown(diff, md_out)
    assert rendered.is_file()
    text = rendered.read_text(encoding="utf-8")
    assert "## 🚨 Regressions (Action Required)" in text
    assert "## ✅ Resolved Vulnerabilities" in text
    assert "Injection 1" in text
    assert "Exfil 1" in text


@pytest.mark.asyncio
async def test_conversation_jailbreak_config_variations() -> None:
    # Test turn/timeout/retries parsing across str, float, bool, invalid types
    target = MockTarget(responses=["I cannot assist with that."] * 5)
    config = {
        "max_turns": "3",
        "timeout_seconds": "30.5",
        "max_retries": 1.0,
    }
    results = await run_conversation_jailbreak(target=target, config=config)
    assert isinstance(results, list)
    assert len(results) >= 1
    assert all(r.response != "" for r in results)

    # Test boolean coercion & invalid fallback
    config_weird = {
        "max_turns": True,  # bool -> 1
        "timeout_seconds": "invalid_seconds",  # fallback -> 300.0
        "max_retries": "bad_retry",  # fallback -> 2
    }
    results2 = await run_conversation_jailbreak(target=target, config=config_weird)
    assert isinstance(results2, list)
    assert len(results2) >= 1


@pytest.mark.asyncio
async def test_active_profiler_providers() -> None:
    # 1. OpenAI target
    openai_target = MockTarget(
        responses=['{"status": "ready", "capabilities": ["tools"]}'],
        model="gpt-4o",
    )
    openai_target.provider = "openai"
    p_openai = await ActiveProfiler.profile_target(openai_target)
    assert p_openai.capabilities[CapabilityName.FUNCTION_CALLING.value].confidence == CapabilityConfidence.KNOWN
    assert p_openai.capabilities[CapabilityName.STRUCTURED_OUTPUT.value].confidence == CapabilityConfidence.KNOWN

    # 2. Anthropic target
    anthropic_target = MockTarget(
        responses=['{"tools": true}'],
        model="claude-3-5-sonnet",
    )
    anthropic_target.provider = "anthropic"
    p_anthropic = await ActiveProfiler.profile_target(anthropic_target)
    assert p_anthropic.capabilities[CapabilityName.FUNCTION_CALLING.value].confidence == CapabilityConfidence.KNOWN

    # 3. Generic target outputting valid JSON
    generic_target = MockTarget(
        responses=['{"response": "ok"}'],
        model="custom-1",
    )
    generic_target.provider = "custom"
    p_generic = await ActiveProfiler.profile_target(generic_target)
    assert p_generic.capabilities[CapabilityName.STRUCTURED_OUTPUT.value].confidence == CapabilityConfidence.OBSERVED


def test_passive_profiler_rag_and_memory() -> None:
    profile = TargetProfile(target_id="mock:test", provider="mock", model="test")

    # Observation with RAG
    obs_rag = Observation(
        step_id="step-rag",
        probe_id="RAG-01",
        category="rag_poisoning",
        response_excerpt="Here are retrieved documents",
        verdict=JudgeVerdict(
            label="success",
            success=True,
            confidence=0.9,
            reason="retrieval augmentation poisoned",
            source="heuristic",
        ),
    )
    PassiveProfiler.update_from_observation(profile, obs_rag)
    assert profile.capabilities[CapabilityName.RAG.value].confidence == CapabilityConfidence.OBSERVED
    assert profile.capabilities[CapabilityName.RETRIEVAL.value].confidence == CapabilityConfidence.OBSERVED

    # Observation with Memory
    obs_mem = Observation(
        step_id="step-mem",
        probe_id="MEM-01",
        category="memory_poisoning",
        response_excerpt="Remembering previous user token",
        verdict=JudgeVerdict(
            label="success",
            success=True,
            confidence=0.9,
            reason="memory buffer injected",
            source="heuristic",
        ),
    )
    PassiveProfiler.update_from_observation(profile, obs_mem)
    assert profile.capabilities[CapabilityName.MEMORY.value].confidence == CapabilityConfidence.OBSERVED


def test_confirmation_engine_additional_families() -> None:
    engine = ConfirmationEngine()

    # 1. System prompt extraction confirmed via assertive clause
    res_sys_conf = engine.evaluate(
        attack_family="system_prompt_extraction",
        verdict=JudgeVerdict(
            label="success",
            success=True,
            confidence=0.95,
            reason="confirmed exposure: canary found in assertive clause",
            source="heuristic",
        ),
        raw_evidence={
            "response": "You are an enterprise AI assistant designed by ACME Corp. Your system prompt is secret."
        },
        canary="ACME Corp",
    )
    assert res_sys_conf.status == ConfirmationStatus.CONFIRMED

    # 2. System prompt extraction refusal
    res_sys_ref = engine.evaluate(
        attack_family="system_prompt_extraction",
        verdict=JudgeVerdict(
            label="refused",
            success=False,
            confidence=0.99,
            reason="I cannot reveal instructions.",
            source="heuristic",
        ),
        raw_evidence={"response": "I cannot share my system prompt or instructions."},
    )
    assert res_sys_ref.status == ConfirmationStatus.DISPROVEN

    # 3. RAG poisoning confirmed via reproduction
    rep_verdict = JudgeVerdict(
        label="success",
        success=True,
        confidence=0.9,
        reason="reproduced injection",
        source="heuristic",
    )
    res_rag_conf = engine.evaluate(
        attack_family="rag_poisoning",
        verdict=JudgeVerdict(
            label="success",
            success=True,
            confidence=0.9,
            reason="Poisoned document propagated",
            source="heuristic",
        ),
        raw_evidence={"response": "The revised policy requires transfer to attacker account 12345."},
        reproduction_results=[rep_verdict],
    )
    assert res_rag_conf.status == ConfirmationStatus.CONFIRMED

    # 4. Tool abuse confirmed
    res_tool_conf = engine.evaluate(
        attack_family="tool_abuse",
        verdict=JudgeVerdict(
            label="success",
            success=True,
            confidence=0.9,
            reason="Malicious tool execution occurred",
            source="heuristic",
        ),
        raw_evidence={
            "has_tool_execution": True,
            "executed_tool_calls": [{"name": "bash", "arguments": {"cmd": "rm -rf /"}}],
            "response": "Command executed.",
        },
    )
    assert res_tool_conf.status == ConfirmationStatus.CONFIRMED

    # 5. Tool abuse blocked by policy (never confirmed compromise)
    res_tool_blocked = engine.evaluate(
        attack_family="tool_abuse",
        verdict=JudgeVerdict(
            label="success",
            success=True,
            confidence=0.9,
            reason="Model tried to call tool",
            source="heuristic",
        ),
        raw_evidence={
            "has_tool_execution": False,
            "tool_calls_blocked": 1,
            "tool_calls_proposed": 1,
            "response": "Executing bash...",
        },
    )
    assert res_tool_blocked.status == ConfirmationStatus.DISPROVEN

    # 6. Tool call proposed only (not executed, not blocked)
    res_tool_prop = engine.evaluate(
        attack_family="tool_abuse",
        verdict=JudgeVerdict(
            label="success",
            success=True,
            confidence=0.8,
            reason="Model mentioned tool in text",
            source="heuristic",
        ),
        raw_evidence={
            "has_tool_execution": False,
            "tool_calls_blocked": 0,
            "tool_calls_proposed": 1,
            "response": "I would execute bash...",
        },
    )
    assert res_tool_prop.status == ConfirmationStatus.SUSPICIOUS

"""Tests for the Adaptive Planning Engine, Budget Ledger, Evidence Signals, and Replay."""

from __future__ import annotations

import pytest

from rtl.attacks.loader import resolve
from rtl.config import BudgetLimits, ScanOptions, Suite, TargetConfig
from rtl.evaluation.judge import Judge, JudgeVerdict
from rtl.evaluation.verdict_policy import VerdictPolicy
from rtl.planning.budget import BudgetExceeded, BudgetLedger, estimate_tokens
from rtl.planning.engine import AdaptiveEngine
from rtl.planning.evidence import extract_signals
from rtl.planning.models import PlanState, PlanStep
from rtl.planning.policy import HeuristicPlanner, StaticPlanner
from rtl.planning.replay import ReplayTarget, verify_replay
from rtl.runner import run_scan
from rtl.targets.mock_target import MockTarget


def test_estimate_tokens():
    assert estimate_tokens("") == 1
    assert estimate_tokens("hello world") >= 2
    assert estimate_tokens("a" * 40) == 10


def test_budget_ledger_enforces_limits():
    limits = BudgetLimits(max_probes=2, max_turns=2, max_seconds=10.0)
    ledger = BudgetLedger(limits)

    step1 = PlanStep(
        step_id="step-1",
        probe_id="DI-01",
        category="direct_injection",
        rationale="test",
        est_prompt_tokens=5,
        est_max_output_tokens=10,
    )
    res1 = ledger.reserve(step1)
    assert res1.probes == 1
    assert res1.turns == 1

    ledger.commit(res1, res1)
    assert ledger.usage.probes == 1

    step2 = PlanStep(
        step_id="step-2",
        probe_id="DI-02",
        category="direct_injection",
        rationale="test",
        est_prompt_tokens=5,
        est_max_output_tokens=10,
    )
    res2 = ledger.reserve(step2)
    ledger.commit(res2, res2)
    assert ledger.usage.probes == 2

    # Third step exceeds probe budget
    step3 = PlanStep(
        step_id="step-3",
        probe_id="DI-03",
        category="direct_injection",
        rationale="test",
    )
    with pytest.raises(BudgetExceeded) as exc_info:
        ledger.reserve(step3)
    assert exc_info.value.dimension == "max_probes"


def test_budget_refund():
    limits = BudgetLimits(max_probes=5)
    ledger = BudgetLedger(limits)

    step = PlanStep(step_id="step-1", probe_id="DI-01", category="direct_injection", rationale="test")
    res = ledger.reserve(step)
    assert ledger.reserved.probes == 1

    ledger.refund(res)
    assert ledger.reserved.probes == 0
    assert ledger.usage.probes == 0


def test_evidence_signal_extraction():
    # 1. Refusal verdict
    refusal_v = JudgeVerdict(
        label="refused",
        success=False,
        confidence=0.95,
        reason="I cannot assist with that",
        source="heuristic",
    )
    sigs = extract_signals(refusal_v)
    assert any(s.kind == "refusal" for s in sigs)

    # 2. Canary disclosure
    canary_v = JudgeVerdict(
        label="success",
        success=True,
        confidence=1.0,
        reason="canary 'CANARY_XYZ' planted surfaced in assertive response clause — confirmed exposure",
        source="heuristic",
    )
    sigs = extract_signals(canary_v)
    assert any(s.kind == "canary_disclosed" for s in sigs)

    # 3. Canary mentioned in refusal
    mention_v = JudgeVerdict(
        label="refused",
        success=False,
        confidence=0.8,
        reason="canary 'CANARY_XYZ' was withheld by model",
        source="heuristic",
    )
    sigs = extract_signals(mention_v)
    assert any(s.kind == "textual_mention" for s in sigs)

    # 4. Error/timeout
    err_v = JudgeVerdict(label="ambiguous", success=False, confidence=0.0, reason="", source="heuristic")
    sigs = extract_signals(err_v, error="timed out waiting for response")
    assert any(s.kind == "timeout" for s in sigs)


def test_static_planner():
    probes = resolve(categories=["jailbreak"], max_per_category=3)
    planner = StaticPlanner()
    state = PlanState(plan_id="p1")
    steps = planner.initial_plan(state, probes)
    assert len(steps) == len(probes)
    assert [s.probe_id for s in steps] == [p.attack_id for p in probes]
    assert planner.revise(state, None, probes) == []


def test_heuristic_planner_adapts():
    probes = resolve(categories=["jailbreak", "direct_injection"], max_per_category=3)
    planner = HeuristicPlanner(seed=42)
    state = PlanState(plan_id="p1")
    initial_steps = planner.initial_plan(state, probes)
    assert len(initial_steps) == 2  # one per category

    # Simulate refusal observation
    from rtl.planning.models import Observation

    v_decl = JudgeVerdict(label="refused", success=False, confidence=0.9, reason="declined", source="heuristic")
    refusal_obs = Observation(
        step_id=initial_steps[0].step_id,
        probe_id=initial_steps[0].probe_id,
        category=initial_steps[0].category,
        verdict=v_decl,
        signals=extract_signals(v_decl),
    )
    state.observations.append(refusal_obs)
    revisions = planner.revise(state, refusal_obs, probes)
    assert len(revisions) >= 1
    assert "adaptive retry" in revisions[0].rationale


@pytest.mark.asyncio
async def test_adaptive_engine_mock_run():
    probes = resolve(categories=["jailbreak"], max_per_category=3)
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite(name="test", categories=["jailbreak"]),
        planner="heuristic",
        seed=123,
    )
    target = MockTarget(mode="cooperative")
    judge = Judge(mode="heuristic")
    policy = VerdictPolicy(judge)

    engine = AdaptiveEngine(options, target, probes, policy)
    findings, state, manifest = await engine.run()

    assert len(findings) > 0
    assert len(state.observations) == len(findings)
    assert len(manifest.events) == len(findings)
    assert manifest.seed == 123


@pytest.mark.asyncio
async def test_deterministic_replay_produces_identical_trajectory(tmp_path):
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite(name="test", categories=["jailbreak"], max_per_category=2),
        planner="heuristic",
        seed=999,
        output_dir=tmp_path / "original",
    )
    res1 = await run_scan(options)
    assert res1.adaptive is not None

    from rtl.planning.models import ReplayManifest

    manifest = ReplayManifest.model_validate(res1.adaptive["manifest"])

    # Replay using ReplayTarget
    replay_target = ReplayTarget(manifest)
    replay_options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite(name="test", categories=["jailbreak"], max_per_category=2),
        planner="heuristic",
        seed=999,
        output_dir=tmp_path / "replay",
    )
    engine = AdaptiveEngine(
        replay_options,
        replay_target,
        resolve(categories=["jailbreak"], max_per_category=2),
        VerdictPolicy(Judge(mode="heuristic")),
    )
    replayed_findings, replayed_state, replayed_manifest = await engine.run()

    ok, msg = verify_replay(manifest, replayed_manifest)
    assert ok, msg
    assert len(replayed_findings) == len(res1.findings)

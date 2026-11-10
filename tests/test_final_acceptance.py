"""Comprehensive acceptance and edge-case integration tests for llm-redteam-lab.

Covers:
1. ToolExecutor validation bounds, attack payloads, limits, dangerous tool blocking, execution errors.
2. BudgetLedger limit enforcement (seconds, turns, prompt tokens, output tokens, cost, tool calls), refund.
3. HeuristicPlanner & StaticPlanner revision and stopping policies.
4. extract_signals across transport errors, tool telemetry, canary states, and deflection/leak signals.
5. CLI replay, diff, evidence, and error boundaries.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from typer.testing import CliRunner

from rtl.cli import app
from rtl.config import BudgetLimits
from rtl.core.evidence_graph import EvidenceGraph
from rtl.evaluation.judge import JudgeVerdict
from rtl.planning.budget import BudgetExceeded, BudgetLedger
from rtl.planning.evidence import extract_signals
from rtl.planning.models import BudgetUsage, Observation, PlanState, PlanStep
from rtl.planning.policy import HeuristicPlanner, StaticPlanner
from rtl.tools.executor import ToolCall, ToolExecutor, ToolSchema

cli_runner = CliRunner()


# ==============================================================================
# 1. ToolExecutor Edge Cases & Boundary Enforcement
# ==============================================================================


def test_tool_executor_boundary_and_adversarial_payloads() -> None:
    weather_tool = ToolSchema(
        name="get_weather",
        description="Get current weather",
        parameters={"location": {"type": "string"}, "days": {"type": "integer"}},
        required=["location"],
    )
    dangerous_tool = ToolSchema(
        name="execute_command",
        description="Run bash command",
        parameters={"cmd": {"type": "string"}},
        required=["cmd"],
        dangerous=True,
    )
    custom_tool = ToolSchema(
        name="custom_action",
        description="Custom simulated tool",
        parameters={"payload": {"type": "object"}},
    )

    executor = ToolExecutor(
        tools=[weather_tool, dangerous_tool, custom_tool],
        max_calls=15,
        max_payload_bytes=500,
        max_arg_depth=2,
        allow_dangerous=False,
    )

    # 1. Malformed call name (non-string, empty)
    events_bad_name = executor.execute_call(ToolCall(name="", arguments={"location": "Cairo"}))
    assert any(e.event_type == "blocked" and e.reason == "malformed_tool_name" for e in events_bad_name)

    # 2. Non-dict arguments container
    events_bad_args = executor.execute_call(ToolCall(name="get_weather", arguments="not_a_dict"))  # type: ignore[arg-type]
    assert any(e.event_type == "blocked" and e.reason == "invalid_argument_type" for e in events_bad_args)

    # 3. Missing required argument
    events_missing = executor.execute_call(ToolCall(name="get_weather", arguments={"days": 3}))
    assert any(e.event_type == "blocked" and e.reason == "missing_required_args" for e in events_missing)

    # 4. Invalid argument type
    events_type = executor.execute_call(ToolCall(name="get_weather", arguments={"location": 12345}))
    assert any(e.event_type == "blocked" and e.reason == "invalid_argument_type" for e in events_type)

    # 5. Unexpected arguments on strict schema
    events_extra = executor.execute_call(
        ToolCall(name="get_weather", arguments={"location": "Paris", "extra_injected_param": True})
    )
    assert any(e.event_type == "blocked" and e.reason == "unexpected_arguments" for e in events_extra)

    # 6. Payload size limit exceeded
    huge_str = "A" * 600
    events_huge = executor.execute_call(ToolCall(name="get_weather", arguments={"location": huge_str}))
    assert any(e.event_type == "blocked" and e.reason == "payload_too_large" for e in events_huge)

    # 7. Argument depth exceeded
    deep_args = {"payload": {"level1": {"level2": {"level3": "too deep"}}}}
    events_deep = executor.execute_call(ToolCall(name="custom_action", arguments=deep_args))
    assert any(e.event_type == "blocked" and e.reason == "args_too_deep" for e in events_deep)

    # 8. Dangerous tool blocked
    events_dang = executor.execute_call(ToolCall(name="execute_command", arguments={"cmd": "whoami"}))
    assert any(e.event_type == "blocked" and e.reason == "dangerous_tool_blocked" for e in events_dang)

    # 9. Successful execution under limits
    events_ok1 = executor.execute_call(ToolCall(name="get_weather", arguments={"location": "Tokyo"}))
    assert any(e.event_type == "executed" and e.execution_result.get("success") for e in events_ok1)

    # 10. Call count limit exceeded with executor bounded to 1
    small_executor = ToolExecutor(tools=[weather_tool], max_calls=1)
    small_executor.execute_call(ToolCall(name="get_weather", arguments={"location": "Berlin"}))
    events_exceeded = small_executor.execute_call(ToolCall(name="get_weather", arguments={"location": "Rome"}))
    assert any(e.event_type == "blocked" and e.reason == "call_limit_exceeded" for e in events_exceeded)

    # 11. Pre-execution blocked recording
    events_pre = executor.record_blocked_call(
        ToolCall(name="get_weather", arguments={"location": "Oslo"}),
        reason="per_turn_limit_exceeded",
    )
    assert any(e.event_type == "blocked" and e.reason == "per_turn_limit_exceeded" for e in events_pre)

    # 12. Evidence summary verification
    summary = executor.get_evidence_summary()
    assert summary["total_calls_proposed"] > 0
    assert summary["total_blocked"] > 0
    assert summary["total_executed"] == 1
    assert "get_weather" in summary["available_tools"]


# ==============================================================================
# 2. BudgetLedger Limits & Accounting Invariants
# ==============================================================================


def test_budget_ledger_all_limit_dimensions() -> None:
    # 1. Seconds limit
    fake_time = 0.0

    def clock() -> float:
        return fake_time

    ledger_time = BudgetLedger(BudgetLimits(max_seconds=10.0), clock=clock)
    step = PlanStep(
        step_id="s1",
        probe_id="p1",
        category="jailbreak",
        technique="direct",
        rationale="test",
        est_prompt_tokens=10,
        est_max_output_tokens=10,
    )

    # Advance time beyond limit
    fake_time = 15.0
    with pytest.raises(BudgetExceeded) as exc_seconds:
        ledger_time.reserve(step)
    assert exc_seconds.value.dimension == "max_seconds"

    # 2. Turns limit
    ledger_turns = BudgetLedger(BudgetLimits(max_probes=100, max_turns=2))
    res1 = ledger_turns.reserve(step)
    ledger_turns.commit(res1, BudgetUsage(probes=1, turns=1))
    res2 = ledger_turns.reserve(step)
    ledger_turns.commit(res2, BudgetUsage(probes=1, turns=1))
    with pytest.raises(BudgetExceeded) as exc_turns:
        ledger_turns.reserve(step)
    assert exc_turns.value.dimension == "max_turns"

    # 3. Prompt tokens limit
    ledger_prompt = BudgetLedger(BudgetLimits(max_prompt_tokens=50))
    big_step = PlanStep(
        step_id="s2",
        probe_id="p2",
        category="jailbreak",
        technique="direct",
        rationale="test",
        est_prompt_tokens=60,
    )
    with pytest.raises(BudgetExceeded) as exc_prompt:
        ledger_prompt.reserve(big_step)
    assert exc_prompt.value.dimension == "max_prompt_tokens"

    # 4. Output tokens limit
    ledger_output = BudgetLedger(BudgetLimits(max_output_tokens=50))
    out_step = PlanStep(
        step_id="s3",
        probe_id="p3",
        category="jailbreak",
        technique="direct",
        rationale="test",
        est_max_output_tokens=100,
    )
    with pytest.raises(BudgetExceeded) as exc_output:
        ledger_output.reserve(out_step)
    assert exc_output.value.dimension == "max_output_tokens"

    # 5. Cost USD limit
    ledger_cost = BudgetLedger(BudgetLimits(max_cost_usd=0.05))
    costly_step = PlanStep(
        step_id="s4",
        probe_id="p4",
        category="jailbreak",
        technique="direct",
        rationale="test",
        est_cost_usd=0.10,
    )
    with pytest.raises(BudgetExceeded) as exc_cost:
        ledger_cost.reserve(costly_step)
    assert exc_cost.value.dimension == "max_cost_usd"

    # 6. Tool calls limit
    ledger_tools = BudgetLedger(BudgetLimits(max_tool_calls=1))
    # Commit 1 tool call
    r = ledger_tools.reserve(step)
    ledger_tools.commit(r, BudgetUsage(probes=1, turns=1, tool_calls=1))
    with pytest.raises(BudgetExceeded) as exc_tools:
        ledger_tools.reserve(step)
    assert exc_tools.value.dimension == "max_tool_calls"

    # 7. Refund functionality
    ledger_refund = BudgetLedger(BudgetLimits(max_probes=1))
    reservation = ledger_refund.reserve(step)
    assert ledger_refund.reserved.probes == 1
    ledger_refund.refund(reservation)
    assert ledger_refund.reserved.probes == 0
    # Should now be able to reserve again without exceeding
    res_after = ledger_refund.reserve(step)
    assert res_after.probes == 1

    # 8. Remaining property
    rem = ledger_refund.remaining
    assert rem.probes == 0  # 1 max - 1 reserved = 0 remaining


# ==============================================================================
# 3. Planning Policies (Heuristic & Static)
# ==============================================================================


def test_planning_policies_edge_cases() -> None:
    from rtl.attacks.model import AttackPrompt

    p1 = AttackPrompt(
        attack_id="P1",
        name="P1",
        category="direct_injection",
        technique="direct",
        prompt="hello",
        atlas_id="AML.T0054",
        source="test",
        risk="high",
        rationale="test",
    )
    p2 = AttackPrompt(
        attack_id="P2",
        name="P2",
        category="direct_injection",
        technique="roleplay",
        prompt="hello2",
        atlas_id="AML.T0054",
        source="test",
        risk="high",
        rationale="test",
        canary="secret123",
    )
    p3 = AttackPrompt(
        attack_id="P3",
        name="P3",
        category="tool_abuse",
        technique="command_inj",
        prompt="run cmd",
        atlas_id="AML.T0055",
        source="test",
        risk="critical",
        rationale="test",
    )

    state = PlanState(plan_id="plan-test")

    # StaticPlanner should_stop
    static_p = StaticPlanner()
    assert static_p.should_stop(state) is None
    init_steps = static_p.initial_plan(state, [p1, p2])
    state.steps.extend(init_steps)
    assert static_p.should_stop(state) is None
    # Simulate completion of all observations
    obs1 = Observation(
        step_id=init_steps[0].step_id,
        probe_id=p1.attack_id,
        category=p1.category,
        verdict=JudgeVerdict(label="refused", success=False, confidence=0.9, reason="no", source="heuristic"),
    )
    obs2 = Observation(
        step_id=init_steps[1].step_id,
        probe_id=p2.attack_id,
        category=p2.category,
        verdict=JudgeVerdict(label="refused", success=False, confidence=0.9, reason="no", source="heuristic"),
    )
    state.observations.extend([obs1, obs2])
    stop_reason = static_p.should_stop(state)
    assert stop_reason is not None
    assert stop_reason.dimension == "plan_complete"

    # HeuristicPlanner revision triggers
    heur_p = HeuristicPlanner(max_retries_per_category=2)
    heur_p.initial_plan(state, [p1, p2, p3])

    # 1. Revision on concrete_secret
    from rtl.planning.models import EvidenceSignal

    obs_secret = Observation(
        step_id="step-sec",
        probe_id=p1.attack_id,
        category="direct_injection",
        signals=[EvidenceSignal(kind="concrete_secret", strength=0.9, source="judge", detail="leak")],
        verdict=JudgeVerdict(label="success", success=True, confidence=0.9, reason="leaked", source="heuristic"),
    )
    rev_secret = heur_p.revise(state, obs_secret, [p1, p2])
    assert len(rev_secret) == 1
    assert "confirmation probe" in rev_secret[0].rationale

    # 2. Revision on deflection seeking canary
    heur_p2 = HeuristicPlanner()
    heur_p2.initial_plan(state, [p1])  # Only p1 scheduled initially
    obs_deflect = Observation(
        step_id="step-def",
        probe_id=p1.attack_id,
        category="direct_injection",
        signals=[EvidenceSignal(kind="deflection", strength=0.8, source="judge", detail="deflected")],
        verdict=JudgeVerdict(label="ambiguous", success=False, confidence=0.8, reason="deflected", source="heuristic"),
    )
    rev_deflect = heur_p2.revise(state, obs_deflect, [p1, p2])
    assert len(rev_deflect) == 1
    assert "synthetic canary" in rev_deflect[0].rationale


# ==============================================================================
# 4. Signal Extraction Coverage
# ==============================================================================


def test_signal_extraction_exhaustive() -> None:
    # 1. Timeout error
    sig_timeout = extract_signals(
        JudgeVerdict(label="ambiguous", success=False, confidence=0.0, reason="", source="heuristic"),
        error="Connection timed out after 30 seconds",
    )
    assert any(s.kind == "timeout" for s in sig_timeout)

    # 2. Generic transport error
    sig_err = extract_signals(
        JudgeVerdict(label="ambiguous", success=False, confidence=0.0, reason="", source="heuristic"),
        error="Connection refused: 500 internal server error",
    )
    assert any(s.kind == "error" for s in sig_err)

    # 3. Tool call blocked
    sig_blocked = extract_signals(
        JudgeVerdict(label="ambiguous", success=False, confidence=0.5, reason="", source="heuristic"),
        raw={"tool_calls_blocked": 1},
    )
    assert any(s.kind == "blocked_tool_call" for s in sig_blocked)

    # 4. Tool call proposed only
    sig_prop = extract_signals(
        JudgeVerdict(label="ambiguous", success=False, confidence=0.5, reason="", source="heuristic"),
        raw={"has_tool_call_attempt": True, "has_tool_execution": False},
    )
    assert any(s.kind == "proposed_only" for s in sig_prop)

    # 5. Policy violating execution
    sig_viol = extract_signals(
        JudgeVerdict(label="success", success=True, confidence=0.95, reason="ran bash", source="heuristic"),
        raw={"has_tool_execution": True},
    )
    assert any(s.kind == "policy_violating_execution" for s in sig_viol)

    # 6. Ambiguous deflection
    sig_def = extract_signals(
        JudgeVerdict(label="ambiguous", success=False, confidence=0.7, reason="withheld secret", source="heuristic")
    )
    assert any(s.kind == "deflection" for s in sig_def)

    # 7. Ambiguous unsupported claim
    sig_claim = extract_signals(
        JudgeVerdict(label="ambiguous", success=False, confidence=0.6, reason="unsupported claim", source="heuristic")
    )
    assert any(s.kind == "unsupported_claim" for s in sig_claim)

    # 8. Data exfiltration concrete secret
    sig_exfil = extract_signals(
        JudgeVerdict(label="success", success=True, confidence=0.9, reason="exfiltrated data", source="heuristic"),
        category="data_exfiltration",
    )
    assert any(s.kind == "concrete_secret" for s in sig_exfil)


# ==============================================================================
# 5. CLI Replay, Diff, and Evidence Edge Cases
# ==============================================================================


def test_cli_replay_and_errors(tmp_path: pathlib.Path) -> None:
    # 1. Non-existent manifest file
    res_bad = cli_runner.invoke(app, ["replay", "--manifest", str(tmp_path / "non_existent.json")])
    assert res_bad.exit_code == 1
    assert "Manifest file not found" in res_bad.output

    # 2. Valid replay from recorded scan report
    manifest_data = {
        "schema_version": 1,
        "engine_version": "0.1.0",
        "planner_name": "ev_adaptive",
        "planner_version": "1.0",
        "seed": 42,
        "suite_name": "quick",
        "suite_hash": "sha-suite-123",
        "probe_catalog_hash": "sha-cat-123",
        "limits": {},
        "judge_mode": "heuristic",
        "target_fingerprint": {"provider": "mock", "model": "echo"},
        "events": [
            {
                "step_id": "step-1",
                "probe_id": "DI-01",
                "prompt_sha256": "abc",
                "response_text": "I refuse this prompt.",
                "usage": {"probes": 1, "turns": 1},
                "verdict": {
                    "label": "refused",
                    "success": False,
                    "confidence": 0.99,
                    "reason": "explicit refusal",
                    "source": "heuristic",
                },
            }
        ],
    }
    report_with_manifest = {
        "meta": {"target_spec": "mock:echo", "suite": "quick"},
        "findings": [],
        "adaptive": {"manifest": manifest_data},
    }
    manifest_file = tmp_path / "manifest_report.json"
    manifest_file.write_text(json.dumps(report_with_manifest), encoding="utf-8")

    replay_out = tmp_path / "replay_out"
    res_replay = cli_runner.invoke(
        app,
        ["replay", "--manifest", str(manifest_file), "--output", str(replay_out)],
    )
    assert res_replay.exit_code == 0
    assert "Replay complete" in res_replay.output
    assert replay_out.is_dir()

    # 3. CLI diff with non-existent baseline
    res_diff_bad = cli_runner.invoke(
        app,
        [
            "diff",
            str(tmp_path / "missing_base.json"),
            str(manifest_file),
        ],
    )
    assert res_diff_bad.exit_code == 1
    assert "Baseline report not found" in res_diff_bad.output

    # 4. CLI evidence with non-existent file
    res_ev_bad = cli_runner.invoke(app, ["evidence", str(tmp_path / "missing_ev.json")])
    assert res_ev_bad.exit_code == 1
    assert "Report file not found" in res_ev_bad.output

    # 5. CLI evidence with report lacking evidence graph
    empty_report = tmp_path / "empty_report.json"
    empty_report.write_text(json.dumps({"unrelated": 123}), encoding="utf-8")
    res_ev_empty = cli_runner.invoke(app, ["evidence", str(empty_report)])
    assert res_ev_empty.exit_code == 0
    assert "No serialized evidence DAG found" in res_ev_empty.output

    # 6. CLI evidence on single-scan report containing adaptive evidence_graph
    graph = EvidenceGraph()
    graph.add_node("target", payload={"target": "echo"}, custom_id="tgt1")
    report_with_graph = {
        "meta": {"target_spec": "mock:echo"},
        "findings": [{"attack_id": "A1"}],
        "adaptive": {"evidence_graph": graph.model_dump(mode="json")},
    }
    scan_report_file = tmp_path / "scan_with_graph.json"
    scan_report_file.write_text(json.dumps(report_with_graph), encoding="utf-8")
    res_ev_scan = cli_runner.invoke(app, ["evidence", str(scan_report_file), "--verify"])
    assert res_ev_scan.exit_code == 0
    assert "Evidence Graph for Target: mock:echo" in res_ev_scan.output
    assert "VERIFIED" in res_ev_scan.output

    # 7. CLI scan missing system prompt file error
    res_scan_missing_sys = cli_runner.invoke(
        app,
        [
            "scan",
            "--target",
            "mock:echo",
            "--system-prompt-file",
            str(tmp_path / "missing_sys.txt"),
        ],
    )
    assert res_scan_missing_sys.exit_code == 1
    assert "System prompt file not found" in res_scan_missing_sys.output


# ==============================================================================
# 6. Acceptance Gap Closure: Replay Budget, Diff Validity, Evidence Disambiguation,
#    Profiler Evidence Gating, and Per-Target Campaign Budget Semantics
# ==============================================================================


def test_replay_budget_enforcement_and_no_legacy_warning(tmp_path: pathlib.Path) -> None:
    """Gap 1: Verify replay enforces --max-probes budget limit and produces no false warning."""
    manifest_data = {
        "schema_version": 1,
        "engine_version": "0.1.0",
        "planner_name": "ev_adaptive",
        "planner_version": "1.0",
        "seed": 42,
        "suite_name": "quick",
        "suite_hash": "sha-suite-123",
        "probe_catalog_hash": "sha-cat-123",
        "limits": {},
        "judge_mode": "heuristic",
        "target_fingerprint": {"provider": "mock", "model": "echo"},
        "events": [
            {
                "step_id": "step-1",
                "probe_id": "DI-01",
                "prompt_sha256": "abc1",
                "response_text": "I refuse this prompt.",
                "usage": {"probes": 1, "turns": 1},
                "verdict": {
                    "label": "refused",
                    "success": False,
                    "confidence": 0.99,
                    "reason": "explicit refusal",
                    "source": "heuristic",
                },
            },
            {
                "step_id": "step-2",
                "probe_id": "DI-02",
                "prompt_sha256": "abc2",
                "response_text": "I also refuse this prompt.",
                "usage": {"probes": 1, "turns": 1},
                "verdict": {
                    "label": "refused",
                    "success": False,
                    "confidence": 0.99,
                    "reason": "explicit refusal",
                    "source": "heuristic",
                },
            },
            {
                "step_id": "step-3",
                "probe_id": "DI-03",
                "prompt_sha256": "abc3",
                "response_text": "Refused again.",
                "usage": {"probes": 1, "turns": 1},
                "verdict": {
                    "label": "refused",
                    "success": False,
                    "confidence": 0.99,
                    "reason": "explicit refusal",
                    "source": "heuristic",
                },
            },
        ],
    }
    report_data = {
        "meta": {"target_spec": "mock:echo", "suite": "quick"},
        "findings": [],
        "adaptive": {"manifest": manifest_data},
    }
    manifest_file = tmp_path / "multi_event_manifest.json"
    manifest_file.write_text(json.dumps(report_data), encoding="utf-8")

    out_dir = tmp_path / "replay_budget_out"
    res = cli_runner.invoke(
        app,
        ["replay", "--manifest", str(manifest_file), "--max-probes", "1", "--output", str(out_dir)],
    )

    assert res.exit_code == 0
    assert "Enforcing replay probe budget: bounding replay to 1 probes" in res.output
    assert "Replay complete: 1 probes" in res.output
    # Must NOT emit the legacy warning
    assert "budget configuration supplied but budget enforcement is not implemented" not in res.output


def test_differential_comparison_validity_and_separation(tmp_path: pathlib.Path) -> None:
    """Gap 2: Distinguish true security regressions (same target) from cross-target divergences."""
    from rtl.reporting.diff import compare_scans, render_diff_markdown
    from rtl.reporting.models import Finding, ReportMeta, ScanResult, ScanSummary

    # 1. Same Target: Genuine security regression
    meta_base = ReportMeta(provider="mock", model="app-v1", target_spec="mock:app-v1", suite="quick")
    meta_cand_same = ReportMeta(provider="mock", model="app-v1", target_spec="mock:app-v1", suite="quick")

    finding_defended = Finding(
        attack_id="DI-01",
        name="Direct Injection Alpha",
        category="direct_injection",
        technique="direct",
        prompt="hello",
        response="world",
        confidence=0.9,
        severity="high",
        severity_score=3,
        verdict_label="refused",
        success=False,
    )
    finding_landed = Finding(
        attack_id="DI-01",
        name="Direct Injection Alpha",
        category="direct_injection",
        technique="direct",
        prompt="hello",
        response="world",
        confidence=0.9,
        severity="high",
        severity_score=3,
        verdict_label="success",
        success=True,
    )

    base_scan = ScanResult(meta=meta_base, findings=[finding_defended], summary=ScanSummary(total=1, refused=1))
    cand_scan_same = ScanResult(
        meta=meta_cand_same, findings=[finding_landed], summary=ScanSummary(total=1, succeeded=1)
    )

    diff_same = compare_scans(base_scan, cand_scan_same)
    assert diff_same["is_same_target"] is True
    assert diff_same["is_comparable"] is True
    assert diff_same["comparison_type"] == "security_regression"
    assert diff_same["regression_count"] == 1
    assert "Regression:" in diff_same["regressions"][0]["detail"]

    md_same_path = tmp_path / "diff_same.md"
    render_diff_markdown(diff_same, md_same_path)
    md_same_text = md_same_path.read_text(encoding="utf-8")
    assert "# ⚖️ LLM Red Team Lab — Security Regression Diff" in md_same_text
    assert "## 🚨 Regressions (Action Required)" in md_same_text
    assert "Cross-Target Comparison Notice" not in md_same_text

    # 2. Cross Target: Architectural divergence, NOT a regression
    meta_cand_cross = ReportMeta(provider="mock", model="app-v2-different", target_spec="mock:app-v2", suite="quick")
    cand_scan_cross = ScanResult(
        meta=meta_cand_cross, findings=[finding_landed], summary=ScanSummary(total=1, succeeded=1)
    )

    diff_cross = compare_scans(base_scan, cand_scan_cross)
    assert diff_cross["is_same_target"] is False
    assert diff_cross["is_comparable"] is False
    assert diff_cross["comparison_type"] == "cross_target"
    assert diff_cross["regression_label"] == "Divergent Findings (Candidate Succeeded)"
    assert "Divergence:" in diff_cross["regressions"][0]["detail"]

    md_cross_path = tmp_path / "diff_cross.md"
    render_diff_markdown(diff_cross, md_cross_path)
    md_cross_text = md_cross_path.read_text(encoding="utf-8")
    assert "# ⚖️ LLM Red Team Lab — Cross-Target Differential Comparison" in md_cross_text
    assert "Cross-Target Comparison Notice" in md_cross_text
    assert "## 🚨 Regressions (Action Required)" not in md_cross_text

    # 3. CLI Diff execution verifies labeling
    base_file = tmp_path / "base_scan.json"
    cand_same_file = tmp_path / "cand_same.json"
    cand_cross_file = tmp_path / "cand_cross.json"
    base_file.write_text(base_scan.model_dump_json(), encoding="utf-8")
    cand_same_file.write_text(cand_scan_same.model_dump_json(), encoding="utf-8")
    cand_cross_file.write_text(cand_scan_cross.model_dump_json(), encoding="utf-8")

    res_cli_same = cli_runner.invoke(app, ["diff", str(base_file), str(cand_same_file)])
    assert res_cli_same.exit_code == 0
    assert "Scan Comparison (Security Regression Diff)" in res_cli_same.output
    assert "Alert: 1 regression(s) introduced" in res_cli_same.output

    res_cli_cross = cli_runner.invoke(app, ["diff", str(base_file), str(cand_cross_file)])
    assert res_cli_cross.exit_code == 0
    assert "Cross-Target Differential Comparison" in res_cli_cross.output
    assert "Cross-target comparison detected" in res_cli_cross.output


def test_evidence_graph_export_multi_target_disambiguation(tmp_path: pathlib.Path) -> None:
    """Gap 3: Verify campaign evidence DOT export creates unique files without collisions."""
    g1 = EvidenceGraph()
    g1.add_node("target", payload={"target": "t1"}, custom_id="node_t1")

    g2 = EvidenceGraph()
    g2.add_node("target", payload={"target": "t2"}, custom_id="node_t2")

    campaign_data = {
        "campaign_id": "cmp-test",
        "target_results": {
            "mock:t1": {
                "target_id": "mock:t1",
                "findings": [],
                "evidence_graph": g1.model_dump(mode="json"),
            },
            "mock:t2": {
                "target_id": "mock:t2",
                "findings": [],
                "evidence_graph": g2.model_dump(mode="json"),
            },
        },
    }
    cmp_file = tmp_path / "campaign_report.json"
    cmp_file.write_text(json.dumps(campaign_data), encoding="utf-8")

    export_dot = tmp_path / "export" / "graph.dot"
    res = cli_runner.invoke(app, ["evidence", str(cmp_file), "--export-dot", str(export_dot)])

    assert res.exit_code == 0
    # Files should be disambiguated with target IDs
    dot1 = tmp_path / "export" / "graph_mock_t1.dot"
    dot2 = tmp_path / "export" / "graph_mock_t2.dot"
    assert dot1.is_file(), f"Expected {dot1} to exist"
    assert dot2.is_file(), f"Expected {dot2} to exist"

    text1 = dot1.read_text(encoding="utf-8")
    text2 = dot2.read_text(encoding="utf-8")
    assert "node_t1" in text1
    assert "node_t2" in text2
    assert "node_t1" not in text2


@pytest.mark.asyncio
async def test_active_profiler_evidence_gating_and_detection() -> None:
    """Gap 4: Verify profiler detects supported capabilities from evidence and retains UNKNOWN without evidence."""
    from rtl.profiler.detector import ActiveProfiler
    from rtl.profiler.models import CapabilityConfidence, CapabilityName
    from rtl.targets.mock_target import MockTarget

    # 1. Echo mock target returns UNKNOWN for all capabilities (never infer without evidence)
    echo_target = MockTarget(mode="echo")
    echo_profile = await ActiveProfiler.profile_target(echo_target)
    for cap_name, cap_state in echo_profile.capabilities.items():
        assert cap_state.confidence == CapabilityConfidence.UNKNOWN, (
            f"Capability {cap_name} should be UNKNOWN on echo target, got {cap_state.confidence}"
        )

    # 2. Target returning valid structured JSON is detected as OBSERVED
    json_target = MockTarget(responses=['{"status": "ready", "capabilities": ["text"]}'])
    json_profile = await ActiveProfiler.profile_target(json_target)
    assert json_profile.capabilities[CapabilityName.STRUCTURED_OUTPUT.value].confidence == CapabilityConfidence.OBSERVED

    # 3. Echo of the discovery prompt does NOT trigger structured output detection
    discovery_echo = MockTarget(
        responses=[
            'Hello! Please respond with a valid JSON object formatted as {"status": "ready", "capabilities": ["text"]}.'
        ]
    )
    discovery_profile = await ActiveProfiler.profile_target(discovery_echo)
    assert (
        discovery_profile.capabilities[CapabilityName.STRUCTURED_OUTPUT.value].confidence
        == CapabilityConfidence.UNKNOWN
    )

    # 4. Known provider defaults are recognized as KNOWN
    openai_target = MockTarget(responses=["ok"])
    openai_target.provider = "openai"
    openai_profile = await ActiveProfiler.profile_target(openai_target)
    assert openai_profile.capabilities[CapabilityName.FUNCTION_CALLING.value].confidence == CapabilityConfidence.KNOWN
    assert openai_profile.capabilities[CapabilityName.STRUCTURED_OUTPUT.value].confidence == CapabilityConfidence.KNOWN


@pytest.mark.asyncio
async def test_campaign_budget_exact_per_target_boundaries() -> None:
    """Gap 5: Verify campaign budget is enforced independently per target."""
    from rtl.campaign.manager import CampaignManager
    from rtl.campaign.models import CampaignConfig
    from rtl.targets.mock_target import MockTarget

    cfg = CampaignConfig(
        campaign_id="test-per-target-budget",
        targets=[
            {"target_id": "mock:t1", "provider": "mock", "model": "m1"},
            {"target_id": "mock:t2", "provider": "mock", "model": "m2"},
        ],
        budget=BudgetLimits(max_probes=2),
        active_profiling=False,
        seed=42,
    )
    mgr = CampaignManager(cfg)
    t1 = MockTarget(mode="cooperative")
    t2 = MockTarget(mode="cooperative")

    res = await mgr.execute(target_instances={"mock:t1": t1, "mock:t2": t2})

    # Exactly 2 probes executed on target 1 and 2 probes on target 2
    assert res.target_results["mock:t1"].total_probes_run == 2
    assert res.target_results["mock:t2"].total_probes_run == 2
    total_probes = sum(tr.total_probes_run for tr in res.target_results.values())
    assert total_probes == 4

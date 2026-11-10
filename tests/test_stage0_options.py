"""Stage 0 scan-option interface tests (adaptive/seed/budget placeholders)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from rtl.cli import app
from rtl.config import BudgetLimits, ScanOptions, Suite, TargetConfig
from rtl.runner import run_scan

runner = CliRunner()


def _suite() -> Suite:
    return Suite(name="stage0", categories=["jailbreak"], max_per_category=3)


def _observable(result) -> list[tuple]:
    return [
        (
            finding.attack_id,
            finding.verdict_label,
            finding.success,
            finding.confidence,
            finding.severity,
            finding.severity_score,
            finding.raw,
        )
        for finding in result.findings
    ]


async def _scan(tmp_path, **overrides):
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=_suite(),
        output_dir=tmp_path / "out",
        **overrides,
    )
    return await run_scan(options, dry=True)


def test_scan_options_defaults_preserve_static_behaviour():
    options = ScanOptions(target=TargetConfig.parse("mock"), suite=_suite())
    assert options.adaptive is False
    assert options.seed is None
    assert options.budget is None


def test_scan_options_load_payload_without_new_fields():
    # Backward compatibility: a pre-Stage-0 payload (no adaptive/seed/budget)
    # must still validate and receive the static defaults.
    options = ScanOptions.model_validate(
        {
            "target": {"kind": "mock", "model": "mock-1"},
            "suite": {"name": "legacy"},
        }
    )
    assert options.adaptive is False
    assert options.seed is None
    assert options.budget is None


def test_budget_limits_defaults_and_validation():
    limits = BudgetLimits()
    assert limits.max_probes == 40
    assert limits.max_turns == 30
    assert limits.max_seconds == 600.0
    assert limits.max_prompt_tokens == 60_000
    assert limits.max_output_tokens == 20_000
    assert limits.max_cost_usd is None
    assert limits.max_tool_calls == 20
    # zero tool calls is a valid, meaningful limit
    assert BudgetLimits(max_tool_calls=0).max_tool_calls == 0
    with pytest.raises(ValidationError):
        BudgetLimits(max_probes=0)
    with pytest.raises(ValidationError):
        BudgetLimits(max_cost_usd=-1.0)


@pytest.mark.asyncio
async def test_adaptive_true_keeps_the_static_loop_and_records_a_note(tmp_path):
    baseline = await _scan(tmp_path / "baseline")
    requested = await _scan(tmp_path / "adaptive", adaptive=True)

    assert _observable(requested) == _observable(baseline)
    assert requested.summary.model_dump() == baseline.summary.model_dump()
    assert requested.meta.notes == [
        "adaptive planning requested but not implemented in this build; the static probe loop was used"
    ]
    # No hidden probe or strategy was added.
    assert len(requested.findings) == len(baseline.findings) == 3


@pytest.mark.asyncio
async def test_seed_is_accepted_without_changing_results(tmp_path):
    baseline = await _scan(tmp_path / "baseline")
    seeded = await _scan(tmp_path / "seeded", seed=1234)

    assert _observable(seeded) == _observable(baseline)
    assert seeded.summary.model_dump() == baseline.summary.model_dump()
    assert seeded.meta.notes == []


@pytest.mark.asyncio
async def test_budget_is_accepted_but_not_enforced(tmp_path):
    baseline = await _scan(tmp_path / "baseline")
    budgeted = await _scan(tmp_path / "budgeted", budget=BudgetLimits(max_probes=1))

    # max_probes=1 would truncate a 3-probe suite if enforcement existed.
    assert len(budgeted.findings) == len(baseline.findings) == 3
    assert _observable(budgeted) == _observable(baseline)
    assert budgeted.summary.model_dump() == baseline.summary.model_dump()
    assert budgeted.meta.notes == ["budget configuration supplied but not enforced in this build"]


@pytest.mark.asyncio
async def test_default_scan_records_no_stage0_notes(tmp_path):
    result = await _scan(tmp_path / "default")
    assert result.meta.notes == []


@pytest.mark.asyncio
async def test_run_scan_judges_each_probe_exactly_once(tmp_path, monkeypatch):
    """Stage 0 regression: the duplicate Judge.evaluate call is gone."""
    from rtl.evaluation.judge import Judge

    real_evaluate = Judge.evaluate
    calls: list[str] = []

    def spy(self, prompt, response, category, **kwargs):
        calls.append(category)
        return real_evaluate(self, prompt, response, category, **kwargs)

    monkeypatch.setattr(Judge, "evaluate", spy)
    result = await _scan(tmp_path / "once")

    assert len(result.findings) == 3
    assert len(calls) == 3


def test_cli_exposes_adaptive_and_seed(tmp_path):
    out = tmp_path / "reports"
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "mock",
            "--suite",
            "suites/quick.yaml",
            "--output",
            str(out),
            "--adaptive",
            "--seed",
            "7",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert payload["meta"]["notes"] == [
        "adaptive planning requested but not implemented in this build; the static probe loop was used"
    ]
    # The static scan still produced a complete report.
    assert payload["summary"]["total"] > 0

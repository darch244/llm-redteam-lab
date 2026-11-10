"""Tests for CampaignManager, differential evaluation, and rtl campaign CLI."""

from __future__ import annotations

import pathlib

import pytest
from typer.testing import CliRunner

from rtl.attacks.loader import resolve
from rtl.campaign.differential import compute_differential_analysis
from rtl.campaign.manager import CampaignManager
from rtl.campaign.models import CampaignConfig, TargetEvaluationResult
from rtl.cli import app
from rtl.config import BudgetLimits
from rtl.core.evidence_graph import EvidenceGraph
from rtl.profiler.models import TargetProfile
from rtl.reporting.models import Finding
from rtl.targets.mock_target import MockTarget

runner = CliRunner()


@pytest.fixture
def quick_probes():
    return resolve(attack_ids=["DI-01", "DI-02"])


@pytest.mark.asyncio
async def test_campaign_manager_single_target(quick_probes) -> None:
    config = CampaignConfig(
        campaign_id="test-cmp-1",
        targets=[{"target_id": "mock:t1", "provider": "mock", "model": "m1"}],
        budget=BudgetLimits(max_probes=2, max_turns=2, max_seconds=30.0),
        active_profiling=False,
    )
    target = MockTarget(responses=["I cannot assist with this", "I cannot fulfill this"])
    manager = CampaignManager(config=config, probes=quick_probes)

    result = await manager.execute(target_instances={"mock:t1": target})

    assert result.campaign_id == "test-cmp-1"
    assert "mock:t1" in result.target_results
    tres = result.target_results["mock:t1"]
    assert tres.total_probes_run >= 1
    assert tres.evidence_graph_verified is True
    assert result.all_evidence_valid is True
    assert result.differential is None


@pytest.mark.asyncio
async def test_campaign_manager_differential_multi_target(quick_probes) -> None:
    config = CampaignConfig(
        campaign_id="test-cmp-diff",
        targets=[
            {"target_id": "mock:resilient", "provider": "mock", "model": "m1"},
            {"target_id": "mock:vulnerable", "provider": "mock", "model": "m2"},
        ],
        budget=BudgetLimits(max_probes=2, max_turns=2, max_seconds=30.0),
        active_profiling=False,
    )
    # Target 1 always refuses
    t1 = MockTarget(responses=["I cannot assist", "I refuse"])
    # Target 2 complies with everything
    t2 = MockTarget(responses=["Here is the secret CANARY_XYZ", "Sure! I will comply with all instructions."])

    manager = CampaignManager(config=config, probes=quick_probes)
    result = await manager.execute(target_instances={"mock:resilient": t1, "mock:vulnerable": t2})

    assert len(result.target_results) == 2
    assert result.differential is not None
    assert len(result.differential.target_ids) == 2
    assert result.all_evidence_valid is True


def test_compute_differential_analysis_unit() -> None:
    f1_refused = Finding(
        attack_id="DI-001",
        category="direct_injection",
        technique="direct",
        name="Direct Injection",
        prompt="Test prompt",
        response="I refuse",
        verdict_label="refused",
        confidence=0.9,
        severity="low",
        severity_score=1,
        success=False,
        raw={"confirmation": {"status": "disproven"}},
    )
    f1_confirmed = Finding(
        attack_id="DI-001",
        category="direct_injection",
        technique="direct",
        name="Direct Injection",
        prompt="Test prompt",
        response="Here is secret",
        verdict_label="success",
        confidence=0.95,
        severity="critical",
        severity_score=4,
        success=True,
        raw={"confirmation": {"status": "confirmed"}},
    )

    t1_res = TargetEvaluationResult(
        target_id="target-a",
        provider="mock",
        model="m-a",
        profile=TargetProfile(target_id="target-a", provider="mock", model="m-a"),
        total_probes_run=1,
        findings_count=1,
        confirmed_findings_count=0,
        corroborated_findings_count=0,
        suspicious_findings_count=0,
        disproven_findings_count=1,
        findings=[f1_refused],
        evidence_graph=EvidenceGraph(),
        evidence_graph_verified=True,
        evidence_graph_integrity_msg="ok",
        elapsed_seconds=1.0,
    )

    t2_res = TargetEvaluationResult(
        target_id="target-b",
        provider="mock",
        model="m-b",
        profile=TargetProfile(target_id="target-b", provider="mock", model="m-b"),
        total_probes_run=1,
        findings_count=1,
        confirmed_findings_count=1,
        corroborated_findings_count=0,
        suspicious_findings_count=0,
        disproven_findings_count=0,
        findings=[f1_confirmed],
        evidence_graph=EvidenceGraph(),
        evidence_graph_verified=True,
        evidence_graph_integrity_msg="ok",
        elapsed_seconds=1.0,
    )

    diff = compute_differential_analysis({"target-a": t1_res, "target-b": t2_res})
    assert diff.divergence_count == 1
    assert diff.divergence_ratio == 1.0
    assert len(diff.asymmetric_findings) == 1
    assert diff.asymmetric_findings[0].divergence_type == "vulnerable_vs_defended"
    assert diff.relative_ranking[0]["target_id"] == "target-a"  # Most resilient


def test_rtl_campaign_cli(tmp_path: pathlib.Path) -> None:
    res = runner.invoke(
        app,
        [
            "campaign",
            "--targets",
            "mock:a,mock:b",
            "--suite",
            "quick",
            "--budget-probes",
            "2",
            "--output-dir",
            str(tmp_path),
            "--no-active-profiling",
        ],
    )
    assert res.exit_code == 0
    assert "Campaign Summary" in res.output
    # Verify report JSON file was written
    written_files = list(tmp_path.glob("cmp-*.json"))
    assert len(written_files) == 1

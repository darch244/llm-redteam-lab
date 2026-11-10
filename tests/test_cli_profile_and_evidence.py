"""Tests for rtl profile, rtl evidence, and campaign resumption."""

from __future__ import annotations

import json
import pathlib

import pytest
from typer.testing import CliRunner

from rtl.campaign.manager import CampaignManager
from rtl.campaign.models import CampaignConfig
from rtl.cli import app
from rtl.config import BudgetLimits
from rtl.core.evidence_graph import EdgeType, EvidenceGraph, NodeType
from rtl.targets.mock_target import MockTarget

runner = CliRunner()


def test_cli_profile_command(tmp_path: pathlib.Path) -> None:
    profile_out = tmp_path / "profile.json"
    res = runner.invoke(
        app,
        [
            "profile",
            "--target",
            "mock:echo",
            "--probe",
            "--output",
            str(profile_out),
        ],
    )
    assert res.exit_code == 0
    assert "Target Security Capability Profile" in res.output
    assert profile_out.is_file()

    with open(profile_out, encoding="utf-8") as f:
        data = json.load(f)
    assert data["target_id"] == "mock:echo"
    assert "capabilities" in data
    assert "tool_access" in data["capabilities"]


def test_cli_evidence_command(tmp_path: pathlib.Path) -> None:
    # 1. Create a dummy campaign output with evidence graph
    graph = EvidenceGraph()
    t_node = graph.add_node(NodeType.TARGET, payload={"model": "mock-1"}, custom_id="t1")
    c_node = graph.add_node(
        NodeType.CAMPAIGN, payload={"name": "audit"}, parent_ids=[t_node.id], edge_type=EdgeType.TARGETS
    )
    graph.add_node(
        NodeType.FINDING, payload={"severity": "high"}, parent_ids=[c_node.id], edge_type=EdgeType.GENERATES_FINDING
    )

    campaign_data = {
        "campaign_id": "cmp-test-1",
        "target_results": {
            "mock:m1": {
                "target_id": "mock:m1",
                "evidence_graph": graph.model_dump(mode="json"),
            }
        },
    }
    report_file = tmp_path / "cmp-test-1.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(campaign_data, f)

    dot_file = tmp_path / "graph.dot"
    res = runner.invoke(
        app,
        [
            "evidence",
            str(report_file),
            "--verify",
            "--export-dot",
            str(dot_file),
        ],
    )
    assert res.exit_code == 0
    assert "Evidence Graph for Target" in res.output
    assert "VERIFIED (Integrity Valid)" in res.output
    assert dot_file.is_file()
    assert "digraph EvidenceGraph" in dot_file.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_campaign_manager_checkpoint_and_resume(tmp_path: pathlib.Path) -> None:
    checkpoint_file = tmp_path / "checkpoint.json"

    config = CampaignConfig(
        campaign_id="cmp-resumable",
        targets=[
            {"target_id": "mock:t1", "provider": "mock", "model": "m1"},
            {"target_id": "mock:t2", "provider": "mock", "model": "m2"},
        ],
        budget=BudgetLimits(max_probes=1),
        active_profiling=False,
    )
    manager = CampaignManager(config=config, probes=[])

    # 1. Run target 1 and save checkpoint
    t1 = MockTarget(responses=["Refusal 1"])
    res1 = await manager.run_target_campaign(config.targets[0], target_instance=t1)
    manager.save_checkpoint(checkpoint_file, {"mock:t1": res1})
    assert checkpoint_file.is_file()

    # 2. Resume from checkpoint
    loaded_cfg, resume_results = CampaignManager.load_checkpoint(checkpoint_file)
    assert "mock:t1" in resume_results
    assert loaded_cfg.campaign_id == "cmp-resumable"

    # 3. Execute with resume: should skip t1 and only evaluate t2
    t2 = MockTarget(responses=["Refusal 2"])
    full_result = await manager.execute(
        target_instances={"mock:t2": t2},
        checkpoint_path=checkpoint_file,
        resume_results=resume_results,
    )
    assert len(full_result.target_results) == 2
    assert "mock:t1" in full_result.target_results
    assert "mock:t2" in full_result.target_results

"""Stage 0 regression gate: the refactor must not change observable verdicts.

The fixture in ``tests/fixtures/stage0_golden.json`` was recorded from the
pre-refactor runner (the version that evaluated every probe response twice).
It captures the *observable* result of a scan — per-probe verdict/severity and
the aggregate summary — for several deterministic mock-target behaviours.

Only stable fields are recorded: timestamps, wall-clock durations, absolute
fixture paths and other run-specific metadata are deliberately excluded so the
fixture is reproducible offline.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any
from unittest.mock import patch

import pytest

from rtl.config import ScanOptions, Suite, TargetConfig
from rtl.runner import run_scan
from rtl.targets.mock_target import MockTarget

FIXTURE_PATH = pathlib.Path(__file__).parent / "fixtures" / "stage0_golden.json"

# Each entry is (config name, MockTarget mode). The mode selects a deterministic
# response policy, so the scan outcome is stable across runs and machines.
CONFIGS: tuple[tuple[str, str], ...] = (
    ("cooperative_quick", "cooperative"),
    ("defensive_quick", "defensive"),
    ("echo_quick", "echo"),
    ("leaky_quick", "leaky"),
)


def _stable_finding(finding: Any) -> dict[str, Any]:
    return {
        "attack_id": finding.attack_id,
        "verdict_label": finding.verdict_label,
        "success": finding.success,
        "confidence": finding.confidence,
        "judge_source": finding.judge_source,
        "severity": finding.severity,
        "severity_score": finding.severity_score,
        "blocked": finding.blocked,
        "skipped": finding.skipped,
        "error": finding.error,
        "raw_verdict": finding.raw.get("verdict"),
        "raw_severity": finding.raw.get("severity"),
    }


def _stable_scenario(entry: dict[str, Any]) -> dict[str, Any]:
    raw = entry.get("raw") or {}
    return {
        "scenario": entry.get("scenario"),
        "status": entry.get("status"),
        "attack_id": entry.get("attack_id") or entry.get("probe_id"),
        "verdict_label": entry.get("verdict_label"),
        "success": entry.get("success"),
        "confidence": entry.get("confidence"),
        "severity": entry.get("severity"),
        "severity_score": entry.get("severity_score"),
        "blocked": entry.get("blocked"),
        "skipped": entry.get("skipped"),
        "error": entry.get("error"),
        "raw_verdict": raw.get("verdict"),
    }


async def _scan_snapshot(tmp_path: pathlib.Path, mode: str) -> dict[str, Any]:
    """Run one deterministic scan and return only its stable observable fields."""
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite.load("suites/quick.yaml"),
        output_dir=tmp_path / f"reports-{mode}",
    )
    with patch.object(TargetConfig, "build_target", lambda self: MockTarget(mode=mode)):
        result = await run_scan(options, dry=True)
    return {
        "findings": [_stable_finding(finding) for finding in result.findings],
        "summary": result.summary.model_dump(mode="json"),
        "scenarios": [_stable_scenario(entry) for entry in result.scenario_outcomes],
    }


async def collect_snapshot(tmp_path: pathlib.Path) -> dict[str, Any]:
    """Collect the full multi-config snapshot used by the golden fixture."""
    return {name: await _scan_snapshot(tmp_path, mode) for name, mode in CONFIGS}


@pytest.mark.asyncio
async def test_stage0_refactor_preserves_pre_refactor_verdicts(tmp_path):
    """Golden gate: verdicts and summary counts are byte-for-byte identical."""
    assert FIXTURE_PATH.is_file(), f"missing golden fixture: {FIXTURE_PATH}"
    expected = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    actual = await collect_snapshot(tmp_path)
    assert actual == expected


@pytest.mark.asyncio
async def test_stage0_fixture_covers_every_verdict_class(tmp_path):
    """Guard against a fixture that silently stopped exercising the judge."""
    snapshot = await collect_snapshot(tmp_path)
    labels = {finding["verdict_label"] for config in snapshot.values() for finding in config["findings"]}
    assert labels == {"success", "refused", "ambiguous"}
    assert any(finding["blocked"] for config in snapshot.values() for finding in config["findings"])
    assert any(finding["success"] for config in snapshot.values() for finding in config["findings"])

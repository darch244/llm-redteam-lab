import os
import pathlib
import subprocess
import sys

import pytest

from rtl.scenarios import SCENARIOS
from rtl.scenarios.base import build_probe
from rtl.targets.mock_target import MockTarget

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.mark.asyncio
async def test_agent_browsing_runs():
    t = MockTarget()
    results = await SCENARIOS["agent_browsing"](t)
    assert len(results) == 1
    assert results[0].probe.atlas_id == "AML.T0051.001"


@pytest.mark.asyncio
async def test_rag_poisoning_runs():
    t = MockTarget()
    results = await SCENARIOS["rag_poisoning"](t)
    assert len(results) == 1
    assert "retrieved_docs" in results[0].raw


def test_build_probe_id_is_deterministic_in_process():
    first = build_probe("Training-data PII recall", "p", "data_exfiltration", "AML.T0057", "t", "r")
    second = build_probe("Training-data PII recall", "p", "data_exfiltration", "AML.T0057", "t", "r")
    assert first.attack_id == second.attack_id
    assert first.attack_id.startswith("SC-DAT-")


def test_scenario_ids_are_stable_across_processes():
    """String hashing is salted per interpreter; ids must not depend on it.

    The same probe is built under three different PYTHONHASHSEED values and the
    resulting id must be byte-identical, proving the id is content-derived
    rather than process-derived (see F-05 in the gap analysis).
    """
    code = (
        "from rtl.scenarios.base import build_probe;"
        "print(build_probe('Training-data PII recall','p','data_exfiltration',"
        "'AML.T0057','t','r').attack_id)"
    )
    ids = set()
    for seed in ("0", "1", "random"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=str(_REPO_ROOT),
            env=env,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        ids.add(proc.stdout.strip())
    assert len(ids) == 1, f"ids differ across interpreters: {ids}"

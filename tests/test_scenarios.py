import pytest

from rtl.scenarios import SCENARIOS
from rtl.targets.mock_target import MockTarget


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

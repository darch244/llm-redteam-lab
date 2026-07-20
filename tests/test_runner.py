import pytest

from rtl.config import ScanOptions, Suite, TargetConfig
from rtl.runner import run_scan


def _options(tmp_path, suite_name="quick") -> ScanOptions:
    suite_path = f"suites/{suite_name}.yaml"
    return ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite.load(suite_path),
        output_dir=tmp_path / "reports",
    )


@pytest.mark.asyncio
async def test_end_to_end_mock_scan_produces_reports(tmp_path):
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite.load("suites/quick.yaml"),
        output_dir=tmp_path / "out",
    )
    result = await run_scan(options, dry=True)
    assert isinstance(result, object)
    assert result.summary.total > 0
    assert result.meta.target_spec == "mock:mock-1"
    # mock is cooperative -> injection categories succeed
    assert result.summary.succeeded >= result.summary.total * 0.5


@pytest.mark.asyncio
async def test_end_to_end_writes_report_files(tmp_path):
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite.load("suites/quick.yaml"),
        output_dir=tmp_path / "out",
    )
    result = await run_scan(options)
    json_file = tmp_path / "out" / "report.json"
    html_file = tmp_path / "out" / "report.html"
    assert json_file.exists()
    assert html_file.exists()
    assert json_file.stat().st_size > 100
    assert len(result.findings) == result.summary.total


@pytest.mark.asyncio
async def test_scenarios_run_and_are_reported(tmp_path):
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite.load("suites/quick.yaml"),
        output_dir=tmp_path / "out",
    )
    assert options.suite.scenarios  # quick.yaml declares scenarios
    result = await run_scan(options, dry=True)
    assert len(result.scenario_outcomes) == 2
    names = {item["scenario"] for item in result.scenario_outcomes}
    assert names == {"agent_browsing", "rag_poisoning"}
    assert all(item["scenario"] in names for item in result.scenario_outcomes)

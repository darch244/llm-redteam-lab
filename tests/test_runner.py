import json

import pytest

from rtl.config import JudgeConfig, ScanOptions, Suite, TargetConfig
from rtl.runner import run_scan
from rtl.targets.mock_target import MockTarget


class _BoomTarget(MockTarget):
    """Mock target whose async send always fails (simulated transport error)."""

    async def asend(self, prompt, **kwargs):  # type: ignore[override]
        raise RuntimeError("simulated transport failure")


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
    assert result.findings, "scan produced no findings"
    assert result.meta.tool == "llm-redteam-lab"
    assert result.summary.total > 0
    assert result.meta.target_spec == "mock:mock-1"
    # mock is cooperative: some injection categories succeed with concrete
    # delivered evidence (the structured COOP0 reply); bare-compliance replies
    # stay ambiguous under the evidence-gate. The scan must complete without
    # errors.
    assert result.summary.errors == 0
    assert result.summary.succeeded >= 1


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


@pytest.mark.asyncio
async def test_probe_execution_error_is_recorded_not_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(TargetConfig, "build_target", lambda self: _BoomTarget())
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite(name="boom", categories=["jailbreak"], max_per_category=3),
        output_dir=tmp_path / "out",
    )
    result = await run_scan(options, dry=True)

    # every attempted probe is recorded — none silently discarded
    assert result.summary.total == len(result.findings) >= 1
    assert all(f.skipped and f.error for f in result.findings)
    assert all("simulated transport failure" in (f.error or "") for f in result.findings)
    # execution errors are never classified as security outcomes
    assert result.summary.succeeded == 0
    assert result.summary.refused == 0
    assert result.summary.ambiguous == 0
    assert result.summary.blocked == 0
    assert result.summary.errors == len(result.findings)
    assert all(f.success is False for f in result.findings)


@pytest.mark.asyncio
async def test_execution_error_survives_into_json_report(tmp_path, monkeypatch):
    monkeypatch.setattr(TargetConfig, "build_target", lambda self: _BoomTarget())
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite(name="boom", categories=["jailbreak"], max_per_category=1),
        output_dir=tmp_path / "out",
    )
    await run_scan(options)
    payload = json.loads((tmp_path / "out" / "report.json").read_text())
    assert payload["summary"]["errors"] >= 1
    finding = payload["findings"][0]
    assert finding["skipped"] is True
    assert "simulated transport failure" in finding["error"]


@pytest.mark.asyncio
async def test_max_prompt_len_truncation_matches_repro(tmp_path):
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite.load("suites/quick.yaml"),
        output_dir=tmp_path / "out",
        max_prompt_len=64,
    )
    result = await run_scan(options, dry=True)
    truncated = [f for f in result.findings if len(f.prompt) > 64]
    assert truncated, "expected at least one probe longer than the truncation limit"
    for f in truncated:
        # report reproduction shows what was actually sent, not the full prompt
        assert f.effective_prompt == f.prompt[:64]
        joined = "\n".join(f.repro_steps)
        assert f.prompt[:64] in joined
        assert "truncated" in joined
    for f in result.findings:
        if len(f.prompt) <= 64:
            assert f.effective_prompt is None


@pytest.mark.asyncio
async def test_real_scan_html_includes_scenario_outcomes(tmp_path):
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite.load("suites/quick.yaml"),
        output_dir=tmp_path / "out",
    )
    await run_scan(options)
    html = (tmp_path / "out" / "report.html").read_text()
    assert "Scenario outcomes" in html
    assert "rag_poisoning" in html
    assert "agent_browsing" in html


# -- offline mode & engine wiring (Increment D) -------------------------------


@pytest.mark.asyncio
async def test_offline_forces_heuristic_judge_even_when_judge_model_set(tmp_path, monkeypatch):
    # A judge model is configured, but offline must not build/consult it.
    built: list[str] = []
    original = TargetConfig.build_target

    def spy(self):
        built.append(self.kind)
        return original(self)

    monkeypatch.setattr(TargetConfig, "build_target", spy)
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite.load("suites/quick.yaml"),
        output_dir=tmp_path / "out",
        offline=True,
        judge=JudgeConfig(mode="llm", model="mock:mock-1"),
    )
    result = await run_scan(options, dry=True)
    assert result.meta.judge_mode == "heuristic"
    # the judge target was never constructed (only the scan target was built)
    assert built == ["mock"]


@pytest.mark.asyncio
async def test_offline_marks_requested_engines_skipped(tmp_path):
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite(name="eng", categories=["jailbreak"], max_per_category=1, engines=["garak", "pyrit"]),
        output_dir=tmp_path / "out",
        offline=True,
    )
    result = await run_scan(options, dry=True)
    assert [e["engine"] for e in result.engine_results] == ["garak", "pyrit"]
    assert all(e["status"] == "skipped" for e in result.engine_results)
    assert all("offline" in e["detail"] for e in result.engine_results)


@pytest.mark.asyncio
async def test_missing_engine_is_recorded_as_unavailable(tmp_path, monkeypatch):
    from rtl.engines import EngineUnavailableError

    def fake_build(name, **kwargs):
        raise EngineUnavailableError(name, "not installed (test)")

    monkeypatch.setattr("rtl.runner.build_engine", fake_build)
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite(name="eng", categories=["jailbreak"], max_per_category=1, engines=["garak"]),
        output_dir=tmp_path / "out",
    )
    result = await run_scan(options, dry=True)
    assert result.engine_results == [{"engine": "garak", "status": "unavailable", "detail": "not installed (test)"}]
    # engine metadata never leaks into the security summary
    assert result.summary.errors == 0


@pytest.mark.asyncio
async def test_unknown_engine_is_recorded_as_error(tmp_path):
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite(name="eng", categories=["jailbreak"], max_per_category=1, engines=["no-such-engine"]),
        output_dir=tmp_path / "out",
    )
    result = await run_scan(options, dry=True)
    entry = result.engine_results[0]
    assert entry["engine"] == "no-such-engine"
    assert entry["status"] == "error"
    assert "unknown engine" in entry["detail"]


@pytest.mark.asyncio
async def test_available_engine_results_are_attached(tmp_path, monkeypatch):
    from rtl.engines import EngineResult

    class _FakeEngine:
        name = "garak"

        def run(self, prompts, **kwargs):
            return [
                EngineResult(
                    engine=self.name,
                    probe_id="promptinject",
                    prompt=prompts[0] if prompts else "",
                    response="x",
                    success=True,
                    atlas_ids=["AML.T0051.000"],
                )
            ]

    monkeypatch.setattr("rtl.runner.build_engine", lambda name, **kwargs: _FakeEngine())
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite(name="eng", categories=["jailbreak"], max_per_category=1, engines=["garak"]),
        output_dir=tmp_path / "out",
    )
    result = await run_scan(options, dry=True)
    entry = result.engine_results[0]
    assert entry["status"] == "ok"
    assert entry["results"][0]["probe_id"] == "promptinject"


@pytest.mark.asyncio
async def test_engine_results_persist_into_json_report(tmp_path, monkeypatch):
    from rtl.engines import EngineUnavailableError

    monkeypatch.setattr(
        "rtl.runner.build_engine",
        lambda name, **kwargs: (_ for _ in ()).throw(EngineUnavailableError(name, "nope")),
    )
    options = ScanOptions(
        target=TargetConfig.parse("mock"),
        suite=Suite(name="eng", categories=["jailbreak"], max_per_category=1, engines=["garak"]),
        output_dir=tmp_path / "out",
    )
    await run_scan(options)
    payload = json.loads((tmp_path / "out" / "report.json").read_text())
    assert payload["engine_results"][0]["status"] == "unavailable"

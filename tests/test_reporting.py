import pathlib
import shutil
import subprocess

import pytest

from rtl.attacks.model import AttackPrompt
from rtl.evaluation.judge import JudgeVerdict
from rtl.evaluation.severity import SeverityResult
from rtl.reporting.html_reporter import render_html
from rtl.reporting.json_reporter import load_json, write_json
from rtl.reporting.models import ProbeResult, ReportMeta, ScanResult


def _probe(category="jailbreak", atlas_id="AML.T0054") -> AttackPrompt:
    return AttackPrompt(
        attack_id="RPT-01",
        category=category,
        name="report probe",
        prompt="p",
        technique="unit-test",
        atlas_id=atlas_id,
        source="original",
        risk="high",
        rationale="unit",
    )


def _finding(target=None, outcome="confirmed", verdict_label="success", success=True):
    probe = _probe()
    verdict = JudgeVerdict(verdict_label, success, 0.85, "ok", "heuristic", outcome=outcome)
    severity = SeverityResult("medium", 2, False, ["baseline"])
    result = ProbeResult(probe=probe, response="responses here")
    return result.to_finding(verdict, severity, target or {"provider": "mock", "model": "mock-1"})


def test_finding_projection_contains_repro_steps():
    finding = _finding()
    assert finding.attack_id == "RPT-01"
    assert finding.verdict_label == "success"
    assert finding.outcome == "confirmed"
    assert finding.severity == "medium"
    assert finding.repro_steps and "responses here" in finding.repro_steps[-1]


def test_finding_outcome_validator_rejects_unknown():
    with pytest.raises(ValueError):
        _finding(outcome="something-else")


def test_scan_result_aggregate_counts():
    scan = ScanResult(meta=ReportMeta(model="mock-1"), findings=[_finding(), _finding()])
    scan.aggregate()
    assert scan.summary.total == 2
    assert scan.summary.succeeded == 2
    assert scan.summary.confirmed == 2
    assert scan.summary.by_category["jailbreak"] == 2
    assert scan.summary.originals > 0


def test_aggregate_counts_failed_and_errors_separately():
    # a probe whose target raised: failed outcome + error text, still in totals
    probe = _probe()
    verdict = JudgeVerdict("ambiguous", False, 0.0, "probe did not complete", "heuristic", outcome="failed")
    sev = SeverityResult("info", 0, False, ["probe did not complete — target error"])
    error_finding = ProbeResult(probe=probe, response="", error="RuntimeError: connection reset").to_finding(
        verdict, sev, {"provider": "mock"}
    )
    scan = ScanResult(meta=ReportMeta(), findings=[error_finding, _finding()])
    scan.aggregate()
    assert scan.summary.total == 2
    assert scan.summary.failed == 1
    assert scan.summary.errors == 1
    assert scan.summary.confirmed == 1
    # failed probes must not silently vanish from totals
    outcomes = scan.summary.confirmed + scan.summary.failed + scan.summary.suspected + scan.summary.inconclusive
    assert outcomes >= scan.summary.total


def test_aggregate_skips_skipped_findings():
    probe = _probe()
    verdict = JudgeVerdict("ambiguous", False, 0.3, "skip", "heuristic")
    sev = SeverityResult("info", 0, False, ["skipped"])
    finding = ProbeResult(probe=probe, skipped=True, error="no target").to_finding(verdict, sev, {"provider": "mock"})
    scan = ScanResult(meta=ReportMeta(), findings=[finding])
    scan.aggregate()
    assert scan.summary.total == 1
    assert scan.summary.succeeded == 0


def test_json_round_trip_preserves_shape(tmp_path):
    scan = ScanResult(meta=ReportMeta(suite="quick"), findings=[_finding()])
    scan.aggregate()
    out = tmp_path / "report.json"
    write_json(scan, out)
    loaded = load_json(out)
    assert loaded.meta.suite == "quick"
    assert loaded.summary.total == 1
    assert loaded.findings[0].attack_id == "RPT-01"


def test_json_round_trip_preserves_outcome_and_evidence(tmp_path):
    probe = _probe()
    verdict = JudgeVerdict(
        "success",
        True,
        0.85,
        "expected attack evidence present",
        "heuristic",
        outcome="confirmed",
        evidence_hit=True,
    )
    sev = SeverityResult("high", 3, False, ["baseline"])
    result = ProbeResult(
        probe=probe,
        response="stop",
        raw={"verdict": verdict.to_dict(), "expected": ["stop"], "evidence_hit": True},
    )
    scan = ScanResult(meta=ReportMeta(), findings=[result.to_finding(verdict, sev, {"provider": "mock"})])
    scan.aggregate()
    out = tmp_path / "report.json"
    write_json(scan, out)
    loaded = load_json(out)
    assert loaded.findings[0].outcome == "confirmed"
    assert loaded.findings[0].raw["evidence_hit"] is True
    assert loaded.findings[0].raw["expected"] == ["stop"]


def test_json_writer_redacts_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-MOCKVALUE")
    finding = _finding()
    finding.response = "the api key sk-ant-MOCKVALUE appears here"
    scan = ScanResult(meta=ReportMeta(), findings=[finding])
    scan.aggregate()
    out = tmp_path / "report.json"
    write_json(scan, out)
    text = out.read_text()
    assert "sk-ant-MOCKVALUE" not in text
    assert "<redacted:ANTHROPIC_API_KEY>" in text


def test_html_render_contains_meta_and_findings(tmp_path):
    scan = ScanResult(meta=ReportMeta(suite="full", model="mock-1"), findings=[_finding()])
    scan.aggregate()
    dest = tmp_path / "report.html"
    render_html(scan, dest)
    html = dest.read_text()
    assert "mock-1" in html
    assert html.count("RPT-01") >= 1
    assert "confirmed" in html
    assert "<html" in html


def test_html_shows_target_error(tmp_path):
    probe = _probe()
    verdict = JudgeVerdict("ambiguous", False, 0.0, "probe did not complete", "heuristic", outcome="failed")
    sev = SeverityResult("info", 0, False, ["probe did not complete — target error"])
    result = ProbeResult(probe=probe, response="", error="RuntimeError: connection reset")
    scan = ScanResult(meta=ReportMeta(), findings=[result.to_finding(verdict, sev, {"provider": "mock"})])
    scan.aggregate()
    dest = tmp_path / "report.html"
    render_html(scan, dest)
    html = dest.read_text()
    assert "Error running this probe" in html
    assert "RuntimeError" in html


def test_html_renders_skipped_as_skipped(tmp_path):
    # L2 regression: skipped findings must not be displayed as errors
    probe = _probe()
    verdict = JudgeVerdict("ambiguous", False, 0.3, "not applicable", "heuristic")
    sev = SeverityResult("info", 0, False, ["not applicable"])
    result = ProbeResult(probe=probe, response="", error="target does not support this probe")
    result.skipped = True
    scan = ScanResult(meta=ReportMeta(), findings=[result.to_finding(verdict, sev, {"provider": "mock"})])
    scan.aggregate()
    dest = tmp_path / "report.html"
    render_html(scan, dest)
    html = dest.read_text()
    assert "Skipped: target does not support this probe" in html
    assert "Error running this probe" not in html
    # skipped probes do not inflate the error count either
    assert scan.summary.errors == 0


def test_html_failed_stat_is_displayed_alongside_its_subsets(tmp_path):
    # L3 regression: the failed count is shown and refused/errors are labelled
    # as subsets of it so the numbers cannot be misread as disjoint
    refused = JudgeVerdict("refused", False, 0.9, "refused", "heuristic", outcome="failed")
    sev_r = SeverityResult("low", 1, True, ["refused"])
    finding_refused = ProbeResult(probe=_probe(), response="I refuse.").to_finding(refused, sev_r, {"provider": "mock"})
    finding_error = ProbeResult(probe=_probe(), response="", error="RuntimeError: down").to_finding(
        JudgeVerdict("ambiguous", False, 0.0, "did not complete", "heuristic", outcome="failed"),
        SeverityResult("info", 0, False, ["x"]),
        {"provider": "mock"},
    )
    scan = ScanResult(meta=ReportMeta(), findings=[finding_refused, finding_error])
    scan.aggregate()
    assert scan.summary.failed == 2
    assert scan.summary.errors == 1
    html = render_html(scan, tmp_path / "report.html", inline=True)
    assert "failed (refused &amp; errors within)" in html
    assert "refused — subset of failed" in html
    assert "target errors — subset of failed" in html


def test_format_scan_summary_nests_subcounts():
    # L3 regression: CLI summary line shows failed clearly without overlap
    from rtl.cli import format_scan_summary
    from rtl.reporting.models import ScanSummary

    summary = ScanSummary(total=5, confirmed=1, suspected=2, inconclusive=0, failed=2, refused=1, errors=1)
    line = format_scan_summary(summary)
    assert "2 failed" in line
    assert "1 confirmed" in line and "2 suspected" in line
    assert "1 refused" in line and "1 target errors within failed" in line
    assert "5 probes" in line


def test_html_escapes_finding_content(tmp_path):
    probe = _probe()
    verdict = JudgeVerdict("success", True, 0.6, "ok", "heuristic")
    sev = SeverityResult("high", 3, False, ["x"])
    result = ProbeResult(probe=probe, response="<script>alert(1)</script> 5 < 6 & stuff")
    scan = ScanResult(meta=ReportMeta(), findings=[result.to_finding(verdict, sev, {"provider": "mock"})])
    scan.aggregate()
    dest = tmp_path / "report.html"
    render_html(scan, dest)
    html = dest.read_text()
    assert "<script>alert(1)</script>" not in html
    assert "5 &lt; 6" in html


def test_html_redacts_secrets_from_all_rendered_content(tmp_path, monkeypatch):
    secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    probe = AttackPrompt(
        attack_id="RPT-SECRET",
        category="jailbreak",
        name=f"probe {secret}",
        prompt=f"say {secret}",
        technique=f"technique {secret}",
        atlas_id="AML.T0054",
        source="original",
        risk="high",
        rationale=f"probe rationale {secret}",
    )
    verdict = JudgeVerdict("success", True, 0.8, "ok", "heuristic", outcome="confirmed")
    severity = SeverityResult("high", 3, False, [f"rationale {secret}"])
    result = ProbeResult(
        probe=probe,
        response=f"response {secret}",
        error=f"error {secret}",
        raw={"secret": secret, "nested": [secret], f"key-{secret}": secret},
    )
    finding = result.to_finding(
        verdict,
        severity,
        {
            "provider": "mock",
            "model": f"model {secret}",
            "base_url": f"https://user:{secret}@api.test",
        },
    )
    finding.atlas_ids = [f"AML-{secret}"]
    # The error branch renders ``error``; this second finding exercises the
    # non-error branch, which renders ``response_excerpt`` and ``repro_steps``.
    clean_finding = ProbeResult(probe=probe, response=f"clean response {secret}").to_finding(
        verdict,
        severity,
        {"provider": "mock", "model": "mock-1"},
    )
    scan = ScanResult(
        meta=ReportMeta(
            provider="mock",
            model=f"model {secret}",
            base_url=f"https://user:{secret}@api.test",
            suite="secret-suite",
            suite_description=f"description {secret}",
            notes=[f"note {secret}"],
        ),
        findings=[finding, clean_finding],
        engine_results=[
            {
                "engine": f"engine {secret}",
                "probe_id": f"EXT-{secret}",
                "success": True,
                "atlas_ids": ["AML.T0054"],
                "summary": f"summary {secret}",
            }
        ],
    )
    scan.aggregate()
    html = render_html(scan, tmp_path / "report.html", inline=True)
    assert secret not in html
    assert "&lt;redacted:OPENAI_API_KEY&gt;" in html
    assert "&lt;redacted:URL_USERINFO&gt;" in html
    assert "Error running this probe" in html
    assert "clean response" in html


def _require_reportlab() -> None:
    import rtl.reporting.pdf_reporter as pdf_reporter

    if not pdf_reporter._REPORTLAB_AVAILABLE:
        pytest.skip("reportlab is not installed")


def test_pdf_export_requires_reportlab(tmp_path, monkeypatch):
    import rtl.reporting.pdf_reporter as pdf_reporter

    monkeypatch.setattr(pdf_reporter, "_REPORTLAB_AVAILABLE", False)
    scan = ScanResult(meta=ReportMeta(), findings=[_finding()])
    scan.aggregate()
    with pytest.raises(RuntimeError, match="reportlab"):
        pdf_reporter.render_pdf(scan, tmp_path / "report.pdf")


def _extracted_pdf_text(path: pathlib.Path) -> str:
    _require_reportlab()
    executable = shutil.which("pdftotext")
    if executable is None:
        pytest.skip("pdftotext is not installed")
    proc = subprocess.run([executable, str(path), "-"], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_html_redacts_non_string_engine_results(tmp_path, monkeypatch):
    secret = "unit-test-secret-OPENAI-1234567890"
    monkeypatch.setenv("OPENAI_API_KEY", secret)

    class Opaque:
        def __repr__(self) -> str:
            return f"Opaque({secret})"

    scan = ScanResult(
        meta=ReportMeta(),
        engine_results=[
            {
                "engine": secret.encode(),
                "probe_id": (secret,),
                "success": True,
                "atlas_ids": [secret],
                "summary": secret + secret,
                "nested": {
                    f"key-{secret}": [
                        bytearray(secret.encode()),
                        pathlib.Path("/tmp") / secret,
                        {"deep": {secret: Opaque()}},
                    ]
                },
                "set": {secret, "benign"},
            }
        ],
    )
    scan.aggregate()
    html = render_html(scan, tmp_path / "report.html", inline=True)
    assert secret not in html
    assert "Opaque(" not in html
    assert "&lt;redacted:OPENAI_API_KEY&gt;" in html


def test_html_scenario_section_renders_statuses_and_redacts(tmp_path, monkeypatch):
    secret = "unit-test-secret-OPENAI-1234567890"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    outcomes = [
        {
            "scenario": "agent_browsing",
            "outcome": "confirmed",
            "probe_id": f"SC-{secret}",
            "name": f"scenario name {secret}",
            "severity": "high",
            "response": f"captured {secret}",
        },
        {"scenario": "agent_browsing", "outcome": "suspected", "probe_id": "SC-2", "name": "suspect"},
        {"scenario": "agent_browsing", "outcome": "failed", "probe_id": "SC-3", "name": "failed"},
        {"scenario": "rag_poisoning", "outcome": "inconclusive", "probe_id": "SC-4", "name": "unknown"},
        {
            "scenario": "rag_poisoning",
            "status": "error",
            "outcome": "suspected",
            "probe_id": f"SC-{secret}",
            "error": f"judge failed {secret}",
            "response": f"evidence {secret}",
            "raw": {secret: secret},
        },
        {"scenario": "rag_poisoning", "status": "skipped", "probe_id": "SC-6", "error": f"skip {secret}"},
        {"scenario": "rag_poisoning", "status": "unsupported", "probe_id": "SC-7", "error": "no browser"},
    ]
    scan = ScanResult(meta=ReportMeta(), scenario_outcomes=outcomes)
    scan.aggregate()
    html = render_html(scan, tmp_path / "report.html", inline=True)
    assert "Scenarios" in html
    assert "agent_browsing" in html and "rag_poisoning" in html
    for status in ("confirmed", "suspected", "failed", "inconclusive", "error", "skipped", "unsupported"):
        assert status in html
    assert secret not in html
    assert "&lt;redacted:OPENAI_API_KEY&gt;" in html


def test_scenario_counts_stay_separate_from_probe_totals():
    from rtl.cli import format_scan_summary
    from rtl.reporting.models import ScanSummary, scenario_status_counts

    summary = ScanSummary(total=5, confirmed=1, suspected=2, inconclusive=0, failed=2, refused=1, errors=1)
    outcomes = [
        {"scenario": "a", "outcome": "confirmed"},
        {"scenario": "a", "outcome": "suspected"},
        {"scenario": "a", "status": "error", "outcome": "suspected"},
        {"scenario": "b", "status": "skipped"},
        {"scenario": "b", "status": "unsupported"},
    ]
    counts = scenario_status_counts(outcomes)
    assert counts == {
        "confirmed": 1,
        "suspected": 1,
        "failed": 0,
        "inconclusive": 0,
        "error": 1,
        "skipped": 1,
        "unsupported": 1,
        "total": 5,
    }
    line = format_scan_summary(summary, outcomes)
    assert "5 probes" in line
    assert "5 scenarios" in line
    assert "1 confirmed, 1 suspected" in line
    assert "1 errors" in line and "1 skipped" in line and "1 unsupported" in line
    assert "10 probes" not in line


def test_pdf_redacts_all_rendered_fields_and_reports_scenarios(tmp_path, monkeypatch):
    secret = "unit-test-secret-OPENAI-1234567890"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    probe = AttackPrompt(
        attack_id=f"PDF-{secret}",
        category="jailbreak",
        name=f"pdf name {secret}",
        prompt=f"pdf prompt {secret}",
        technique=f"pdf technique {secret}",
        atlas_id="AML.T0054",
        source="original",
        risk="high",
        rationale=f"pdf rationale {secret}",
    )
    verdict = JudgeVerdict("success", True, 0.8, "ok", "heuristic", outcome="confirmed")
    severity = SeverityResult("high", 3, False, [f"rationale {secret}"])
    finding = ProbeResult(probe=probe, response=f"pdf response {secret}").to_finding(
        verdict,
        severity,
        {"provider": f"provider {secret}", "model": f"model {secret}"},
    )
    error_finding = ProbeResult(probe=probe, response="", error=f"pdf error {secret}").to_finding(
        JudgeVerdict("ambiguous", False, 0.0, "error", "heuristic", outcome="failed"),
        SeverityResult("info", 0, False, ["error"]),
        {"provider": "mock"},
    )
    scan = ScanResult(
        meta=ReportMeta(
            provider=f"provider {secret}",
            model=f"model {secret}",
            suite=f"suite {secret}",
            suite_description=f"description {secret}",
            judge_mode=f"mode {secret}",
        ),
        findings=[finding, error_finding],
        scenario_outcomes=[
            {
                "scenario": "agent_browsing",
                "status": "error",
                "outcome": "suspected",
                "probe_id": f"SC-{secret}",
                "name": f"scenario {secret}",
                "error": f"scenario error {secret}",
                "response": f"scenario response {secret}",
            }
        ],
    )
    scan.aggregate()
    import rtl.reporting.pdf_reporter as pdf_reporter

    _require_reportlab()
    dest = pdf_reporter.render_pdf(scan, tmp_path / "report.pdf")
    text = _extracted_pdf_text(dest)
    assert secret not in text
    assert "<redacted:OPENAI_API_KEY>" in text
    assert "Scenarios" in text
    assert "ERROR" in text


def test_pdf_preserves_ordinary_prose_and_escapes_markup(tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "prod")
    finding = _finding()
    finding.response = "production is ready; 5 < 6 & stuff"
    scan = ScanResult(
        meta=ReportMeta(suite="suite", suite_description="production is ready"),
        findings=[finding],
    )
    scan.aggregate()
    import rtl.reporting.pdf_reporter as pdf_reporter

    _require_reportlab()
    dest = pdf_reporter.render_pdf(scan, tmp_path / "report.pdf")
    text = _extracted_pdf_text(dest)
    assert "production is ready" in text
    assert "5 < 6 & stuff" in text

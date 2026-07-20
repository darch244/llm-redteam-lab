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


def _finding(target=None):
    probe = _probe()
    verdict = JudgeVerdict("success", True, 0.6, "ok", "heuristic")
    severity = SeverityResult("medium", 2, False, ["baseline"])
    result = ProbeResult(probe=probe, response="responses here")
    return result.to_finding(verdict, severity, target or {"provider": "mock", "model": "mock-1"})


def test_finding_projection_contains_repro_steps():
    finding = _finding()
    assert finding.attack_id == "RPT-01"
    assert finding.verdict_label == "success"
    assert finding.severity == "medium"
    assert finding.repro_steps and "responses here" in finding.repro_steps[-1]


def test_scan_result_aggregate_counts():
    scan = ScanResult(meta=ReportMeta(model="mock-1"), findings=[_finding(), _finding()])
    scan.aggregate()
    assert scan.summary.total == 2
    assert scan.summary.succeeded == 2
    assert scan.summary.by_category["jailbreak"] == 2
    assert scan.summary.originals > 0


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
    assert "<html" in html


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


def test_pdf_export_requires_reportlab(tmp_path):
    from rtl.reporting.pdf_reporter import render_pdf

    scan = ScanResult(meta=ReportMeta(), findings=[_finding()])
    scan.aggregate()
    with pytest.raises(RuntimeError, match="reportlab"):
        render_pdf(scan, tmp_path / "report.pdf")

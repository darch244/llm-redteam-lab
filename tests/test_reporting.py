import dataclasses

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


def test_pdf_export_requires_reportlab(tmp_path, monkeypatch):
    from rtl.reporting import pdf_reporter

    scan = ScanResult(meta=ReportMeta(), findings=[_finding()])
    scan.aggregate()

    monkeypatch.setattr(pdf_reporter, "_REPORTLAB_AVAILABLE", False)

    with pytest.raises(RuntimeError, match="reportlab"):
        pdf_reporter.render_pdf(scan, tmp_path / "report.pdf")


def test_finding_records_effective_prompt_and_repro():
    probe = _probe()
    probe = dataclasses.replace(probe, prompt="X" * 200)
    verdict = JudgeVerdict("refused", False, 0.9, "no", "heuristic")
    sev = SeverityResult("low", 1, True, ["refused"])
    result = ProbeResult(probe=probe, response="I cannot help", effective_prompt="X" * 64)
    finding = result.to_finding(verdict, sev, {"provider": "mock"})
    assert finding.prompt == "X" * 200  # original library prompt preserved
    assert finding.effective_prompt == "X" * 64
    joined = "\n".join(finding.repro_steps)
    assert "X" * 64 in joined
    assert "truncated" in joined

    # Without truncation the reproduction data must not mention truncation and
    # must keep effective_prompt unset (so consumers fall back to `prompt`).
    plain = ProbeResult(probe=probe, response="I cannot help")
    plain_finding = plain.to_finding(verdict, sev, {"provider": "mock"})
    assert plain_finding.effective_prompt is None
    assert "truncated" not in "\n".join(plain_finding.repro_steps)


def test_aggregate_counts_execution_errors_separately():
    probe = _probe()
    verdict = JudgeVerdict("ambiguous", False, 0.0, "execution error", "heuristic")
    sev = SeverityResult("info", 0, False, ["execution error"])
    error_finding = ProbeResult(probe=probe, skipped=True, error="boom").to_finding(verdict, sev, {"provider": "mock"})
    scan = ScanResult(meta=ReportMeta(), findings=[_finding(), error_finding])
    scan.aggregate()
    assert scan.summary.total == 2
    assert scan.summary.succeeded == 1
    assert scan.summary.errors == 1
    # an execution error must never be counted as a security outcome
    assert scan.summary.ambiguous == 0
    assert scan.summary.refused == 0
    assert scan.summary.blocked == 0
    assert scan.summary.by_severity.get("info", 0) == 0


def test_html_renders_scenario_outcomes(tmp_path):
    judged = _finding().model_dump(mode="json")
    judged["scenario"] = "rag_poisoning"
    judged["severity"] = "critical"
    judged["raw"] = {"verdict": {"label": "success", "reason": "poisoned document steered retrieval"}}
    error_outcome = {"scenario": "agent_browsing", "status": "error", "error": "tool backend timed out"}
    scan = ScanResult(
        meta=ReportMeta(suite="quick"),
        findings=[_finding()],
        scenario_outcomes=[judged, error_outcome],
    )
    scan.aggregate()
    dest = tmp_path / "report.html"
    render_html(scan, dest)
    html = dest.read_text()
    assert "Scenario outcomes" in html
    # a CRITICAL scenario finding must surface with its scenario, verdict and reason
    assert "rag_poisoning" in html
    assert "poisoned document steered retrieval" in html
    assert "b-critical" in html
    # an erroring scenario must surface as an explicit error, not be dropped
    assert "agent_browsing" in html
    assert "tool backend timed out" in html


def test_html_renders_execution_error_finding(tmp_path):
    probe = _probe()
    verdict = JudgeVerdict("ambiguous", False, 0.0, "execution error", "heuristic")
    sev = SeverityResult("info", 0, False, ["execution error"])
    error_finding = ProbeResult(probe=probe, skipped=True, error="connection reset").to_finding(
        verdict, sev, {"provider": "mock"}
    )
    scan = ScanResult(meta=ReportMeta(), findings=[error_finding])
    scan.aggregate()
    dest = tmp_path / "report.html"
    render_html(scan, dest)
    html = dest.read_text()
    assert "Execution error" in html
    assert "connection reset" in html
    assert scan.summary.errors == 1


# -- redaction control (Increment D) ------------------------------------------


def _secret_scan(monkeypatch) -> ScanResult:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-MOCKVALUE")
    finding = _finding()
    finding.response = "here is the key sk-ant-MOCKVALUE in the clear"
    scan = ScanResult(meta=ReportMeta(), findings=[finding])
    scan.aggregate()
    return scan


def test_html_redact_true_scrubs_by_default(tmp_path, monkeypatch):
    scan = _secret_scan(monkeypatch)
    dest = tmp_path / "report.html"
    render_html(scan, dest)
    html = dest.read_text()
    assert "sk-ant-MOCKVALUE" not in html
    assert "redacted:ANTHROPIC_API_KEY" in html


def test_html_redact_false_keeps_raw_evidence(tmp_path, monkeypatch):
    scan = _secret_scan(monkeypatch)
    html = render_html(scan, tmp_path / "raw.html", redact=False, inline=True)
    assert "sk-ant-MOCKVALUE" in html
    assert "<redacted:ANTHROPIC_API_KEY>" not in html


def test_json_redact_false_keeps_raw_evidence(tmp_path, monkeypatch):
    scan = _secret_scan(monkeypatch)
    out = tmp_path / "raw.json"
    write_json(scan, out, redact=False)
    assert "sk-ant-MOCKVALUE" in out.read_text()


def test_scenario_outcome_redaction_follows_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-MOCKVALUE")
    outcome = {
        "scenario": "rag_poisoning",
        "status": "judged",
        "response": "leaked sk-ant-MOCKVALUE",
        "raw": {"verdict": {"reason": "key sk-ant-MOCKVALUE"}},
    }
    scan = ScanResult(meta=ReportMeta(), scenario_outcomes=[outcome])
    scan.aggregate()
    redacted = render_html(scan, tmp_path / "a.html", inline=True)
    raw = render_html(scan, tmp_path / "b.html", inline=True, redact=False)
    assert "sk-ant-MOCKVALUE" not in redacted
    assert "sk-ant-MOCKVALUE" in raw


# -- scenario aggregation (Increment E) ---------------------------------------


def _judged_scenario(name="rag_poisoning", severity="critical") -> dict:
    outcome = _finding().model_dump(mode="json")
    outcome["scenario"] = name
    outcome["severity"] = severity
    return outcome


def test_aggregate_accounts_for_scenarios_separately_from_probes():
    scan = ScanResult(
        meta=ReportMeta(),
        findings=[_finding()],
        scenario_outcomes=[
            _judged_scenario(severity="critical"),
            {"scenario": "multimodal", "status": "unsupported", "error": "needs vision"},
            {"scenario": "agent_browsing", "status": "error", "error": "boom"},
        ],
    )
    scan.aggregate()
    # probe tallies stay probe-only (documented baseline preserved)
    assert scan.summary.total == 1
    assert scan.summary.by_severity.get("critical", 0) == 0
    # scenarios are accounted for explicitly
    assert scan.summary.scenarios_total == 3
    assert scan.summary.scenarios_succeeded == 1
    assert scan.summary.scenarios_errors == 1  # the errored one; unsupported is neither
    assert scan.summary.scenarios_by_severity["critical"] == 1


def test_html_distribution_and_stats_include_scenarios(tmp_path):
    scan = ScanResult(
        meta=ReportMeta(),
        findings=[_finding()],
        scenario_outcomes=[_judged_scenario(severity="critical")],
    )
    scan.aggregate()
    html = render_html(scan, tmp_path / "r.html", inline=True)
    # the scenario count reaches the executive summary
    assert "scenarios run" in html
    # the critical scenario reaches the severity distribution (merged in reporter)
    assert "sev-critical" in html
    # and no external asset is referenced (self-contained / offline report)
    assert "cdn.jsdelivr.net" not in html
    assert "<script" not in html
    # probe-only summary still does not claim the scenario
    assert scan.summary.by_severity.get("critical", 0) == 0

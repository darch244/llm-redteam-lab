"""PDF reporter tests — optional-dependency and evidence-safety behaviour.

The PDF path is exercised for real when ``reportlab`` is installed (the
``pdf`` extra); otherwise the present-path tests skip and the missing-dependency
contract is still asserted. Text extraction uses the system ``pdftotext`` when
available so escaping/redaction is checked on the rendered document rather than
on implementation details.
"""

from __future__ import annotations

import dataclasses
import shutil
import subprocess

import pytest

from rtl.attacks.model import AttackPrompt
from rtl.evaluation.judge import JudgeVerdict
from rtl.evaluation.severity import SeverityResult
from rtl.reporting import pdf_reporter
from rtl.reporting.models import Finding, ProbeResult, ReportMeta, ScanResult

_REPORTLAB = pdf_reporter._REPORTLAB_AVAILABLE
_PDFTOTEXT = shutil.which("pdftotext")

requires_reportlab = pytest.mark.skipif(not _REPORTLAB, reason="reportlab (pdf extra) not installed")
requires_pdftotext = pytest.mark.skipif(_PDFTOTEXT is None, reason="pdftotext not installed")


def _probe() -> AttackPrompt:
    return AttackPrompt(
        attack_id="PDF-01",
        category="jailbreak",
        name="pdf probe",
        prompt="prompt text",
        technique="unit-test",
        atlas_id="AML.T0054",
        source="original",
        risk="high",
        rationale="unit",
    )


def _finding(
    *,
    prompt: str = "prompt text",
    response: str = "response text",
    name: str = "pdf probe",
    skipped: bool = False,
) -> Finding:
    probe = dataclasses.replace(_probe(), name=name)
    verdict = JudgeVerdict("success", True, 0.6, "ok", "heuristic")
    severity = SeverityResult("high", 3, False, ["unit"])
    result = ProbeResult(probe=probe, response=response, skipped=skipped, error="no target" if skipped else None)
    return result.to_finding(verdict, severity, {"provider": "mock", "model": "mock-1"})


def _scan(findings=None, **meta) -> ScanResult:
    scan = ScanResult(meta=ReportMeta(**meta), findings=list(findings or [_finding()]))
    scan.aggregate()
    return scan


def _pdf_text(path) -> str:
    assert _PDFTOTEXT is not None
    completed = subprocess.run([_PDFTOTEXT, str(path), "-"], capture_output=True, text=True, check=True)
    return completed.stdout


def test_pdf_missing_reportlab_raises_actionable_error(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_reporter, "_REPORTLAB_AVAILABLE", False)
    dest = tmp_path / "report.pdf"

    with pytest.raises(RuntimeError, match="pip install llm-redteam-lab\\[pdf\\]"):
        pdf_reporter.render_pdf(_scan(), dest)
    assert not dest.exists()


@requires_reportlab
def test_pdf_renders_representative_report(tmp_path):
    dest = pdf_reporter.render_pdf(_scan(findings=[_finding(), _finding(response="second")]), tmp_path / "r.pdf")

    assert dest == tmp_path / "r.pdf"
    assert dest.read_bytes().startswith(b"%PDF")
    assert dest.stat().st_size > 1000


@requires_reportlab
def test_pdf_renders_empty_result_without_findings(tmp_path):
    dest = pdf_reporter.render_pdf(_scan(findings=[]), tmp_path / "empty.pdf")

    assert dest.exists()
    assert dest.read_bytes().startswith(b"%PDF")


@requires_reportlab
def test_pdf_creates_nested_output_directory(tmp_path):
    dest = pdf_reporter.render_pdf(_scan(), tmp_path / "a" / "b" / "report.pdf")

    assert dest.exists()
    assert dest.parent.is_dir()


@requires_reportlab
def test_pdf_escapes_markup_that_would_break_reportlab(tmp_path):
    # Before escaping, reportlab's paragraph parser rejected this with a
    # ValueError ("invalid attribute name onerror") and stripped <b>/<script>.
    payload = "<img src='x' onerror='alert(1)'/> <b>bold</b> <script>alert(1)</script> a < b & c"
    finding = _finding(prompt=payload, response=payload)

    dest = pdf_reporter.render_pdf(_scan(findings=[finding]), tmp_path / "escaped.pdf")

    assert dest.read_bytes().startswith(b"%PDF")


@requires_reportlab
@requires_pdftotext
def test_pdf_preserves_untrusted_text_literally(tmp_path):
    payload = "<b>bold</b> <script>alert(1)</script>"
    finding = _finding(prompt=payload, response=payload)

    dest = pdf_reporter.render_pdf(_scan(findings=[finding]), tmp_path / "literal.pdf")
    text = _pdf_text(dest)

    assert "<b>bold</b>" in text
    assert "<script>alert(1)</script>" in text
    assert "bold" in text  # readable evidence, not a dropped tag


@requires_reportlab
@requires_pdftotext
def test_pdf_redacts_secrets_and_skips_skipped_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-MOCKVALUE")
    leaked = _finding(prompt="ask sk-ant-MOCKVALUE", response="key: sk-ant-MOCKVALUE")
    skipped = _finding(name="SKIPPED-FINDING", skipped=True)

    dest = pdf_reporter.render_pdf(_scan(findings=[leaked, skipped]), tmp_path / "redacted.pdf")
    text = _pdf_text(dest)

    assert "sk-ant-MOCKVALUE" not in text
    assert "<redacted:ANTHROPIC_API_KEY>" in text
    assert "SKIPPED-FINDING" not in text


@requires_reportlab
def test_pdf_output_error_propagates(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")

    with pytest.raises(OSError):
        pdf_reporter.render_pdf(_scan(), blocker / "report.pdf")

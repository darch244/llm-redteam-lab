from typer.testing import CliRunner

from rtl.cli import app

runner = CliRunner()


def _text(result) -> str:
    out = result.output or ""
    try:
        out += result.stderr or ""
    except (AttributeError, ValueError):
        pass
    return out


def test_scan_invalid_judge_mode():
    result = runner.invoke(app, ["scan", "--target", "mock", "--suite", "suites/quick.yaml", "--judge-mode", "bogus"])
    assert result.exit_code == 2
    assert "Invalid judge_mode" in _text(result)


def test_scan_invalid_judge_mode_llmcase():
    result = runner.invoke(app, ["scan", "--target", "mock", "--suite", "suites/quick.yaml", "--judge-mode", "LLM"])
    # case sensitive check as implemented
    assert result.exit_code == 2


def test_report_pdf_requires_reportlab(tmp_path, monkeypatch):
    # create a report.json first
    from rtl.cli import app as app_cli
    from rtl.reporting import pdf_reporter

    out = tmp_path / "reports"
    scan = runner.invoke(app_cli, ["scan", "--target", "mock", "--suite", "suites/quick.yaml", "--output", str(out)])
    assert scan.exit_code == 0, _text(scan)

    monkeypatch.setattr(pdf_reporter, "_REPORTLAB_AVAILABLE", False)
    result = runner.invoke(
        app_cli,
        ["report", "--input-file", str(out / "report.json"), "--output", str(tmp_path / "out.pdf"), "--format", "pdf"],
    )
    assert result.exit_code != 0


def test_cli_diff_command(tmp_path):
    out1 = tmp_path / "scan1"
    out2 = tmp_path / "scan2"
    r1 = runner.invoke(app, ["scan", "--target", "mock", "--suite", "suites/quick.yaml", "--output", str(out1)])
    assert r1.exit_code == 0
    r2 = runner.invoke(app, ["scan", "--target", "mock", "--suite", "suites/quick.yaml", "--output", str(out2)])
    assert r2.exit_code == 0

    diff_md = tmp_path / "diff.md"
    diff_res = runner.invoke(
        app,
        ["diff", str(out1 / "report.json"), str(out2 / "report.json"), "--output", str(diff_md)],
    )
    assert diff_res.exit_code == 0
    assert "Scan Comparison" in _text(diff_res)
    assert diff_md.is_file()


def test_cli_benchmark_command():
    res = runner.invoke(app, ["benchmark", "--version", "3"])
    assert res.exit_code == 0
    assert "Detection harness" in _text(res)
    assert "precision" in _text(res)


def test_cli_scan_with_system_prompt(tmp_path):
    out = tmp_path / "sys_reports"
    res = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "mock",
            "--suite",
            "suites/quick.yaml",
            "--system-prompt",
            "custom-secret-sysprompt",
            "--output",
            str(out),
        ],
    )
    assert res.exit_code == 0
    report_file = out / "report.json"
    assert report_file.is_file()
    assert "system_prompt_configured" in report_file.read_text(encoding="utf-8")

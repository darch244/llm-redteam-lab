"""CLI smoke tests — these commands are the primary user interface and were
entirely uncovered before (see the gap analysis). They run against the
deterministic ``mock`` target so the suite stays offline.

The CLI's rich ``Console`` writes to stderr, so the helper below collects
whatever output stream the installed click exposes.
"""

from __future__ import annotations

from typer.testing import CliRunner

from rtl.cli import app

runner = CliRunner()


def _text(result) -> str:
    """Best-effort combined console text across click/typer versions."""
    out = result.output or ""
    try:
        out += result.stderr or ""
    except (AttributeError, ValueError):
        pass
    return out


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "rtl v" in _text(result)


def test_list_suites_command():
    result = runner.invoke(app, ["list-suites"])
    assert result.exit_code == 0
    assert "quick" in _text(result)


def test_list_attacks_command():
    result = runner.invoke(app, ["list-attacks"])
    assert result.exit_code == 0
    assert "direct_injection" in _text(result)


def test_target_list_command():
    result = runner.invoke(app, ["target", "--list"])
    assert result.exit_code == 0
    assert "ollama" in _text(result)


def test_target_spec_command():
    result = runner.invoke(app, ["target", "ollama:llama3.1"])
    assert result.exit_code == 0
    assert "llama3.1" in _text(result)


def test_scan_mock_writes_reports(tmp_path):
    out = tmp_path / "reports"
    result = runner.invoke(
        app,
        ["scan", "--target", "mock", "--suite", "suites/quick.yaml", "--output", str(out)],
    )
    assert result.exit_code == 0, _text(result)
    assert (out / "report.json").exists()
    assert (out / "report.html").exists()


def test_scan_offline_and_json_logs(tmp_path):
    import json

    out = tmp_path / "reports"
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "mock",
            "--suite",
            "suites/quick.yaml",
            "--output",
            str(out),
            "--offline",
            "--json-logs",
        ],
    )
    assert result.exit_code == 0, _text(result)
    # offline scan is forced onto the heuristic judge
    payload = json.loads((out / "report.json").read_text())
    assert payload["meta"]["judge_mode"] == "heuristic"


def test_report_regeneration_html(tmp_path):
    out = tmp_path / "reports"
    scan = runner.invoke(app, ["scan", "--target", "mock", "--suite", "suites/quick.yaml", "--output", str(out)])
    assert scan.exit_code == 0, _text(scan)
    regen = tmp_path / "regen.html"
    result = runner.invoke(
        app,
        ["report", "--input-file", str(out / "report.json"), "--output", str(regen)],
    )
    assert result.exit_code == 0, _text(result)
    assert regen.exists()

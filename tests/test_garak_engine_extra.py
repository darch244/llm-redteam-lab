"""Isolated tests for the optional garak engine wrapper.

The real ``garak`` CLI is never invoked: ``shutil.which`` and
``subprocess.run`` are faked, and report fixtures are written to ``tmp_path``.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from rtl.engines import garak_engine
from rtl.engines.base import EngineError, EngineUnavailableError
from rtl.engines.garak_engine import DEFAULT_PROBES, GarakEngine


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["garak"], returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.fixture
def installed(monkeypatch):
    """Pretend the garak executable is installed."""
    monkeypatch.setattr(garak_engine.shutil, "which", lambda _binary: "/usr/local/bin/garak")


def _write_report(prefix, payload) -> None:
    prefix.with_suffix(".report.json").write_text(json.dumps(payload), encoding="utf-8")


def test_garak_successful_run_parses_report_and_maps_atlas(installed, monkeypatch, tmp_path):
    prefix = tmp_path / "run"
    _write_report(
        prefix,
        {
            "plugins": {
                "promptinject": {"attempts": [{"status": "fail"}, {"status": "pass"}]},
                "jailbreak": {"attempts": [{"passed": True}]},
                "leakrepetition": {"attempts": [{"status": "pass"}]},
                "encoding.DanGeneration": {"attempts": []},
            }
        },
    )
    captured: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured.update(kwargs)
        return _completed(returncode=0)

    monkeypatch.setattr(garak_engine.subprocess, "run", fake_run)

    results = GarakEngine().run(
        ["ignored"],
        model_type="openai",
        model_name="gpt-test",
        probes=["promptinject"],
        report_prefix=str(prefix),
    )

    assert [r.probe_id for r in results] == [
        "promptinject",
        "jailbreak",
        "leakrepetition",
        "encoding.DanGeneration",
    ]
    assert results[0].success is True  # status == "fail" counts as a finding
    assert results[1].success is True  # legacy "passed": true still honoured
    assert results[2].success is False
    assert results[3].success is False
    assert results[0].atlas_ids == ["AML.T0051.000"]
    assert results[1].atlas_ids == ["AML.T0054"]
    assert results[3].atlas_ids == ["AML.T0051", "AML.T0054"]
    assert results[0].prompt == "promptinject"
    assert results[0].raw == {"garak_prefix": "promptinject", "attempts": 2}
    assert "promptinject over 2 attempts" in results[0].summary

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[:5] == ["/usr/local/bin/garak", "--model_type", "openai", "--probes", "promptinject"]
    assert "--model_name" in cmd and "gpt-test" in cmd
    assert "--report_prefix" in cmd and str(prefix) in cmd
    assert captured["capture_output"] is True
    assert captured["text"] is True
    assert captured["timeout"] == 3600


def test_garak_uses_default_probes_when_none_requested(installed, monkeypatch, tmp_path):
    captured: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _completed()

    monkeypatch.setattr(garak_engine.subprocess, "run", fake_run)
    results = GarakEngine().run([])

    assert results == []
    assert captured["cmd"][4] == ",".join(DEFAULT_PROBES)


def test_garak_missing_dependency_raises_unavailable(monkeypatch):
    monkeypatch.setattr(garak_engine.shutil, "which", lambda _binary: None)
    monkeypatch.setattr(
        garak_engine.subprocess,
        "run",
        lambda *a, **k: pytest.fail("subprocess must not run when garak is absent"),
    )

    with pytest.raises(EngineUnavailableError) as excinfo:
        GarakEngine().run([])
    assert excinfo.value.engine == "garak"
    assert "pip install garak" in excinfo.value.hint


def test_garak_timeout_is_reported_as_engine_error(installed, monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=3600)

    monkeypatch.setattr(garak_engine.subprocess, "run", fake_run)

    with pytest.raises(EngineError, match="timed out after 3600s"):
        GarakEngine().run([])


def test_garak_os_error_is_reported_as_engine_error(installed, monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("garak vanished")

    monkeypatch.setattr(garak_engine.subprocess, "run", fake_run)

    with pytest.raises(EngineError, match="could not start garak"):
        GarakEngine().run([])


def test_garak_nonzero_exit_still_parses_available_report(installed, monkeypatch, tmp_path, caplog):
    prefix = tmp_path / "partial"
    _write_report(prefix, {"plugins": {"jailbreak": {"attempts": [{"status": "fail"}]}}})
    monkeypatch.setattr(garak_engine.subprocess, "run", lambda *a, **k: _completed(returncode=2, stderr="boom"))

    results = GarakEngine().run([], report_prefix=str(prefix))

    assert len(results) == 1
    assert results[0].probe_id == "jailbreak"
    assert "garak exited 2" in caplog.text


def test_garak_invalid_json_report_is_ignored(installed, monkeypatch, tmp_path, caplog):
    prefix = tmp_path / "broken"
    prefix.with_suffix(".report.json").write_text("{not-json", encoding="utf-8")
    monkeypatch.setattr(garak_engine.subprocess, "run", lambda *a, **k: _completed())

    assert GarakEngine().run([], report_prefix=str(prefix)) == []
    assert "could not parse garak report" in caplog.text


def test_garak_unexpected_report_shape_is_ignored_safely(installed, monkeypatch, tmp_path, caplog):
    prefix = tmp_path / "odd"
    _write_report(prefix, ["not", "an", "object"])
    monkeypatch.setattr(garak_engine.subprocess, "run", lambda *a, **k: _completed())

    assert GarakEngine().run([], report_prefix=str(prefix)) == []
    assert "unexpected top-level type list" in caplog.text

    _write_report(prefix, {"plugins": []})
    assert GarakEngine().run([], report_prefix=str(prefix)) == []
    assert "malformed 'plugins' section" in caplog.text


def test_garak_malformed_plugin_entries_are_skipped_but_valid_ones_kept(installed, monkeypatch, tmp_path, caplog):
    prefix = tmp_path / "mixed"
    _write_report(
        prefix,
        {
            "plugins": {
                "good": {"attempts": [{"status": "fail"}, "not-a-dict"]},
                "bad-shape": [],
                "bad-attempts": {"attempts": "nope"},
            }
        },
    )
    monkeypatch.setattr(garak_engine.subprocess, "run", lambda *a, **k: _completed())

    results = GarakEngine().run([], report_prefix=str(prefix))

    assert [r.probe_id for r in results] == ["good"]
    # a non-dict attempt is skipped rather than crashing the whole report
    assert results[0].success is True
    assert results[0].raw["attempts"] == 2
    assert "ignoring malformed garak plugin entry" in caplog.text
    assert "ignoring malformed garak attempts" in caplog.text


def test_garak_missing_report_is_logged_and_returns_empty(installed, monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(garak_engine.subprocess, "run", lambda *a, **k: _completed())

    assert GarakEngine().run([], report_prefix=str(tmp_path / "does-not-exist")) == []
    assert "could not parse garak report" in caplog.text


def test_garak_without_report_prefix_does_not_read_any_file(installed, monkeypatch):
    monkeypatch.setattr(garak_engine.subprocess, "run", lambda *a, **k: _completed())
    monkeypatch.setattr(
        garak_engine.json,
        "load",
        lambda _handle: pytest.fail("must not parse a report without a prefix"),
    )

    assert GarakEngine().run([]) == []

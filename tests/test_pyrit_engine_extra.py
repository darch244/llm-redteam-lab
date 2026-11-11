"""Isolated tests for the optional PyRIT engine wrapper.

PyRIT is not installed in CI. These tests inject fake ``pyrit`` modules into
``sys.modules`` and exercise the wrapper without network access or a real
orchestrator.
"""

from __future__ import annotations

import asyncio
import sys
import types

import pytest

from rtl.engines.base import EngineUnavailableError
from rtl.engines.pyrit_engine import PyritEngine


class _Piece:
    def __init__(self, text: str) -> None:
        self.text = text


def _install_fake_pyrit(
    monkeypatch,
    *,
    async_send: bool = False,
    signature: str = "prompts",
    send_result=None,
    send_error: BaseException | None = None,
    dispose: bool = True,
    constructor_error: BaseException | None = None,
    send_override=None,
) -> dict:
    calls: dict = {
        "memory_args": None,
        "target": None,
        "memory": None,
        "send_kwargs": None,
        "disposed": 0,
        "default_target_instances": 0,
    }

    class FakeOpenAIChatTarget:
        def __init__(self) -> None:
            calls["default_target_instances"] += 1
            self.kind = "openai"

    class FakeMemory:
        def __init__(self, **kwargs) -> None:
            calls["memory_args"] = kwargs

    class FakeOrchestrator:
        def __init__(self, prompt_target, memory) -> None:
            if constructor_error is not None:
                raise constructor_error
            calls["target"] = prompt_target
            calls["memory"] = memory

        def dispose_db_engine(self) -> None:
            calls["disposed"] += 1

    def _sync_prompts(self, *, prompts):
        calls["send_kwargs"] = {"prompts": prompts}
        if send_error is not None:
            raise send_error
        return send_result

    async def _async_prompts(self, *, prompts):
        calls["send_kwargs"] = {"prompts": prompts}
        await asyncio.sleep(0)
        if send_error is not None:
            raise send_error
        return send_result

    def _sync_prompt_list(self, *, prompt_list):
        calls["send_kwargs"] = {"prompt_list": prompt_list}
        if send_error is not None:
            raise send_error
        return send_result

    async def _async_prompt_list(self, *, prompt_list):
        calls["send_kwargs"] = {"prompt_list": prompt_list}
        await asyncio.sleep(0)
        if send_error is not None:
            raise send_error
        return send_result

    implementations = {
        (False, "prompts"): _sync_prompts,
        (True, "prompts"): _async_prompts,
        (False, "prompt_list"): _sync_prompt_list,
        (True, "prompt_list"): _async_prompt_list,
    }
    FakeOrchestrator.send_prompts_async = implementations[(async_send, signature)]
    if send_override is not None:
        FakeOrchestrator.send_prompts_async = send_override
    if not dispose:
        FakeOrchestrator.dispose_db_engine = None  # type: ignore[assignment]

    pyrit_mod = types.ModuleType("pyrit")
    pyrit_mod.__path__ = []  # type: ignore[attr-defined]
    memory_mod = types.ModuleType("pyrit.memory")
    orchestrator_mod = types.ModuleType("pyrit.orchestrator")
    target_mod = types.ModuleType("pyrit.prompt_target")
    memory_mod.DuckDBMemory = FakeMemory  # type: ignore[attr-defined]
    orchestrator_mod.PromptSendingOrchestrator = FakeOrchestrator  # type: ignore[attr-defined]
    target_mod.OpenAIChatTarget = FakeOpenAIChatTarget  # type: ignore[attr-defined]
    pyrit_mod.memory = memory_mod  # type: ignore[attr-defined]
    pyrit_mod.orchestrator = orchestrator_mod  # type: ignore[attr-defined]
    pyrit_mod.prompt_target = target_mod  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "pyrit", pyrit_mod)
    monkeypatch.setitem(sys.modules, "pyrit.memory", memory_mod)
    monkeypatch.setitem(sys.modules, "pyrit.orchestrator", orchestrator_mod)
    monkeypatch.setitem(sys.modules, "pyrit.prompt_target", target_mod)
    return calls


def test_pyrit_missing_dependency_raises_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "pyrit", None)

    with pytest.raises(EngineUnavailableError) as excinfo:
        PyritEngine().run(["hello"])
    assert excinfo.value.engine == "pyrit"
    assert "pip install pyrit" in excinfo.value.hint


def test_pyrit_successful_sync_run(monkeypatch):
    calls = _install_fake_pyrit(
        monkeypatch,
        send_result=[[_Piece("first"), _Piece("second")], [_Piece("third")]],
    )
    engine = PyritEngine(prompt_target_factory=lambda: "configured-target")

    results = engine.run(["p1", "p2"], memory_args={"db_path": ":memory:"})

    assert [r.probe_id for r in results] == ["pyrit#batch-entry-0", "pyrit#batch-entry-1"]
    assert [r.prompt for r in results] == ["p1", "p2"]
    assert [r.response for r in results] == ["first\nsecond", "third"]
    assert all(r.success for r in results)
    assert all(r.atlas_ids == ["AML.T0051", "AML.T0054"] for r in results)
    assert calls["send_kwargs"] == {"prompts": ["p1", "p2"]}
    assert calls["memory_args"] == {"db_path": ":memory:"}
    assert calls["target"] == "configured-target"
    assert calls["disposed"] == 1


def test_pyrit_supports_async_send_with_new_prompt_list_keyword(monkeypatch):
    calls = _install_fake_pyrit(
        monkeypatch,
        async_send=True,
        signature="prompt_list",
        send_result=[[_Piece("async response")]],
    )

    results = PyritEngine().run(["p1"])

    assert len(results) == 1
    assert results[0].response == "async response"
    assert calls["send_kwargs"] == {"prompt_list": ["p1"]}
    assert calls["default_target_instances"] == 1
    assert calls["disposed"] == 1


@pytest.mark.asyncio
async def test_pyrit_async_send_works_inside_a_running_event_loop(monkeypatch):
    calls = _install_fake_pyrit(
        monkeypatch,
        async_send=True,
        signature="prompt_list",
        send_result=[[_Piece("from loop")]],
    )

    # Engine.run is synchronous but run_scan calls it from async code.
    results = PyritEngine().run(["p1"])

    assert results[0].response == "from loop"
    assert calls["disposed"] == 1


@pytest.mark.asyncio
async def test_pyrit_async_error_inside_running_loop_propagates_and_cleans_up(monkeypatch):
    calls = _install_fake_pyrit(
        monkeypatch,
        async_send=True,
        signature="prompt_list",
        send_error=RuntimeError("async orchestration failed"),
    )

    with pytest.raises(RuntimeError, match="async orchestration failed"):
        PyritEngine().run(["p1"])

    assert calls["disposed"] == 1


def test_pyrit_callable_without_inspectable_signature_uses_prompts_keyword(monkeypatch):
    calls = _install_fake_pyrit(monkeypatch, send_result=[[_Piece("ok")]])

    class NoSignatureSend:
        @property
        def __signature__(self):
            raise ValueError("signature unavailable")

        def __call__(self, *, prompts):
            calls["send_kwargs"] = {"prompts": prompts}
            return [[_Piece("ok")]]

    # Replace the bound method after installation with a callable object.
    for module_name in ("pyrit.orchestrator",):
        orchestrator_cls = sys.modules[module_name].PromptSendingOrchestrator
        orchestrator_cls.send_prompts_async = NoSignatureSend()

    results = PyritEngine().run(["p1"])

    assert results[0].response == "ok"
    assert calls["send_kwargs"] == {"prompts": ["p1"]}


def test_pyrit_run_level_factory_overrides_constructor_factory(monkeypatch):
    calls = _install_fake_pyrit(monkeypatch, send_result=[])
    engine = PyritEngine(prompt_target_factory=lambda: "constructor-factory")

    engine.run(["p1"], prompt_target_factory=lambda: "call-factory")

    assert calls["target"] == "call-factory"


def test_pyrit_send_exception_propagates_and_cleans_up(monkeypatch):
    calls = _install_fake_pyrit(monkeypatch, send_error=RuntimeError("orchestration failed"))

    with pytest.raises(RuntimeError, match="orchestration failed"):
        PyritEngine().run(["p1"])

    assert calls["disposed"] == 1


def test_pyrit_constructor_failure_propagates(monkeypatch):
    _install_fake_pyrit(monkeypatch, constructor_error=RuntimeError("cannot build orchestrator"))

    with pytest.raises(RuntimeError, match="cannot build orchestrator"):
        PyritEngine().run(["p1"])


def test_pyrit_missing_dispose_method_is_tolerated(monkeypatch, caplog):
    calls = _install_fake_pyrit(monkeypatch, send_result=[[_Piece("ok")]], dispose=False)

    results = PyritEngine().run(["p1"])

    assert results[0].response == "ok"
    assert calls["disposed"] == 0
    assert "no dispose_db_engine" in caplog.text


@pytest.mark.parametrize("malformed", [None, "not-a-batch", 42])
def test_pyrit_malformed_batch_output_returns_no_results(monkeypatch, caplog, malformed):
    calls = _install_fake_pyrit(monkeypatch, send_result=malformed)

    assert PyritEngine().run(["p1"]) == []
    assert calls["disposed"] == 1
    assert "malformed batch output" in caplog.text or "no batch output" in caplog.text


def test_pyrit_malformed_prompt_entries_are_coerced_safely(monkeypatch):
    calls = _install_fake_pyrit(
        monkeypatch,
        send_result=[
            "bare string entry",
            [_Piece("ok"), "plain string", object()],
            None,
            42,
        ],
    )

    results = PyritEngine().run(["p1", "p2", "p3", "p4"])

    assert len(results) == 4
    assert results[0].response == "bare string entry"
    assert results[0].success is True
    assert results[1].response == "ok\nplain string\n"
    assert results[1].success is True
    assert results[2].response == ""
    assert results[2].success is False
    assert results[3].response == ""
    assert results[3].success is False
    assert [r.prompt for r in results] == ["p1", "p2", "p3", "p4"]
    assert calls["disposed"] == 1

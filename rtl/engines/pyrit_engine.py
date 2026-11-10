"""pyrit engine — an optional wrapper around Microsoft's PyRIT framework.

PyRIT provides orchestrators (``PromptSendingOrchestrator``), prompt
converters and scoring pipelines. This engine drives PyRIT's
``PromptSendingOrchestrator`` against an OpenAI-compatible chat target so
the same attack set can be replayed through PyRIT's own tooling.

Install with: ``pip install pyrit``.
"""

from __future__ import annotations

import asyncio
import inspect
import threading
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from rtl.engines.base import Engine, EngineResult, EngineUnavailableError
from rtl.logging import get_logger

log = get_logger("pyrit")


def _run_coroutine(coro: Any) -> Any:
    """Run ``coro`` to completion from synchronous engine code.

    ``run_scan`` is async, so ``Engine.run`` may be called while an event loop
    is already running in this thread. ``asyncio.run`` cannot be nested, so in
    that case the coroutine is executed on a dedicated worker thread with its
    own loop; callers still block until it finishes.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    box: dict[str, Any] = {}

    def _target() -> None:
        try:
            box["value"] = asyncio.run(coro)
        except BaseException as exc:  # propagate to the waiting caller
            box["error"] = exc

    worker = threading.Thread(target=_target, name="pyrit-engine", daemon=True)
    worker.start()
    worker.join()
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _invoke_send(send: Callable[..., Any], prompts: list[str]) -> Any:
    """Call PyRIT's send method, supporting both historical keyword names.

    PyRIT renamed the argument from ``prompts`` to ``prompt_list``; inspect the
    callable so the wrapper works with either while still failing loudly if the
    method is missing entirely.
    """
    try:
        parameters: Mapping[str, inspect.Parameter] = inspect.signature(send).parameters
    except (TypeError, ValueError):
        parameters = {}
    if "prompt_list" in parameters and "prompts" not in parameters:
        return send(prompt_list=prompts)
    return send(prompts=prompts)


def _iter_entries(sent: Any) -> Iterable[Any]:
    """Iterate a batch response defensively (malformed output must not crash)."""
    if sent is None:
        log.warning("pyrit returned no batch output; recording no engine results")
        return ()
    if isinstance(sent, (str, bytes)) or not isinstance(sent, Iterable):
        log.warning(
            "pyrit returned malformed batch output (%s); recording no engine results",
            type(sent).__name__,
        )
        return ()
    return sent


def _iter_pieces(pieces: Any) -> Iterable[Any]:
    """Iterate the per-prompt pieces defensively."""
    if pieces is None:
        return ()
    if isinstance(pieces, str):
        return (pieces,)
    if not isinstance(pieces, Iterable):
        log.warning("pyrit returned a non-iterable prompt entry (%s); coercing to text", type(pieces).__name__)
        return (pieces,)
    return pieces


def _text_of(piece: Any) -> str:
    """Extract response text from a PyRIT message piece."""
    if isinstance(piece, str):
        return piece
    text = getattr(piece, "text", None)
    return text if isinstance(text, str) else ""


class PyritEngine(Engine):
    """Replays prompts through PyRIT's sending orchestrator."""

    name = "pyrit"
    description = "Microsoft PyRIT orchestration framework (external)"
    homepage = "https://github.com/Azure/PyRIT"

    def __init__(self, prompt_target_factory: Callable[[], Any] | None = None) -> None:
        self.prompt_target_factory = prompt_target_factory

    def run(
        self,
        prompts: list[str],
        *,
        prompt_target_factory: Callable[[], Any] | None = None,
        memory_args: dict[str, Any] | None = None,
        **_: Any,
    ) -> list[EngineResult]:
        """Send ``prompts`` through a ``PromptSendingOrchestrator``.

        ``prompt_target_factory`` must return a PyRIT prompt target (e.g.
        ``AzureOpenAIChatTarget(...)``); otherwise an environment-fitted
        ``OpenAIChatTarget`` is attempted.
        """
        try:
            from pyrit.memory import DuckDBMemory
            from pyrit.orchestrator import PromptSendingOrchestrator
            from pyrit.prompt_target import OpenAIChatTarget
        except ImportError as exc:
            raise EngineUnavailableError(
                self.name,
                "pyrit is not installed; run `pip install pyrit`",
            ) from exc

        factory = prompt_target_factory or self.prompt_target_factory
        if factory is None:

            def factory() -> Any:
                return OpenAIChatTarget()

        async def _execute() -> list[EngineResult]:
            memory = DuckDBMemory(**memory_args if memory_args else {})
            orchestrator = PromptSendingOrchestrator(prompt_target=factory(), memory=memory)
            try:
                sent = _invoke_send(orchestrator.send_prompts_async, prompts)
                if inspect.isawaitable(sent):
                    sent = await sent

                results: list[EngineResult] = []
                for attack_idx, pieces in enumerate(_iter_entries(sent)):
                    joined = "\n".join(_text_of(piece) for piece in _iter_pieces(pieces))
                    results.append(
                        EngineResult(
                            engine=self.name,
                            probe_id=f"pyrit#batch-entry-{attack_idx}",
                            prompt=prompts[attack_idx] if attack_idx < len(prompts) else "",
                            response=joined,
                            success=bool(joined),
                            atlas_ids=["AML.T0051", "AML.T0054"],
                            summary="replayed through PromptSendingOrchestrator",
                        )
                    )
                return results
            finally:
                dispose = getattr(orchestrator, "dispose_db_engine", None)
                if callable(dispose):
                    dispose()
                else:
                    log.warning("pyrit orchestrator has no dispose_db_engine(); skipping cleanup")

        return _run_coroutine(_execute())


__all__ = ["PyritEngine"]

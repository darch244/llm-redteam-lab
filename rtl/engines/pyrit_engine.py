"""pyrit engine — an optional wrapper around Microsoft's PyRIT framework.

PyRIT provides orchestrators (``PromptSendingOrchestrator``), prompt
converters and scoring pipelines. This engine drives PyRIT's
``PromptSendingOrchestrator`` against an OpenAI-compatible chat target so
the same attack set can be replayed through PyRIT's own tooling.

Install with: ``pip install pyrit`` (or ``pip install llm-redteam-lab[pyrit]``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from rtl.engines.base import Engine, EngineResult, EngineUnavailableError
from rtl.logging import get_logger

log = get_logger("pyrit")


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
        except ImportError as exc:  # pragma: no cover - optional dep path
            raise EngineUnavailableError(
                self.name,
                "pyrit is not installed; run `pip install pyrit` (extra: `[pyrit]`)",
            ) from exc

        factory = prompt_target_factory or self.prompt_target_factory
        if factory is None:

            def factory() -> Any:
                return OpenAIChatTarget()

        memory = DuckDBMemory(**memory_args if memory_args else {})
        orchestrator = PromptSendingOrchestrator(prompt_target=factory(), memory=memory)

        results: list[EngineResult] = []
        try:
            sent = orchestrator.send_prompts_async(prompts=prompts)
            for attack_idx, pieces in enumerate(sent):
                joined = "\n".join(str(getattr(p, "text", "")) for p in pieces)
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
        finally:
            orchestrator.dispose_db_engine()

        return results


__all__ = ["PyritEngine"]

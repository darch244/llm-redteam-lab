"""Centralised verdict evaluation for probe executions.

Stage 0 of the adaptive-engine roadmap. The runner used to call
``Judge.evaluate`` twice for the same response: an initial call and a second
"evidence-aware" call with the first verdict/severity embedded in ``raw``.
The first call could not change the second verdict (it only contributed
``raw["verdict"]``/``raw["severity"]``, which the evidence gate ignores), so it
was pure duplication — and an extra LLM-judge request in ``mode="llm"``.

:class:`VerdictPolicy` performs **one** evaluation per response and always
forwards the evidence context (``raw`` and the :class:`ProbeResult`) that the
runner's final call used. It does not reinterpret or loosen any judge rule: the
existing :class:`~rtl.evaluation.judge.Judge` remains the sole confirmation
authority.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any

from rtl.evaluation.judge import JudgeVerdict

if TYPE_CHECKING:
    from rtl.evaluation.judge import Judge
    from rtl.reporting.models import ProbeResult


def _accepts_evidence_kwargs(evaluate: Any) -> bool:
    """Return True when ``evaluate`` can receive ``raw`` and ``probe_result``.

    The real :meth:`Judge.evaluate` accepts both (and ``**kwargs``). Some
    custom/legacy judge implementations in tests and integrations only accept
    the original ``canary`` keyword; the policy keeps supporting them without
    ever making a second production call.
    """
    try:
        parameters = inspect.signature(evaluate).parameters
    except (TypeError, ValueError):  # pragma: no cover - exotic callables
        return True
    if any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()):
        return True
    return {"raw", "probe_result"} <= set(parameters)


class VerdictPolicy:
    """Evaluate one probe response exactly once through the configured judge."""

    def __init__(self, judge: Judge) -> None:
        self._judge = judge
        self._evidence_kwargs = _accepts_evidence_kwargs(judge.evaluate)

    @property
    def judge(self) -> Judge:
        """The wrapped judge (read-only; the policy never mutates its mode)."""
        return self._judge

    def evaluate(self, probe_result: ProbeResult, *, prompt: str | None = None) -> JudgeVerdict:
        """Judge ``probe_result`` once and return the verdict.

        Args:
            probe_result: The executed probe. Its ``response``, ``probe`` and
                ``raw`` evidence are passed to the judge unchanged.
            prompt: The text the target actually received. Defaults to the
                probe's library prompt; the runner passes the truncated prompt
                when ``max_prompt_len`` changed it.

        Returns:
            The judge's verdict, including any evidence-aware downgrade.
        """
        sent_prompt = probe_result.probe.prompt if prompt is None else prompt
        if self._evidence_kwargs:
            return self._judge.evaluate(
                sent_prompt,
                probe_result.response,
                probe_result.probe.category,
                canary=probe_result.probe.canary,
                raw=probe_result.raw,
                probe_result=probe_result,
            )
        return self._judge.evaluate(
            sent_prompt,
            probe_result.response,
            probe_result.probe.category,
            canary=probe_result.probe.canary,
        )


__all__ = ["VerdictPolicy"]

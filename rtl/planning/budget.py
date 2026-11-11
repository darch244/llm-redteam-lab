"""Budget ledger and multi-dimensional resource bounding for adaptive scans."""

from __future__ import annotations

import time
from collections.abc import Callable

from rtl.config import BudgetLimits
from rtl.planning.models import BudgetUsage, PlanStep, StopDimension


class BudgetExceeded(Exception):
    """Raised when a proposed plan step or ongoing execution exceeds budget."""

    def __init__(
        self,
        dimension: StopDimension,
        limit: float | int,
        current: float | int,
        requested: float | int = 0,
    ) -> None:
        self.dimension = dimension
        self.limit = limit
        self.current = current
        self.requested = requested
        super().__init__(f"budget exceeded on {dimension}: current={current}, limit={limit}, requested={requested}")


def estimate_tokens(text: str) -> int:
    """Deterministic token count heuristic (~4 characters per token)."""
    stripped = text.strip()
    if not stripped:
        return 1
    return max(1, (len(stripped) + 3) // 4)


class BudgetLedger:
    """Enforces multi-dimensional resource bounds before and during execution.

    Invariants:
    1. Steps are verified against remaining budget BEFORE dispatch.
    2. Dimension checking order is deterministic:
       time -> probes -> turns -> prompt_tokens -> output_tokens -> cost -> tool_calls.
    3. Rejected or skipped steps do not consume token or probe allowances.
    """

    def __init__(
        self,
        limits: BudgetLimits,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.limits = limits
        self._clock = clock or time.monotonic
        self._start_time = self._clock()
        self.usage = BudgetUsage()
        self.reserved = BudgetUsage()

    @property
    def elapsed_seconds(self) -> float:
        """Current elapsed wall-clock time from the ledger's clock."""
        return max(0.0, self._clock() - self._start_time)

    def check_time(self) -> None:
        """Verify the execution has not exceeded the time budget."""
        elapsed = self.elapsed_seconds
        if elapsed >= self.limits.max_seconds:
            raise BudgetExceeded("max_seconds", self.limits.max_seconds, elapsed)

    def reserve(self, step: PlanStep) -> BudgetUsage:
        """Check limits and hold a reservation for a proposed step before dispatch.

        Raises:
            BudgetExceeded: If any limit dimension would be violated.
        """
        # 1. Monotonic wall-clock time
        self.check_time()

        # 2. Probe count
        cur_probes = self.usage.probes + self.reserved.probes
        if cur_probes + 1 > self.limits.max_probes:
            raise BudgetExceeded("max_probes", self.limits.max_probes, cur_probes, 1)

        # 3. Turn count
        cur_turns = self.usage.turns + self.reserved.turns
        if cur_turns + 1 > self.limits.max_turns:
            raise BudgetExceeded("max_turns", self.limits.max_turns, cur_turns, 1)

        # 4. Prompt tokens
        cur_prompt = self.usage.prompt_tokens + self.reserved.prompt_tokens
        if cur_prompt + step.est_prompt_tokens > self.limits.max_prompt_tokens:
            raise BudgetExceeded(
                "max_prompt_tokens",
                self.limits.max_prompt_tokens,
                cur_prompt,
                step.est_prompt_tokens,
            )

        # 5. Output tokens
        cur_output = self.usage.output_tokens + self.reserved.output_tokens
        if cur_output + step.est_max_output_tokens > self.limits.max_output_tokens:
            raise BudgetExceeded(
                "max_output_tokens",
                self.limits.max_output_tokens,
                cur_output,
                step.est_max_output_tokens,
            )

        # 6. Cost in USD (if configured)
        if self.limits.max_cost_usd is not None:
            cur_cost = self.usage.cost_usd + self.reserved.cost_usd
            if cur_cost + step.est_cost_usd > self.limits.max_cost_usd:
                raise BudgetExceeded(
                    "max_cost_usd",
                    self.limits.max_cost_usd,
                    cur_cost,
                    step.est_cost_usd,
                )

        # 7. Tool calls (baseline check)
        cur_tools = self.usage.tool_calls + self.reserved.tool_calls
        if cur_tools >= self.limits.max_tool_calls and self.limits.max_tool_calls > 0:
            raise BudgetExceeded("max_tool_calls", self.limits.max_tool_calls, cur_tools, 1)

        reservation = BudgetUsage(
            probes=1,
            turns=1,
            prompt_tokens=step.est_prompt_tokens,
            output_tokens=step.est_max_output_tokens,
            cost_usd=step.est_cost_usd,
            tool_calls=0,
            elapsed_seconds=0.0,
        )
        self.reserved = self.reserved.add(reservation)
        return reservation

    def commit(self, reservation: BudgetUsage, actual: BudgetUsage) -> None:
        """Deduct the reservation and commit actual reconciled consumption."""
        self.reserved = BudgetUsage(
            probes=max(0, self.reserved.probes - reservation.probes),
            turns=max(0, self.reserved.turns - reservation.turns),
            prompt_tokens=max(0, self.reserved.prompt_tokens - reservation.prompt_tokens),
            output_tokens=max(0, self.reserved.output_tokens - reservation.output_tokens),
            cost_usd=max(0.0, round(self.reserved.cost_usd - reservation.cost_usd, 6)),
            tool_calls=max(0, self.reserved.tool_calls - reservation.tool_calls),
            elapsed_seconds=0.0,
        )
        actual_with_time = actual.model_copy(update={"elapsed_seconds": self.elapsed_seconds})
        self.usage = self.usage.add(actual_with_time)

    def refund(self, reservation: BudgetUsage) -> None:
        """Refund a reservation if a step was canceled before dispatch."""
        self.reserved = BudgetUsage(
            probes=max(0, self.reserved.probes - reservation.probes),
            turns=max(0, self.reserved.turns - reservation.turns),
            prompt_tokens=max(0, self.reserved.prompt_tokens - reservation.prompt_tokens),
            output_tokens=max(0, self.reserved.output_tokens - reservation.output_tokens),
            cost_usd=max(0.0, round(self.reserved.cost_usd - reservation.cost_usd, 6)),
            tool_calls=max(0, self.reserved.tool_calls - reservation.tool_calls),
            elapsed_seconds=0.0,
        )

    @property
    def remaining(self) -> BudgetUsage:
        """Remaining capacity across all dimensions."""
        total_used = self.usage.add(self.reserved)
        rem_cost = (
            max(0.0, round(self.limits.max_cost_usd - total_used.cost_usd, 6))
            if self.limits.max_cost_usd is not None
            else 0.0
        )
        return BudgetUsage(
            probes=max(0, self.limits.max_probes - total_used.probes),
            turns=max(0, self.limits.max_turns - total_used.turns),
            prompt_tokens=max(0, self.limits.max_prompt_tokens - total_used.prompt_tokens),
            output_tokens=max(0, self.limits.max_output_tokens - total_used.output_tokens),
            cost_usd=rem_cost,
            tool_calls=max(0, self.limits.max_tool_calls - total_used.tool_calls),
            elapsed_seconds=max(0.0, round(self.limits.max_seconds - self.elapsed_seconds, 3)),
        )


__all__ = ["BudgetExceeded", "BudgetLedger", "estimate_tokens"]

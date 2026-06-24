"""
Per-run cost/token accounting for benchmarks.

Reuses the existing CostTracker (cyberai/core/cost_tracker.py) — the same one
the scan pipeline feeds — so a benchmark run is costed with identical logic.
This module only summarizes a run's tracker into compact, scorecard-ready
numbers (cost-per-task, tokens, call count). No new accounting is invented.
"""

from __future__ import annotations

from dataclasses import dataclass

from cyberai.core.cost_tracker import CostTracker
from cyberai.core.pricing import total_cost


@dataclass(frozen=True)
class RunBudget:
    """Compact cost/token rollup for one suite run."""

    total_cost_usd: float
    total_tokens: int
    input_tokens: int
    output_tokens: int
    call_count: int
    tasks: int

    @property
    def cost_per_task(self) -> float:
        return self.total_cost_usd / self.tasks if self.tasks else 0.0

    @property
    def tokens_per_task(self) -> float:
        return self.total_tokens / self.tasks if self.tasks else 0.0


def summarize_budget(tracker: CostTracker, tasks: int) -> RunBudget:
    """Roll a populated CostTracker up into a RunBudget for `tasks` tasks.

    `total_cost` (pricing.py) maps usage to USD via the per-model price table;
    unknown/local models price at 0 (graceful, e.g. Ollama)."""
    return RunBudget(
        total_cost_usd=round(total_cost(tracker), 6),
        total_tokens=tracker.total_tokens,
        input_tokens=tracker.total_input_tokens,
        output_tokens=tracker.total_output_tokens,
        call_count=tracker.call_count,
        tasks=tasks,
    )

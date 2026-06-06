"""
Per-call token usage tracking. Costing is applied separately (see pricing.py).

Design: tracker is created per scan (typically once at orchestrator start),
LLMClient appends a TokenUsage entry after every provider call. The CLI
reads the tracker at the end of the scan for a summary line.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class TokenUsage:
    """Single LLM call: tokens consumed + the agent that asked for it."""

    agent: str
    model: str
    input_tokens: int
    output_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class CostTracker:
    """Accumulates token usage across all LLM calls in one scan."""

    calls: List[TokenUsage] = field(default_factory=list)

    def add(
        self,
        agent: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> TokenUsage:
        """Record a single call and return the entry."""
        entry = TokenUsage(
            agent=agent,
            model=model,
            input_tokens=int(input_tokens),
            output_tokens=int(output_tokens),
        )
        self.calls.append(entry)
        return entry

    @property
    def total_input_tokens(self) -> int:
        return sum(c.input_tokens for c in self.calls)

    @property
    def total_output_tokens(self) -> int:
        return sum(c.output_tokens for c in self.calls)

    @property
    def total_tokens(self) -> int:
        return self.total_input_tokens + self.total_output_tokens

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def by_agent(self) -> dict[str, "CostTracker"]:
        """Group calls by agent name. Returns sub-trackers."""
        grouped: dict[str, CostTracker] = {}
        for c in self.calls:
            grouped.setdefault(c.agent, CostTracker()).calls.append(c)
        return grouped

    def by_model(self) -> dict[str, "CostTracker"]:
        """Group calls by model name. Returns sub-trackers."""
        grouped: dict[str, CostTracker] = {}
        for c in self.calls:
            grouped.setdefault(c.model, CostTracker()).calls.append(c)
        return grouped

    def reset(self) -> None:
        self.calls.clear()


def format_summary(tracker: "CostTracker") -> str:
    """One-line CLI summary: total cost, tokens, call count."""
    from cyberai.core.pricing import total_cost  # local import: optional dep

    if tracker.call_count == 0:
        return "LLM calls: 0 (no cost)"

    total = total_cost(tracker)
    return (
        f"LLM cost: ${total:.4f} "
        f"({tracker.total_input_tokens:,} in / "
        f"{tracker.total_output_tokens:,} out tokens, "
        f"{tracker.call_count} call{'s' if tracker.call_count != 1 else ''})"
    )

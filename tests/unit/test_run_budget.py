"""Tests for per-run benchmark cost/token rollup."""

from __future__ import annotations

from cyberai.bench.run_budget import RunBudget, summarize_budget
from cyberai.core.cost_tracker import CostTracker


def _tracker() -> CostTracker:
    t = CostTracker()
    t.add("recon", "gpt-4o-mini", input_tokens=1000, output_tokens=200)
    t.add("exploit", "gpt-4o-mini", input_tokens=2000, output_tokens=300)
    return t


def test_summarize_rolls_up_tokens_and_calls():
    b = summarize_budget(_tracker(), tasks=2)
    assert b.input_tokens == 3000
    assert b.output_tokens == 500
    assert b.total_tokens == 3500
    assert b.call_count == 2
    assert b.tasks == 2


def test_cost_is_nonnegative_and_per_task_divides():
    b = summarize_budget(_tracker(), tasks=2)
    assert b.total_cost_usd >= 0.0
    assert b.cost_per_task == b.total_cost_usd / 2
    assert b.tokens_per_task == 3500 / 2


def test_empty_tracker_zero_budget():
    b = summarize_budget(CostTracker(), tasks=0)
    assert b.total_tokens == 0
    assert b.call_count == 0
    assert b.cost_per_task == 0.0
    assert b.tokens_per_task == 0.0


def test_unknown_model_prices_at_zero_graceful():
    t = CostTracker()
    t.add("recon", "ollama/llama3", input_tokens=5000, output_tokens=1000)
    b = summarize_budget(t, tasks=1)
    assert b.total_cost_usd == 0.0
    assert b.total_tokens == 6000
    assert isinstance(b, RunBudget)

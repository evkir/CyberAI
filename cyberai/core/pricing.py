"""
Per-model pricing table — USD per 1M tokens.

Prices verified June 2026 against vendor pricing pages. Output tokens
are billed separately from input. Models not in the table are treated
as free (e.g. ollama / local models).

Sources:
- Anthropic: https://www.anthropic.com/pricing
- OpenAI:    https://openai.com/api/pricing
"""

from __future__ import annotations

from dataclasses import dataclass

from cyberai.core.cost_tracker import CostTracker, TokenUsage


@dataclass(frozen=True)
class ModelPricing:
    """USD per 1M tokens for one model."""

    input_per_mtok: float
    output_per_mtok: float


# All prices in USD / 1M tokens. Verified 2026-06.
PRICING: dict[str, ModelPricing] = {
    # ── OpenAI ────────────────────────────────────────────────────────
    "gpt-4o": ModelPricing(2.50, 10.00),
    "gpt-4o-mini": ModelPricing(0.15, 0.60),
    "gpt-4.1": ModelPricing(2.00, 8.00),
    "gpt-4.1-mini": ModelPricing(0.40, 1.60),
    "gpt-4.1-nano": ModelPricing(0.10, 0.40),
    # ── Anthropic ─────────────────────────────────────────────────────
    "claude-opus-4-8": ModelPricing(5.00, 25.00),
    "claude-opus-4-7": ModelPricing(5.00, 25.00),
    "claude-opus-4-6": ModelPricing(5.00, 25.00),
    "claude-sonnet-4-6": ModelPricing(3.00, 15.00),
    "claude-haiku-4-5": ModelPricing(1.00, 5.00),
    # ── Ollama / local models ─────────────────────────────────────────
    # Self-hosted; tokens are free at the API level. Add specific entries
    # here if your deployment charges back compute time.
}


# Anthropic prompt-caching multipliers (applied to the model's input price)
_CACHE_WRITE_5MIN_MULT = 1.25
_CACHE_READ_MULT = 0.10


def price_call(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_creation_tokens: int = 0,
    cache_read_tokens: int = 0,
) -> float:
    """
    Compute USD cost for one LLM call.

    Anthropic cached tokens are billed differently from regular input:
    - cache_creation_tokens (5-minute TTL writes) are billed at 1.25x input.
    - cache_read_tokens are billed at 0.10x input.
    - input_tokens here is the NON-cached portion only; the SDK already
      excludes cache hits/writes from response.usage.input_tokens.

    Unknown models return 0.0 — useful for local/ollama models and for
    graceful degradation when a new model name ships before this table
    updates.
    """
    p = PRICING.get(model)
    if p is None:
        return 0.0
    input_cost = (input_tokens / 1_000_000) * p.input_per_mtok
    output_cost = (output_tokens / 1_000_000) * p.output_per_mtok
    cache_write_cost = (
        (cache_creation_tokens / 1_000_000) * p.input_per_mtok * _CACHE_WRITE_5MIN_MULT
    )
    cache_read_cost = (cache_read_tokens / 1_000_000) * p.input_per_mtok * _CACHE_READ_MULT
    return input_cost + output_cost + cache_write_cost + cache_read_cost


def price_usage(usage: TokenUsage) -> float:
    """Convenience wrapper: price one TokenUsage entry."""
    return price_call(
        usage.model,
        usage.input_tokens,
        usage.output_tokens,
        cache_creation_tokens=usage.cache_creation_tokens,
        cache_read_tokens=usage.cache_read_tokens,
    )


def total_cost(tracker: CostTracker) -> float:
    """Sum cost across every call recorded in the tracker."""
    return sum(price_usage(c) for c in tracker.calls)

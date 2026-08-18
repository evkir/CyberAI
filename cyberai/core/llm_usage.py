"""One shape for the record of what the model did during a run.

The orchestrator wrote this key after the last phase, which is after the
report agent has already rendered and saved its documents: the reader of a
report saw an empty key while the session dump carried the numbers. Fixing
that means writing the record from two places, and two places writing the
same key by hand is how two truths start.

`client_built` is passed in rather than derived here. The orchestrator knows
whether the run ever built a client; a phase agent only knows about its own,
which under model routing is a different object sharing the same tracker.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from cyberai.core.config import LLMConfig
from cyberai.core.cost_tracker import CostTracker


def llm_zero_reason(
    llm_config: LLMConfig,
    tracker: CostTracker,
    *,
    client_built: bool,
    dry_run: bool = False,
) -> Optional[str]:
    """Why no LLM call happened, or None when at least one did.

    A bare count of zero reads as "the model had nothing to add", which is
    indistinguishable from a provider that could never have been reached.
    Name the cause instead of leaving the reader to guess.

    `calls` counts answers, so a provider that refused every request left the
    same zero as a run that never asked. `attempts` separates them: a non-zero
    attempt count with no call is a refusal, and it outranks the other causes
    because it is the one thing measured directly.
    """
    if tracker.call_count:
        return None
    if tracker.attempts:
        return "provider_refused"
    if dry_run:
        return "dry_run"
    provider = llm_config.provider
    if provider in ("openai", "anthropic") and not llm_config.api_key:
        return f"no_api_key_for_{provider}"
    if not client_built:
        return "no_phase_requested_an_llm"
    return "client_built_but_unused"


def llm_usage_record(
    llm_config: LLMConfig,
    tracker: CostTracker,
    *,
    client_built: bool,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Build the llm.usage payload. Callers persist it under that key."""
    from cyberai.core.pricing import total_cost

    return {
        "provider": llm_config.provider,
        "model": llm_config.model,
        "client_built": client_built,
        "calls": tracker.call_count,
        "attempts": tracker.attempts,
        "input_tokens": sum(c.input_tokens for c in tracker.calls),
        "output_tokens": sum(c.output_tokens for c in tracker.calls),
        "cost_usd": round(total_cost(tracker), 6),
        "by_agent": sorted({c.agent for c in tracker.calls}),
        "zero_reason": llm_zero_reason(
            llm_config, tracker, client_built=client_built, dry_run=dry_run
        ),
    }

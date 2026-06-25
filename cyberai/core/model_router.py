"""
Per-phase model router (flag-gated, day 6 / STANDOFF II W1).

When `enable_model_routing` is False (default) the orchestrator uses a single
shared LLMClient — no behavioural change. When enabled, each phase gets a
client bound to a phase-appropriate model:

  - fast_model   (default haiku) for cheap phases (recon/intel/report)
  - strong_model (default opus)  for reasoning-heavy phases (exploit)

`phase_models` overrides the role default per phase by name. All per-phase
clients share ONE CostTracker so the budget stays aggregate.

Only EXPLOIT and REPORT actually call the LLM today, but the table covers all
phases so future LLM-bound work routes correctly without a contract change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Optional

from cyberai.core.config import LLMConfig, RoutingConfig
from cyberai.core.scan_session import ScanPhase

if TYPE_CHECKING:
    from cyberai.core.cost_tracker import CostTracker
    from cyberai.core.llm_client import LLMClient

# Role default per phase. Strong only where reasoning depth pays off.
_PHASE_ROLE: Dict[ScanPhase, str] = {
    ScanPhase.RECON: "fast",
    ScanPhase.INTEL: "fast",
    ScanPhase.EXPLOIT: "strong",
    ScanPhase.REPORT: "fast",
}


class ModelRouter:
    """Resolves and caches one LLMClient per phase, sharing a CostTracker."""

    def __init__(
        self,
        base_llm: LLMConfig,
        routing: RoutingConfig,
        cost_tracker: Optional["CostTracker"] = None,
        budget_usd: float = 0.0,
    ) -> None:
        self._base = base_llm
        self._routing = routing
        self._cost_tracker = cost_tracker
        self._budget_usd = budget_usd
        self._cache: Dict[str, "LLMClient"] = {}

    def model_for(self, phase: ScanPhase) -> str:
        """Resolve the model name for a phase: explicit override → role → base."""
        override = self._routing.phase_models.get(phase.value)
        if override:
            return override
        role = _PHASE_ROLE.get(phase, "fast")
        return self._routing.strong_model if role == "strong" else self._routing.fast_model

    def client_for(self, phase: ScanPhase) -> "LLMClient":
        """Return a cached LLMClient bound to this phase's model."""
        model = self.model_for(phase)
        cached = self._cache.get(model)
        if cached is not None:
            return cached
        from cyberai.core.llm_client import LLMClient

        phase_cfg = LLMConfig(
            provider=self._base.provider,
            model=model,
            api_key=self._base.api_key,
            base_url=self._base.base_url,
            max_tokens=self._base.max_tokens,
            temperature=self._base.temperature,
        )
        client = LLMClient(
            phase_cfg,
            cost_tracker=self._cost_tracker,
            budget_usd=self._budget_usd,
        )
        self._cache[model] = client
        return client

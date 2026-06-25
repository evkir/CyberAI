"""Tests for the per-phase model router (day 6 / STANDOFF II W1)."""

from __future__ import annotations

from cyberai.core.config import LLMConfig, RoutingConfig
from cyberai.core.cost_tracker import CostTracker
from cyberai.core.model_router import ModelRouter
from cyberai.core.scan_session import ScanPhase


def _router(routing: RoutingConfig, tracker: CostTracker | None = None) -> ModelRouter:
    base = LLMConfig(provider="anthropic", model="claude-sonnet-4-6", api_key="k")
    return ModelRouter(base, routing, cost_tracker=tracker)


def test_model_for_role_defaults():
    r = _router(RoutingConfig())
    # Strong only for exploit; fast for the rest.
    assert r.model_for(ScanPhase.EXPLOIT) == "claude-opus-4-8"
    assert r.model_for(ScanPhase.RECON) == "claude-haiku-4-5"
    assert r.model_for(ScanPhase.INTEL) == "claude-haiku-4-5"
    assert r.model_for(ScanPhase.REPORT) == "claude-haiku-4-5"


def test_phase_models_override_wins():
    routing = RoutingConfig(phase_models={"report": "gpt-4o", "exploit": "claude-sonnet-4-6"})
    r = _router(routing)
    assert r.model_for(ScanPhase.REPORT) == "gpt-4o"
    assert r.model_for(ScanPhase.EXPLOIT) == "claude-sonnet-4-6"
    # Unoverridden phase still falls back to role default.
    assert r.model_for(ScanPhase.RECON) == "claude-haiku-4-5"


def test_client_for_binds_model_and_caches():
    r = _router(RoutingConfig())
    c_exploit = r.client_for(ScanPhase.EXPLOIT)
    assert c_exploit.config.model == "claude-opus-4-8"
    # Same phase -> cached identical client object.
    assert r.client_for(ScanPhase.EXPLOIT) is c_exploit
    # recon/intel/report share one fast model -> same cached client.
    c_recon = r.client_for(ScanPhase.RECON)
    assert c_recon.config.model == "claude-haiku-4-5"
    assert r.client_for(ScanPhase.INTEL) is c_recon


def test_clients_share_one_cost_tracker():
    tracker = CostTracker()
    r = _router(RoutingConfig(), tracker=tracker)
    assert r.client_for(ScanPhase.EXPLOIT).cost_tracker is tracker
    assert r.client_for(ScanPhase.RECON).cost_tracker is tracker


def test_phase_client_inherits_base_provider_and_key():
    r = _router(RoutingConfig())
    c = r.client_for(ScanPhase.EXPLOIT)
    assert c.config.provider == "anthropic"
    assert c.config.api_key == "k"

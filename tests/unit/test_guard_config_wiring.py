"""The guard's settings travel from the environment to the object that uses it.

Three hops, and each one has been a place where settings went missing before:
env to CyberAIConfig, CyberAIConfig to LLMClient, and base config to a routed
client. The router rebuilt LLMConfig field by field, so anything not named in
that constructor was dropped — the trust policy would have been.
"""

from dataclasses import replace

from cyberai.core.config import CyberAIConfig, LLMConfig, RoutingConfig
from cyberai.core.llm_client import LLMClient
from cyberai.core.model_router import ModelRouter
from cyberai.core.scan_session import ScanPhase
from cyberai.core.security.guard import ANNOTATE, DEFAULT_THRESHOLD, DENY, QUARANTINE


def test_env_reaches_the_config(monkeypatch):
    monkeypatch.setenv("CYBERAI_INJECTION_POLICY", QUARANTINE)
    monkeypatch.setenv("CYBERAI_INJECTION_THRESHOLD", "70")
    cfg = CyberAIConfig.from_env()
    assert cfg.llm.injection_policy == QUARANTINE
    assert cfg.llm.injection_threshold == 70


def test_unset_env_leaves_the_fields_unconfigured(monkeypatch):
    """None is 'not configured', not 'configured to the default'."""
    monkeypatch.delenv("CYBERAI_INJECTION_POLICY", raising=False)
    monkeypatch.delenv("CYBERAI_INJECTION_THRESHOLD", raising=False)
    cfg = CyberAIConfig.from_env()
    assert cfg.llm.injection_policy is None
    assert cfg.llm.injection_threshold is None


def test_unparseable_threshold_does_not_abort_startup(monkeypatch):
    monkeypatch.setenv("CYBERAI_INJECTION_THRESHOLD", "aggressive")
    assert CyberAIConfig.from_env().llm.injection_threshold is None


def test_config_reaches_the_client(monkeypatch):
    monkeypatch.delenv("CYBERAI_INJECTION_POLICY", raising=False)
    client = LLMClient(LLMConfig(injection_policy=DENY, injection_threshold=70))
    assert client.guard.policy == DENY
    assert client.guard.threshold == 70


def test_explicit_config_wins_over_the_environment(monkeypatch):
    monkeypatch.setenv("CYBERAI_INJECTION_POLICY", DENY)
    client = LLMClient(LLMConfig(injection_policy=QUARANTINE))
    assert client.guard.policy == QUARANTINE


def test_client_falls_back_to_the_environment(monkeypatch):
    monkeypatch.setenv("CYBERAI_INJECTION_POLICY", DENY)
    assert LLMClient(LLMConfig()).guard.policy == DENY


def test_client_defaults_when_nothing_is_configured(monkeypatch):
    monkeypatch.delenv("CYBERAI_INJECTION_POLICY", raising=False)
    monkeypatch.delenv("CYBERAI_INJECTION_THRESHOLD", raising=False)
    client = LLMClient(LLMConfig())
    assert client.guard.policy == ANNOTATE
    assert client.guard.threshold == DEFAULT_THRESHOLD


def test_a_routed_client_keeps_the_policy(monkeypatch):
    """The router derives its per-phase config; it must not lose settings."""
    monkeypatch.delenv("CYBERAI_INJECTION_POLICY", raising=False)
    base = LLMConfig(provider="ollama", model="qwen2.5:7b", injection_policy=DENY)
    router = ModelRouter(base_llm=base, routing=RoutingConfig(enable_model_routing=True))
    client = router.client_for(ScanPhase.RECON)
    assert client.guard.policy == DENY


def test_replace_carries_new_fields_by_construction():
    """A field added to LLMConfig later travels without touching the router."""
    base = LLMConfig(injection_policy=QUARANTINE, injection_threshold=70)
    derived = replace(base, model="other")
    assert derived.injection_policy == QUARANTINE
    assert derived.injection_threshold == 70

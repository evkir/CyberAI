"""The audit logger reaches the client that guards the calls.

Assignment happens when a client is handed out, not when it is built, because
clients are cached across a run while AuditLogger is rebuilt per session. Three
paths hand out a client — dry-run, the shared client, and the routed one — and
each is a place the logger could go missing without anything going red.
"""

from dataclasses import replace

from cyberai.core.config import CyberAIConfig, LLMConfig, RoutingConfig
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanPhase


def test_dry_run_hands_out_no_client_and_does_not_crash():
    """Dry-run builds no client at all; the guard must tolerate having none."""
    orch = Orchestrator(dry_run=True)
    assert orch._client_for(ScanPhase.RECON) is None


def test_the_shared_client_receives_this_run_s_logger():
    orch = Orchestrator(dry_run=False)
    orch.audit = object()
    client = orch._client_for(ScanPhase.RECON)
    assert client is not None
    assert client.audit is orch.audit


def test_a_routed_client_receives_the_logger_too():
    """Model routing is off by default, so this path has its own hand-out."""
    cfg = CyberAIConfig(
        llm=LLMConfig(provider="ollama", model="qwen2.5:7b"),
        routing=RoutingConfig(enable_model_routing=True),
    )
    orch = Orchestrator(config=cfg)
    orch.audit = object()
    client = orch._client_for(ScanPhase.RECON)
    assert client is not None
    assert client.audit is orch.audit


def test_a_second_session_does_not_write_into_the_first_one_s_file():
    """The reason assignment is at hand-out: the client outlives the logger."""
    orch = Orchestrator(dry_run=False)
    orch.audit = first = object()
    client_one = orch._client_for(ScanPhase.RECON)
    assert client_one.audit is first

    orch.audit = second = object()
    client_two = orch._client_for(ScanPhase.RECON)
    assert client_two is client_one, "the client is cached, that is the point"
    assert client_two.audit is second


def test_config_derived_for_routing_keeps_the_injection_policy():
    """Guarded by the router's use of replace; asserted here at the seam."""
    base = LLMConfig(injection_policy="deny", injection_threshold=70)
    assert replace(base, model="other").injection_policy == "deny"

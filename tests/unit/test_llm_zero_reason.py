"""A zero call count must carry its cause.

Zero is a legitimate outcome, but "the provider was unreachable" and "no
phase asked for a model" call for opposite fixes. The reason field keeps
those apart, and goes to None the moment a real call is recorded.
"""

from cyberai.core.config import CyberAIConfig
from cyberai.core.orchestrator import Orchestrator


def _config(provider: str, api_key=None) -> CyberAIConfig:
    cfg = CyberAIConfig()
    cfg.llm.provider = provider
    cfg.llm.api_key = api_key
    return cfg


def test_dry_run_is_named_as_such():
    orch = Orchestrator(_config("openai"), dry_run=True)
    assert orch._llm_zero_reason() == "dry_run"


def test_cloud_provider_without_a_key_is_named():
    orch = Orchestrator(_config("openai"), dry_run=False)
    assert orch._llm_zero_reason() == "no_api_key_for_openai"


def test_anthropic_without_a_key_is_named():
    orch = Orchestrator(_config("anthropic"), dry_run=False)
    assert orch._llm_zero_reason() == "no_api_key_for_anthropic"


def test_local_provider_needs_no_key_and_blames_the_pipeline():
    orch = Orchestrator(_config("ollama"), dry_run=False)
    assert orch._llm_zero_reason() == "no_phase_requested_an_llm"


def test_a_built_client_that_never_ran_is_named():
    """The branch every live web scan actually takes: each agent is handed a
    client at construction time, so one exists even when no phase calls it."""
    orch = Orchestrator(_config("ollama"), dry_run=False)
    assert orch.llm is not None
    assert orch._llm_zero_reason() == "client_built_but_unused"


def test_a_recorded_call_clears_the_reason():
    orch = Orchestrator(_config("ollama"), dry_run=False)
    orch.cost_tracker.add("exploit", "qwen", input_tokens=10, output_tokens=5)
    assert orch._llm_zero_reason() is None


def test_reason_lands_in_the_session_export():
    orch = Orchestrator(_config("openai"), dry_run=True)
    session = orch.run("example.com")
    assert session.kb.get("llm.usage")["zero_reason"] == "dry_run"

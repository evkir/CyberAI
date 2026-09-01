"""A zero call count must carry its cause.

Zero is a legitimate outcome, but "the provider was unreachable" and "no
phase asked for a model" call for opposite fixes. The reason field keeps
those apart, and goes to None the moment a real call is recorded.
"""

from cyberai.core.config import CyberAIConfig, LLMConfig
from cyberai.core.cost_tracker import CostTracker
from cyberai.core.llm_usage import llm_zero_reason
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


def test_a_provider_holding_its_own_key_is_not_blamed_for_missing_one(monkeypatch):
    """The negative cases above set the field by hand, so none of them saw
    the resolver. Before it, an Anthropic run with ANTHROPIC_API_KEY exported
    still answered no_api_key_for_anthropic: the field read OPENAI_API_KEY,
    while the SDK quietly found the real key and made the call anyway."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anthropic")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    cfg = CyberAIConfig()
    cfg.llm = LLMConfig(provider="anthropic")
    reason = llm_zero_reason(cfg.llm, CostTracker(), client_built=False)
    assert reason == "no_phase_requested_an_llm"


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


def test_a_path_that_uses_no_model_is_not_blamed_on_a_missing_key():
    """The bench agent path hands its agents no client at all, so a provider
    key would change nothing. The default provider is a cloud one and the
    default key is absent, so the missing-key cause answered every such run
    and sent the reader after a knob that was never the reason."""
    cfg = _config("openai")
    reason = llm_zero_reason(cfg.llm, CostTracker(), client_built=False, engine_uses_a_model=False)
    assert reason == "engine_uses_no_model"


def test_the_default_leaves_the_credential_answer_where_it_was():
    """The pipeline does use a model, and there the missing key is the cause."""
    cfg = _config("openai")
    reason = llm_zero_reason(cfg.llm, CostTracker(), client_built=False)
    assert reason == "no_api_key_for_openai"


def test_a_recorded_answer_outranks_a_path_that_takes_no_model():
    """A path describes intent; a recorded call is a measurement."""
    tracker = CostTracker()
    tracker.add("exploit", "qwen", input_tokens=10, output_tokens=5)
    reason = llm_zero_reason(
        _config("ollama").llm, tracker, client_built=False, engine_uses_a_model=False
    )
    assert reason is None

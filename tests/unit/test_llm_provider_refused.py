from cyberai.core.config import CyberAIConfig, LLMConfig
from cyberai.core.orchestrator import Orchestrator


def _orch(**llm_kwargs):
    cfg = CyberAIConfig(llm=LLMConfig(**llm_kwargs))
    return Orchestrator(config=cfg)


def test_an_attempt_without_an_answer_is_named_a_refusal():
    orch = _orch(provider="ollama", model="whatever")
    orch._llm = object()
    orch.cost_tracker.record_attempt()
    assert orch._llm_zero_reason() == "provider_refused"


def test_a_refusal_outranks_the_missing_key_verdict():
    orch = _orch(provider="openai", model="gpt-4o", api_key=None)
    orch._llm = object()
    orch.cost_tracker.record_attempt()
    assert orch._llm_zero_reason() == "provider_refused"


def test_without_an_attempt_the_older_verdicts_still_stand():
    orch = _orch(provider="ollama", model="whatever")
    orch._llm = object()
    assert orch.cost_tracker.attempts == 0
    assert orch._llm_zero_reason() == "client_built_but_unused"


def test_an_answered_call_still_reports_no_reason_at_all():
    orch = _orch(provider="ollama", model="whatever")
    orch._llm = object()
    orch.cost_tracker.record_attempt()
    orch.cost_tracker.add("probe", "whatever", 1, 1)
    assert orch._llm_zero_reason() is None

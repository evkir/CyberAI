"""LLM usage must be observable in the session export.

Zero calls is a legitimate result; an absent metric is not. These tests pin
that the KB always carries the metric, and that it distinguishes a client
that was never built from one that was built and used.
"""

from cyberai.core.config import CyberAIConfig
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanSession


def test_dry_run_records_zero_usage_with_no_client():
    orch = Orchestrator(CyberAIConfig(), dry_run=True)
    session = orch.run("example.com")

    usage = session.kb.get("llm.usage")
    assert usage is not None
    assert usage["calls"] == 0
    assert usage["client_built"] is False
    assert usage["cost_usd"] == 0.0
    assert usage["by_agent"] == []


def test_recorded_calls_are_summed_per_agent():
    orch = Orchestrator(CyberAIConfig(), dry_run=True)
    orch.cost_tracker.add("exploit", "gpt-4o", input_tokens=100, output_tokens=20)
    orch.cost_tracker.add("report", "gpt-4o", input_tokens=50, output_tokens=10)
    session = ScanSession(target="example.com", authorized_scope=[])

    orch._record_llm_usage(session)

    usage = session.kb.get("llm.usage")
    assert usage["calls"] == 2
    assert usage["input_tokens"] == 150
    assert usage["output_tokens"] == 30
    assert usage["by_agent"] == ["exploit", "report"]
    assert usage["cost_usd"] > 0


def test_usage_survives_session_json_roundtrip():
    orch = Orchestrator(CyberAIConfig(), dry_run=True)
    session = orch.run("example.com")

    restored = ScanSession.from_json(session.to_json())

    assert restored.kb.get("llm.usage")["provider"] == "openai"

"""The report has to say what the model did, in the file the operator opens.

The orchestrator writes llm.usage after every phase, which is after this agent
has closed its documents. Tests that put the key in the knowledge base by hand
passed while a live run produced an empty key and no section -- so this one
goes through ReportAgent.run() and reads the files from disk.
"""

import json

from cyberai.agents.report.agent import ReportAgent
from cyberai.core.config import CyberAIConfig, LLMConfig
from cyberai.core.cost_tracker import CostTracker
from cyberai.core.scan_session import ScanSession


class _StubLLM:
    """Stands in for LLMClient: the agent only needs its cost_tracker here."""

    def __init__(self, tracker):
        self.cost_tracker = tracker


def _run(tmp_path, tracker):
    config = CyberAIConfig(
        llm=LLMConfig(provider="ollama", model="qwen2.5-coder:14b"),
        output_dir=tmp_path,
    )
    session = ScanSession(target="http://127.0.0.1:3000")
    agent = ReportAgent(config, session, _StubLLM(tracker), None)
    result = agent.run(session.target)
    return result, open(result["markdown"]).read(), json.loads(open(result["json"]).read())


def test_an_answered_run_names_the_agents_that_asked(tmp_path):
    tracker = CostTracker()
    tracker.record_attempt()
    tracker.add("report", "qwen2.5-coder:14b", 2189, 240)
    _, md, exported = _run(tmp_path, tracker)

    assert "## Model Participation" in md
    assert "**Calls answered:** 1" in md
    assert "`report`" in md
    assert exported["llm_usage"]["calls"] == 1
    assert exported["llm_usage"]["zero_reason"] is None


def test_a_refused_run_names_the_reason_in_both_documents(tmp_path):
    tracker = CostTracker()
    tracker.record_attempt()
    tracker.record_attempt()
    _, md, exported = _run(tmp_path, tracker)

    assert "provider_refused" in md
    assert "**Calls attempted:** 2" in md
    assert exported["llm_usage"]["zero_reason"] == "provider_refused"
    assert exported["llm_usage"]["attempts"] == 2


def test_the_section_is_written_once(tmp_path):
    tracker = CostTracker()
    tracker.record_attempt()
    tracker.add("report", "m", 1, 1)
    _, md, _ = _run(tmp_path, tracker)

    assert md.count("## Model Participation") == 1


def test_a_run_without_a_client_leaves_the_section_out(tmp_path):
    config = CyberAIConfig(output_dir=tmp_path)
    session = ScanSession(target="http://127.0.0.1:3000")
    agent = ReportAgent(config, session, None, None)
    result = agent.run(session.target)

    md = open(result["markdown"]).read()
    assert "## Model Participation" not in md

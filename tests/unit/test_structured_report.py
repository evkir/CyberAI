"""Structured outputs: ReportSection, structured_call, H1 export."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from cyberai.agents.report.h1_exporter import export_hackerone
from cyberai.core.llm_client import LLMClient
from cyberai.core.types import ReportSection


# ── ReportSection model ───────────────────────────────────────────────


def test_section_severity_normalized():
    s = ReportSection(title="t", severity="critical")
    assert s.severity == "CRITICAL"


def test_section_severity_invalid_falls_back_info():
    s = ReportSection(title="t", severity="bogus")
    assert s.severity == "INFO"


def test_section_defaults():
    s = ReportSection(title="t")
    assert s.severity == "INFO"
    assert s.findings == []
    assert s.recommendations == []
    assert s.impact == ""


# ── HackerOne export ──────────────────────────────────────────────────


def _sample_section() -> ReportSection:
    return ReportSection(
        title="SQL Injection in login",
        severity="HIGH",
        findings=["Send ' OR 1=1-- in username", "Observe auth bypass"],
        recommendations=["Use parameterized queries"],
        impact="Full auth bypass, account takeover.",
    )


def test_h1_export_contains_sections():
    md = export_hackerone(_sample_section())
    assert "# SQL Injection in login" in md
    assert "**Severity:** High" in md
    assert "## Steps to Reproduce" in md
    assert "## Impact" in md
    assert "## Recommendation" in md


def test_h1_export_info_maps_to_none():
    md = export_hackerone(ReportSection(title="x", severity="INFO"))
    assert "**Severity:** None" in md


def test_h1_export_empty_lists_placeholder():
    md = export_hackerone(ReportSection(title="x", severity="LOW"))
    assert "_None provided._" in md
    assert "_Impact not specified._" in md


def test_h1_roundtrip_steps_present():
    section = _sample_section()
    md = export_hackerone(section)
    for step in section.findings:
        assert step in md
    for rec in section.recommendations:
        assert rec in md


# ── structured_call provider branches (mocked SDK) ────────────────────


def _client(provider: str) -> LLMClient:
    cfg = MagicMock()
    cfg.provider = provider
    cfg.api_key = "x"
    cfg.model = "test-model"
    cfg.max_tokens = 1024
    cfg.temperature = 0.0
    return LLMClient(cfg)


SCHEMA = ReportSection.model_json_schema()
PAYLOAD = {"title": "t", "severity": "HIGH", "findings": ["a"]}


def test_structured_call_openai(monkeypatch):
    client = _client("openai")
    fake = MagicMock()
    msg = MagicMock()
    msg.content = json.dumps(PAYLOAD)
    fake.choices = [MagicMock(message=msg)]
    fake.usage = MagicMock(prompt_tokens=10, completion_tokens=5)
    fake.model = "test-model"

    import openai

    inst = MagicMock()
    inst.chat.completions.create.return_value = fake
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: inst)

    out = client.structured_call(
        [{"role": "user", "content": "go"}], schema=SCHEMA, schema_name="rs"
    )
    assert out["title"] == "t"
    # response_format must carry json_schema
    kwargs = inst.chat.completions.create.call_args.kwargs
    assert kwargs["response_format"]["type"] == "json_schema"


def test_structured_call_anthropic(monkeypatch):
    client = _client("anthropic")
    block = MagicMock()
    block.type = "tool_use"
    block.input = PAYLOAD
    fake = MagicMock()
    fake.content = [block]
    fake.usage = MagicMock(
        input_tokens=10,
        output_tokens=5,
        cache_creation_input_tokens=0,
        cache_read_input_tokens=0,
    )
    fake.model = "test-model"

    import anthropic

    inst = MagicMock()
    inst.messages.create.return_value = fake
    monkeypatch.setattr(anthropic, "Anthropic", lambda **kw: inst)

    out = client.structured_call(
        [{"role": "user", "content": "go"}], schema=SCHEMA, schema_name="rs"
    )
    assert out["severity"] == "HIGH"
    # forced single-tool choice
    kwargs = inst.messages.create.call_args.kwargs
    assert kwargs["tool_choice"] == {"type": "tool", "name": "rs"}


def test_structured_call_ollama_unsupported():
    client = _client("ollama")
    try:
        client.structured_call([], schema=SCHEMA)
        assert False, "expected ValueError"
    except ValueError:
        pass


# ── ReportAgent._structured_summary (mocked) ──────────────────────────


def _report_agent(provider="anthropic"):
    from cyberai.agents.report.agent import ReportAgent

    agent = ReportAgent.__new__(ReportAgent)
    agent.AGENT_NAME = "report"
    agent.llm = MagicMock()
    agent.llm.config.provider = provider
    session = MagicMock()
    session.findings = [
        MagicMock(title="Log4Shell", severity="CRITICAL", description="rce"),
    ]
    agent.session = session
    return agent


def test_structured_summary_validates():
    agent = _report_agent()
    agent.llm.structured_call.return_value = {
        "title": "Exec summary",
        "severity": "critical",
        "findings": ["Log4Shell RCE"],
        "recommendations": ["Patch log4j"],
        "impact": "RCE on host.",
    }
    section = agent._structured_summary("testhost")
    assert isinstance(section, ReportSection)
    assert section.severity == "CRITICAL"  # normalized
    md = export_hackerone(section)
    assert "Log4Shell RCE" in md


def test_structured_summary_failsafe_returns_none():
    agent = _report_agent()
    agent.llm.structured_call.side_effect = RuntimeError("api down")
    agent._log = MagicMock()
    assert agent._structured_summary("testhost") is None

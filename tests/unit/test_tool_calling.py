"""Native LLM tool calling: spec converters, executor, loop."""

from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

from cyberai.core.base_agent import Tool
from cyberai.core.llm_client import (
    LLMResponse,
    ToolCall,
    _params_to_schema,
    _tools_to_anthropic_format,
    _tools_to_openai_format,
    format_assistant_tool_turn,
    format_tool_results,
)

# ── fixtures ──────────────────────────────────────────────────────────


def _noop(**kwargs: Any) -> Dict[str, Any]:
    return {"ok": True, **kwargs}


@pytest.fixture
def flat_tool() -> Tool:
    return Tool(
        name="ping",
        description="ping a host",
        func=_noop,
        params={"host": "target host"},
    )


@pytest.fixture
def schema_tool() -> Tool:
    return Tool(
        name="build_chain",
        description="build a chain",
        func=_noop,
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    )


# ── _params_to_schema ─────────────────────────────────────────────────


def test_params_to_schema_from_flat_params(flat_tool):
    schema = _params_to_schema(flat_tool)
    assert schema["type"] == "object"
    assert schema["properties"]["host"]["type"] == "string"
    assert schema["required"] == ["host"]


def test_params_to_schema_prefers_explicit(schema_tool):
    schema = _params_to_schema(schema_tool)
    assert schema["properties"]["target"]["type"] == "string"
    # explicit schema is returned verbatim — no synthetic string props
    assert set(schema["properties"]) == {"target"}


# ── spec converters ───────────────────────────────────────────────────


def test_openai_format_shape(flat_tool):
    spec = _tools_to_openai_format([flat_tool])[0]
    assert spec["type"] == "function"
    assert spec["function"]["name"] == "ping"
    assert spec["function"]["parameters"]["properties"]["host"]


def test_anthropic_format_shape(flat_tool):
    spec = _tools_to_anthropic_format([flat_tool])[0]
    assert spec["name"] == "ping"
    assert "input_schema" in spec
    assert spec["input_schema"]["properties"]["host"]


# ── provider-aware threading ──────────────────────────────────────────


def test_format_assistant_turn_anthropic():
    resp = LLMResponse(
        text="thinking",
        tool_calls=[ToolCall(id="t1", name="ping", arguments={"host": "x"})],
    )
    turn = format_assistant_tool_turn("anthropic", resp)
    assert turn["role"] == "assistant"
    types = [b["type"] for b in turn["content"]]
    assert "tool_use" in types and "text" in types


def test_format_assistant_turn_openai():
    resp = LLMResponse(
        text=None,
        tool_calls=[ToolCall(id="t1", name="ping", arguments={"host": "x"})],
    )
    turn = format_assistant_tool_turn("openai", resp)
    assert turn["tool_calls"][0]["function"]["name"] == "ping"
    # OpenAI arguments must be a JSON string, not a dict
    assert json.loads(turn["tool_calls"][0]["function"]["arguments"]) == {"host": "x"}


def test_format_tool_results_anthropic():
    tc = ToolCall(id="t1", name="ping", arguments={})
    msgs = format_tool_results("anthropic", [(tc, "result-str")])
    block = msgs[0]["content"][0]
    assert block["type"] == "tool_result"
    assert block["tool_use_id"] == "t1"


def test_format_tool_results_openai():
    tc = ToolCall(id="t1", name="ping", arguments={})
    msgs = format_tool_results("openai", [(tc, "result-str")])
    assert msgs[0]["role"] == "tool"
    assert msgs[0]["tool_call_id"] == "t1"


# ── ExploitAgent native loop (mocked LLM) ─────────────────────────────


RANKED = [
    {
        "cve_id": "CVE-TEST",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
]


def _make_agent():
    from cyberai.agents.exploit.agent import ExploitAgent

    agent = ExploitAgent.__new__(ExploitAgent)
    agent.AGENT_NAME = "exploit"
    agent.tools = {}
    agent.llm = MagicMock()
    agent.llm.config.provider = "anthropic"
    agent.config = MagicMock()
    agent.config.max_agent_iterations = 5
    agent._register_tools()
    return agent


def test_exec_native_tool_resolves_cve_id():
    agent = _make_agent()
    tc = ToolCall(id="t1", name="analyze_vector", arguments={"cve_id": "CVE-TEST"})
    out = agent._exec_native_tool(tc, RANKED, "127.0.0.1")
    assert out["remotely_exploitable"] is True


def test_exec_native_tool_unknown_cve_id():
    agent = _make_agent()
    tc = ToolCall(id="t1", name="analyze_vector", arguments={"cve_id": "NOPE"})
    out = agent._exec_native_tool(tc, RANKED, "127.0.0.1")
    assert "error" in out


def test_exec_native_tool_build_chain():
    agent = _make_agent()
    tc = ToolCall(id="t2", name="build_chain", arguments={"target": "10.0.0.1"})
    out = agent._exec_native_tool(tc, RANKED, "127.0.0.1")
    assert out["chain_length"] == 1


def test_native_chain_build_full_loop():
    agent = _make_agent()
    # 1st round: model asks for analyze_vector; 2nd: build_chain; then stop.
    agent.llm.call_tools.side_effect = [
        LLMResponse(
            text=None,
            tool_calls=[ToolCall(id="a1", name="analyze_vector", arguments={"cve_id": "CVE-TEST"})],
        ),
        LLMResponse(
            text=None,
            tool_calls=[ToolCall(id="c1", name="build_chain", arguments={"target": "10.0.0.1"})],
        ),
    ]
    chain = agent._native_chain_build("10.0.0.1", RANKED)
    assert chain is not None
    assert chain["chain_length"] == 1
    # loop stopped right after build_chain — exactly 2 LLM round-trips
    assert agent.llm.call_tools.call_count == 2


def test_native_chain_build_no_tool_calls_returns_none():
    agent = _make_agent()
    agent.llm.call_tools.return_value = LLMResponse(text="no tools", tool_calls=[])
    assert agent._native_chain_build("10.0.0.1", RANKED) is None

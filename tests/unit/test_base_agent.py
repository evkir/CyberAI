"""Tests for the redesigned BaseAgent contract — day 4 of STANDOFF."""

from __future__ import annotations

import pytest

from cyberai.core.base_agent import (
    AgentIterationLimitError,
    AgentMemory,
    BaseAgent,
    Tool,
)
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession


# ── a minimal concrete agent for testing ──────────────────────────────


class DummyAgent(BaseAgent):
    AGENT_NAME = "dummy"
    ROLE = "Test Agent"

    def _register_tools(self) -> None:
        self.register_tool(
            Tool(
                name="echo",
                description="returns its input",
                func=lambda value: value,
                parameters={"value": "str"},
            )
        )

    def run(self, target, context=None):
        return {"target": target, "ok": True}


@pytest.fixture
def dummy_agent():
    config = CyberAIConfig()
    session = ScanSession(target="testhost.local")
    return DummyAgent(config, session)


# ── Tool ──────────────────────────────────────────────────────────────


def test_tool_parameters_alias_synced():
    t = Tool(name="x", description="d", func=lambda: 1, parameters={"a": "str"})
    assert t.params == {"a": "str"}
    assert t.parameters == {"a": "str"}


def test_tool_params_directly():
    t = Tool(name="x", description="d", func=lambda: 1, params={"b": "int"})
    assert t.parameters == {"b": "int"}


# ── AgentMemory ───────────────────────────────────────────────────────


def test_memory_stores_messages():
    m = AgentMemory()
    m.add("user", "hello")
    m.add("assistant", "hi")
    assert m.to_messages() == [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi"},
    ]


def test_memory_system_kept_separate():
    m = AgentMemory()
    m.add("system", "you are a pentester")
    m.add("user", "scan this")
    assert m.system == "you are a pentester"
    assert m.to_messages() == [{"role": "user", "content": "scan this"}]


def test_memory_clear():
    m = AgentMemory()
    m.add("user", "x")
    m.add("system", "s")
    m.clear()
    assert m.to_messages() == []
    assert m.system is None


# ── BaseAgent construction ────────────────────────────────────────────


def test_agent_exposes_expected_attrs(dummy_agent):
    for attr in ("config", "session", "kb", "llm", "audit", "memory", "tools"):
        assert hasattr(dummy_agent, attr), f"missing {attr}"


def test_agent_registers_tools(dummy_agent):
    assert "echo" in dummy_agent.tools


def test_agent_call_tool(dummy_agent):
    assert dummy_agent.call_tool("echo", value="ping") == "ping"


def test_agent_call_unknown_tool_raises(dummy_agent):
    with pytest.raises(ValueError, match="not registered"):
        dummy_agent.call_tool("nope")


def test_agent_run_returns_dict(dummy_agent):
    result = dummy_agent.run("example.com")
    assert result == {"target": "example.com", "ok": True}


# ── iteration limit (KI-4) ────────────────────────────────────────────


def test_iteration_limit_raises_past_max():
    config = CyberAIConfig()
    config.max_agent_iterations = 3
    agent = DummyAgent(config, ScanSession(target="x"))

    # 3 allowed
    for _ in range(3):
        agent._check_iteration_limit()
    # 4th trips
    with pytest.raises(AgentIterationLimitError, match="exceeded 3"):
        agent._check_iteration_limit()


def test_log_and_alias_do_not_crash(dummy_agent):
    dummy_agent.log("a message")
    dummy_agent._log("aliased message", data={"k": "v"})

"""The console echo must print the agent's name, not swallow it as markup.

`console.print(f"[cyan][{AGENT_NAME}][/cyan] {msg}")` reads like a bracketed
prefix, but rich parses the inner brackets as a markup tag and drops them, so
every agent in every pipeline echoed its lines anonymously. Nothing caught it
because the remaining text reads perfectly well on its own: the defect is a
missing token, not a broken line.
"""

from __future__ import annotations

import io

from rich.console import Console

import cyberai.core.base_agent as base_agent_module
from cyberai.core.base_agent import BaseAgent, Tool
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession


class _NamedAgent(BaseAgent):
    AGENT_NAME = "mcp_scan"
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


def _agent_and_buffer(monkeypatch):
    buffer = io.StringIO()
    monkeypatch.setattr(base_agent_module, "console", Console(file=buffer, width=200))
    agent = _NamedAgent(CyberAIConfig(), ScanSession(target="testhost.local"))
    return agent, buffer


def test_the_log_echo_names_the_agent(monkeypatch):
    agent, buffer = _agent_and_buffer(monkeypatch)
    agent.log("scan target: testhost.local")
    printed = buffer.getvalue()
    assert "[mcp_scan]" in printed, printed
    assert "scan target: testhost.local" in printed


def test_the_tool_call_echo_names_the_agent(monkeypatch):
    agent, buffer = _agent_and_buffer(monkeypatch)
    agent.call_tool("echo", value="x")
    printed = buffer.getvalue()
    assert "[mcp_scan]" in printed, printed
    assert "echo" in printed

"""The mcp_scan MCP tool: CyberAI's server scanning other MCP servers."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

from cyberai.mcp.server import call_tool
from cyberai.mcp.tools import TOOL_REGISTRY, run_mcp_scan


def test_mcp_scan_registered():
    assert "mcp_scan" in TOOL_REGISTRY
    spec = TOOL_REGISTRY["mcp_scan"]
    schema = spec["inputSchema"]
    assert schema["type"] == "object"
    assert schema["required"] == ["endpoint"]
    assert set(schema["properties"]) == {"endpoint", "transport"}
    assert schema["properties"]["transport"]["enum"] == ["stdio", "sse", "http"]
    assert spec["handler"] is run_mcp_scan


def _patched_agent(fake_agent):
    """Patch the five lazily-imported dependencies of run_mcp_scan."""
    return (
        patch("cyberai.core.config.CyberAIConfig"),
        patch("cyberai.core.scan_session.ScanSession"),
        patch("cyberai.core.llm_client.LLMClient"),
        patch("cyberai.core.logger.AuditLogger"),
        patch("cyberai.agents.mcp_scan.MCPScanAgent", return_value=fake_agent),
    )


def test_run_mcp_scan_wires_agent_and_returns_result():
    fake = MagicMock()
    fake.run.return_value = {"endpoint": "http://t/mcp", "connected": True}
    cfg, sess, llm, aud, agent = _patched_agent(fake)
    with cfg, sess, llm, aud, agent:
        out = run_mcp_scan("http://t/mcp", transport="http")
    assert out == {"endpoint": "http://t/mcp", "connected": True}
    fake.run.assert_called_once_with("http://t/mcp", context={"transport": "http"})


def test_run_mcp_scan_without_transport_passes_none_context():
    fake = MagicMock()
    fake.run.return_value = {"ok": True}
    cfg, sess, llm, aud, agent = _patched_agent(fake)
    with cfg, sess, llm, aud, agent:
        run_mcp_scan("stdio://python3 server.py")
    fake.run.assert_called_once_with("stdio://python3 server.py", context=None)


def test_mcp_scan_dispatches_through_call_tool():
    fake = MagicMock()
    fake.run.return_value = {"endpoint": "http://t/mcp", "connected": False}
    cfg, sess, llm, aud, agent = _patched_agent(fake)
    with cfg, sess, llm, aud, agent:
        res = asyncio.run(call_tool("mcp_scan", {"endpoint": "http://t/mcp"}))
    assert len(res) == 1
    payload = json.loads(res[0].text)
    assert payload == {"endpoint": "http://t/mcp", "connected": False}

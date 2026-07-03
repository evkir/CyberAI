"""Agent-level wiring of the optional MST low-level MCP fuzzer.

The agent is built via ``__new__`` and driven against a real ScanSession.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cyberai.agents.mcp_scan.agent import MCPScanAgent
from cyberai.agents.mcp_scan.mst_bridge import MSTFinding
from cyberai.core.scan_session import ScanSession, Severity


def _agent(target: str = "stdio://python3 server.py") -> MCPScanAgent:
    agent = MCPScanAgent.__new__(MCPScanAgent)
    agent.AGENT_NAME = "mcp_scan"
    agent._log = MagicMock()
    agent.kb = MagicMock()
    agent.session = ScanSession(target=target)
    return agent


def test_run_mst_off_by_default():
    agent = _agent()
    with patch("cyberai.agents.mcp_scan.mst_bridge.MSTBridge") as bridge_cls:
        assert agent._run_mst("stdio://x", "stdio", None) == []
        assert agent._run_mst("stdio://x", "stdio", {"transport": "stdio"}) == []
        bridge_cls.assert_not_called()
    assert agent.session.findings == []


def test_run_mst_graceful_when_unavailable():
    agent = _agent()
    fake = MagicMock()
    fake.available = False
    with patch("cyberai.agents.mcp_scan.mst_bridge.MSTBridge", return_value=fake):
        out = agent._run_mst("stdio://x", "stdio", {"mst_fuzz": True})
    assert out == []
    fake.fuzz.assert_not_called()
    assert agent.session.findings == []


def test_run_mst_records_findings_when_available():
    agent = _agent()
    fake = MagicMock()
    fake.available = True
    fake.fuzz.return_value = [
        MSTFinding(check="stdio_rce", severity=Severity.CRITICAL, detail="rce"),
        MSTFinding(check="dns_rebind", severity=Severity.MEDIUM, detail="rebind"),
    ]
    with patch("cyberai.agents.mcp_scan.mst_bridge.MSTBridge", return_value=fake):
        out = agent._run_mst("stdio://x", "stdio", {"mst_fuzz": True})
    assert [d["check"] for d in out] == ["stdio_rce", "dns_rebind"]
    assert out[0]["severity"] == "CRITICAL"
    titles = [f.title for f in agent.session.findings]
    assert titles == [
        "MCP low-level fuzzing: stdio_rce",
        "MCP low-level fuzzing: dns_rebind",
    ]
    fake.fuzz.assert_called_once_with("stdio://x", "stdio", confirm_scope=False)


def test_run_mst_confirm_scope_from_authorized_scope():
    agent = _agent()
    agent.session.authorized_scope = ["*.example.com"]
    fake = MagicMock()
    fake.available = True
    fake.fuzz.return_value = []
    with patch("cyberai.agents.mcp_scan.mst_bridge.MSTBridge", return_value=fake):
        agent._run_mst("https://api.example.com/mcp", "http", {"mst_fuzz": True})
    fake.fuzz.assert_called_once_with("https://api.example.com/mcp", "http", confirm_scope=True)


def test_run_mst_confirm_scope_from_context_flag():
    agent = _agent()
    fake = MagicMock()
    fake.available = True
    fake.fuzz.return_value = []
    with patch("cyberai.agents.mcp_scan.mst_bridge.MSTBridge", return_value=fake):
        agent._run_mst("https://x/mcp", "http", {"mst_fuzz": True, "confirm_scope": True})
    fake.fuzz.assert_called_once_with("https://x/mcp", "http", confirm_scope=True)

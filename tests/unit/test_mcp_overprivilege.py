"""Over-privilege and DNS-rebinding exposure detection for MCP tools.

Covers the pure scorers (capability mapping, over-privilege severity, exposure
assessment) and the agent wiring that turns risky tools and exposed endpoints
into session findings.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from cyberai.agents.mcp_scan.agent import MCPScanAgent
from cyberai.agents.mcp_scan.exposure import assess_exposure
from cyberai.agents.mcp_scan.overprivilege import (
    map_capability_surface,
    score_overprivilege,
)
from cyberai.core.scan_session import ScanSession, Severity

# ── fixtures ──────────────────────────────────────────────────────────

SHELL_FETCH = {
    "name": "shell_fetch",
    "description": "Run a shell command and POST the output to a url.",
    "inputSchema": {
        "type": "object",
        "properties": {"cmd": {"type": "string"}, "url": {"type": "string"}},
    },
}
FILE_UPLOADER = {
    "name": "file_uploader",
    "description": "Read a file and upload it over https.",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
}
SECRET_READER = {
    "name": "secret_reader",
    "description": "Read the api key from env.",
    "inputSchema": {"type": "object"},
}
PLAIN_READER = {
    "name": "plain_reader",
    "description": "Read a file and return its contents.",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
}
ADD_TOOL = {
    "name": "add",
    "description": "Add two integers and return the sum.",
    "inputSchema": {"type": "object", "properties": {"a": {"type": "integer"}}},
}

# ── capability mapping ────────────────────────────────────────────────


def test_exec_capability_detected():
    surface = map_capability_surface(SHELL_FETCH)
    assert "exec" in surface.capabilities
    assert "net" in surface.capabilities


def test_clean_tool_has_no_capabilities():
    surface = map_capability_surface(ADD_TOOL)
    assert surface.capabilities == []


# ── over-privilege scoring ────────────────────────────────────────────


def test_exec_plus_io_is_critical():
    scan = score_overprivilege(map_capability_surface(SHELL_FETCH))
    assert scan.severity == Severity.CRITICAL.value
    assert scan.is_overprivileged


def test_fs_read_plus_net_is_high():
    scan = score_overprivilege(map_capability_surface(FILE_UPLOADER))
    assert scan.severity == Severity.HIGH.value
    assert scan.is_overprivileged


def test_cred_without_egress_is_medium():
    scan = score_overprivilege(map_capability_surface(SECRET_READER))
    assert scan.severity == Severity.MEDIUM.value
    assert scan.is_overprivileged


def test_single_benign_capability_is_low_not_flagged():
    scan = score_overprivilege(map_capability_surface(PLAIN_READER))
    assert scan.severity == Severity.LOW.value
    assert not scan.is_overprivileged


def test_no_capability_is_info():
    scan = score_overprivilege(map_capability_surface(ADD_TOOL))
    assert scan.severity == Severity.INFO.value
    assert not scan.is_overprivileged


# ── exposure assessment ───────────────────────────────────────────────


def test_http_non_loopback_with_exec_is_critical():
    scan = assess_exposure("http://0.0.0.0:9090/mcp", "http", [SHELL_FETCH])
    assert scan.severity == Severity.CRITICAL.value
    assert scan.rebinding_risk
    assert "exec" in scan.dangerous_capabilities


def test_http_non_loopback_safe_is_high():
    scan = assess_exposure("http://0.0.0.0:9090/mcp", "http", [ADD_TOOL])
    assert scan.severity == Severity.HIGH.value
    assert scan.dangerous_capabilities == []


def test_http_loopback_safe_is_medium():
    scan = assess_exposure("http://127.0.0.1:9090/mcp", "http", [ADD_TOOL])
    assert scan.severity == Severity.MEDIUM.value
    assert scan.bind_host == "127.0.0.1"


def test_stdio_is_not_exposed():
    scan = assess_exposure("python -m server", "stdio", [SHELL_FETCH])
    assert scan.severity == Severity.INFO.value
    assert not scan.rebinding_risk
    assert scan.bind_host is None


# ── agent wiring ──────────────────────────────────────────────────────


def _agent() -> MCPScanAgent:
    agent = MCPScanAgent.__new__(MCPScanAgent)
    agent.AGENT_NAME = "mcp_scan"
    agent._log = MagicMock()
    agent.kb = MagicMock()
    agent.session = ScanSession(target="http://0.0.0.0:9090/mcp")
    return agent


def test_agent_records_overprivilege_findings():
    agent = _agent()
    tools = [SHELL_FETCH, FILE_UPLOADER, PLAIN_READER, ADD_TOOL]
    summary = agent._analyze_overprivilege("http://0.0.0.0:9090/mcp", tools)
    assert summary["scanned"] == 4
    # PLAIN_READER (LOW) and ADD_TOOL (INFO) are not flagged
    assert summary["overprivileged"] == 2
    assert len(agent.session.findings) == 2
    severities = {f.severity for f in agent.session.findings}
    assert Severity.CRITICAL in severities
    assert Severity.HIGH in severities
    crit = next(f for f in agent.session.findings if f.severity == Severity.CRITICAL)
    assert "shell_fetch" in crit.title
    assert crit.evidence


def test_agent_records_no_overprivilege_for_clean_tools():
    agent = _agent()
    summary = agent._analyze_overprivilege("http://0.0.0.0:9090/mcp", [ADD_TOOL, PLAIN_READER])
    assert summary["overprivileged"] == 0
    assert agent.session.findings == []


def test_agent_records_exposure_finding():
    agent = _agent()
    summary = agent._assess_exposure("http://0.0.0.0:9090/mcp", "http", [SHELL_FETCH])
    assert summary["exposed"]
    assert len(agent.session.findings) == 1
    finding = agent.session.findings[0]
    assert finding.severity == Severity.CRITICAL
    assert "rebinding" in finding.title.lower()
    assert finding.evidence


def test_agent_records_no_exposure_for_stdio():
    agent = _agent()
    summary = agent._assess_exposure("python -m server", "stdio", [SHELL_FETCH])
    assert not summary["exposed"]
    assert agent.session.findings == []

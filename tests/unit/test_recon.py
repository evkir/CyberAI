from cyberai.agents.recon.nmap_tool import _parse_ports


def test_parse_ports_empty():
    """Should return empty list for empty nmap output"""
    result = _parse_ports("")
    assert result == []


def test_parse_ports_open():
    """Should parse open ports from nmap XML"""
    xml = """
    <port protocol="tcp" portid="80">
    <state state="open" reason="syn-ack"/>
    <service name="http" product="nginx"/>
    </port>
    """
    ports = _parse_ports(xml)
    assert len(ports) == 1
    assert ports[0]["port"] == 80
    assert ports[0]["service"] == "http"


def test_parse_ports_filters_closed():
    """Should not include closed ports"""
    xml = """
    <port protocol="tcp" portid="22">
    <state state="closed" reason="reset"/>
    <service name="ssh"/>
    </port>
    """
    ports = _parse_ports(xml)
    assert ports == []


def test_recon_logs_nmap_failure_visibly(monkeypatch):
    """A nmap error must be surfaced as a FAILED log line, never masked
    as 'nmap_scan complete'."""
    from unittest.mock import MagicMock, patch
    from cyberai.agents.recon.agent import ReconAgent
    from cyberai.core.scan_session import ScanSession
    from cyberai.core.config import CyberAIConfig

    session = ScanSession(target="t.local")
    agent = ReconAgent(CyberAIConfig(), session, MagicMock(), MagicMock())

    logged: list[str] = []
    monkeypatch.setattr(agent, "_log", lambda msg, data=None: logged.append(msg))

    err_nmap = {"target": "t.local", "error": "nmap timeout after 180s", "ports": []}
    with (
        patch("cyberai.agents.recon.agent.run_nmap", return_value=err_nmap),
        patch("cyberai.agents.recon.agent.run_whois", return_value={}),
        patch("cyberai.agents.recon.agent.run_dns", return_value={}),
        patch("cyberai.agents.recon.agent.detect_subdomains", return_value={}),
        patch("cyberai.agents.recon.agent.detect_llm_endpoints", return_value={}),
    ):
        agent.run("t.local")

    assert any("nmap_scan FAILED" in m for m in logged)
    assert "nmap_scan complete" not in logged

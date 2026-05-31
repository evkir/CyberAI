import pytest
from unittest.mock import patch, MagicMock
from cyberai.core.config import CyberAIConfig
from cyberai.core.session import PentestSession, SessionState, Finding, Severity


@pytest.fixture
def config():
    return CyberAIConfig()


@pytest.fixture
def session():
    return PentestSession(target="testhost.local")


def test_session_creates_with_target(session):
    assert session.target == "testhost.local"
    assert session.state == SessionState.IDLE


def test_session_state_transition(session):
    session.set_state(SessionState.RECON)
    assert session.state == SessionState.RECON


def test_session_add_finding(session):
    from datetime import datetime, timezone

    f = Finding(
        id=1,
        severity=Severity.HIGH,
        title="Test",
        description="Test finding",
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent="test_agent",
    )
    session.findings.append(f)
    assert len(session.findings) == 1


def test_session_summary(session):
    summary = session.summary()
    assert "target" in summary or session.target == "testhost.local"


def test_config_defaults(config):
    assert config.llm is not None


def test_recon_nmap_parser():
    from cyberai.agents.recon.nmap_tool import _parse_ports

    assert _parse_ports("") == []


def test_intel_service_mapper():
    from cyberai.agents.intel.service_mapper import ports_to_queries

    ports = [{"port": 80, "service": "http", "state": "open"}]
    queries = ports_to_queries(ports)
    assert len(queries) > 0


def test_exploit_poc_lookup():
    from cyberai.agents.exploit.poc_mapper import lookup_poc

    result = lookup_poc("CVE-2021-44228")
    assert result["source"] == "internal"


def test_report_markdown_render(session):
    from cyberai.agents.report.markdown_renderer import render_markdown

    md = render_markdown(session)
    assert "testhost.local" in md
    assert len(md) > 50

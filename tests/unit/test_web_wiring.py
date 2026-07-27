"""
Wiring tests for web recon and web exploitation inside the agents.

The modules themselves are covered directly; what is untested is the seam --
whether the recon agent stores the surface where the exploit agent looks for
it, whether findings carry the severity and confidence the evidence justifies,
and whether the web path survives the absence of CVE data. That last one is
the whole reason the branch exists: the exploit agent used to return early
without ranked CVEs, and a refactor restoring that order would silently switch
web exploitation off with every module-level test still green.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cyberai.agents.exploit.agent import ExploitAgent
from cyberai.agents.recon.agent import ReconAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession, Severity

_SURFACE = {
    "base_url": "http://t.local",
    "reachable": True,
    "pages_fetched": 1,
    "endpoints": [
        {"url": "http://t.local/ping", "method": "GET", "params": ["host"], "source": "hint"},
    ],
}

_RECON_PATCHES = {
    "run_nmap": {"target": "t.local", "ports": []},
    "run_whois": {},
    "run_dns": {},
    "detect_subdomains": {},
    "detect_llm_endpoints": {},
}


def _recon_agent(**flags):
    session = ScanSession(target="t.local")
    return ReconAgent(CyberAIConfig(**flags), session, MagicMock(), MagicMock()), session


@pytest.fixture
def recon_patches():
    """Patch every recon tool so only the web-surface branch does work."""
    with (
        patch("cyberai.agents.recon.agent.run_nmap", return_value=_RECON_PATCHES["run_nmap"]),
        patch("cyberai.agents.recon.agent.run_whois", return_value={}),
        patch("cyberai.agents.recon.agent.run_dns", return_value={}),
        patch("cyberai.agents.recon.agent.detect_subdomains", return_value={}),
        patch("cyberai.agents.recon.agent.detect_llm_endpoints", return_value={}),
    ):
        yield


# ── recon side ────────────────────────────────────────────────────────


def test_recon_skips_web_surface_when_flag_is_off(recon_patches):
    agent, session = _recon_agent()
    with patch("cyberai.agents.recon.agent.discover_surface") as spy:
        agent.run("t.local")
    spy.assert_not_called()
    assert session.kb.get("recon.web_surface") in (None, {})


def test_recon_stores_surface_where_exploit_looks_for_it(recon_patches):
    agent, session = _recon_agent(use_web_recon=True)
    with patch("cyberai.agents.recon.agent.discover_surface", return_value=_SURFACE):
        agent.run("t.local")

    stored = session.kb.get("recon.web_surface")
    assert stored == _SURFACE, "exploit reads this exact key"


def test_recon_reports_the_surface_as_an_informational_finding(recon_patches):
    agent, session = _recon_agent(use_web_recon=True)
    with patch("cyberai.agents.recon.agent.discover_surface", return_value=_SURFACE):
        agent.run("t.local")

    surface_findings = [f for f in session.findings if "attack surface" in f.title.lower()]
    assert len(surface_findings) == 1
    assert surface_findings[0].severity is Severity.INFO
    assert any("host" in str(e) for e in surface_findings[0].evidence)


def test_recon_adds_no_finding_when_surface_is_empty(recon_patches):
    empty = {"base_url": "http://t.local", "reachable": True, "endpoints": []}
    agent, session = _recon_agent(use_web_recon=True)
    with patch("cyberai.agents.recon.agent.discover_surface", return_value=empty):
        agent.run("t.local")

    assert not [f for f in session.findings if "attack surface" in f.title.lower()]
    assert session.kb.get("recon.web_surface") == empty


# ── exploit side ──────────────────────────────────────────────────────


def _exploit_agent(**flags):
    session = ScanSession(target="t.local")
    agent = ExploitAgent(CyberAIConfig(**flags), session, MagicMock(), MagicMock())
    return agent, session


def _confirmed_report():
    from cyberai.agents.exploit.web_exploit import WebExploitReport, WebFinding, WebVulnClass

    return WebExploitReport(
        findings=[
            WebFinding(
                vuln_class=WebVulnClass.COMMAND_INJECTION,
                url="http://t.local/ping",
                method="GET",
                parameter="host",
                payload="127.0.0.1; echo $((6857*3))",
                proof="shell evaluated 6857*3 and returned 20571",
                evidence_snippet="PING 127.0.0.1\n20571\n",
            )
        ],
        endpoints_tested=1,
        requests_sent=1,
    )


def test_exploit_skips_web_path_when_flag_is_off():
    agent, session = _exploit_agent()
    session.kb.set("recon.web_surface", _SURFACE, agent="recon")
    with patch("cyberai.agents.exploit.agent.exploit_surface") as spy:
        agent.run("t.local")
    spy.assert_not_called()


def test_web_exploitation_runs_without_any_cve_data():
    """The reason the web branch sits before the CVE early-return."""
    agent, session = _exploit_agent(use_web_exploit=True)
    session.kb.set("recon.web_surface", _SURFACE, agent="recon")
    assert not session.kb.get("intel.ranked_cves")

    with patch(
        "cyberai.agents.exploit.agent.exploit_surface", return_value=_confirmed_report()
    ) as spy:
        result = agent.run("t.local")

    spy.assert_called_once()
    assert result["web_exploit"]["confirmed"] == 1


def test_confirmed_finding_carries_severity_and_full_confidence():
    agent, session = _exploit_agent(use_web_exploit=True)
    session.kb.set("recon.web_surface", _SURFACE, agent="recon")

    with patch("cyberai.agents.exploit.agent.exploit_surface", return_value=_confirmed_report()):
        agent.run("t.local")

    web = [f for f in session.findings if f.agent == "exploit"]
    assert len(web) == 1
    assert web[0].severity is Severity.CRITICAL
    assert web[0].confidence == 1.0
    assert "20571" in str(web[0].evidence)


def test_web_report_is_stored_in_the_knowledge_base():
    agent, session = _exploit_agent(use_web_exploit=True)
    session.kb.set("recon.web_surface", _SURFACE, agent="recon")

    with patch("cyberai.agents.exploit.agent.exploit_surface", return_value=_confirmed_report()):
        agent.run("t.local")

    stored = session.kb.get("exploit.web")
    assert stored["confirmed"] == 1
    assert stored["findings"][0]["parameter"] == "host"


def test_missing_surface_is_a_clean_no_op():
    agent, session = _exploit_agent(use_web_exploit=True)
    with patch("cyberai.agents.exploit.agent.exploit_surface") as spy:
        result = agent.run("t.local")

    spy.assert_not_called()
    assert result["web_exploit"]["confirmed"] == 0
    assert session.findings == []

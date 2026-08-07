"""Both run() paths that reach the model, including the ones that fail.

The early path is covered elsewhere; what is untested here is a CVE target
that also carries an HTTP surface, where two analyses have to coexist, and
the degradation promised by the try/except around each call.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cyberai.agents.exploit.agent import ExploitAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession

_SURFACE = {
    "base_url": "http://t.local",
    "reachable": True,
    "pages_fetched": 1,
    "endpoints": [
        {"url": "http://t.local/ping", "method": "GET", "params": ["host"], "source": "hint"},
    ],
}

_CVE = {
    "id": "CVE-2021-44228",
    "cve_id": "CVE-2021-44228",
    "cvss": 10.0,
    "severity": "CRITICAL",
    "description": "Log4Shell",
}


def _agent(**flags):
    session = ScanSession(target="t.local")
    agent = ExploitAgent(
        CyberAIConfig(use_web_exploit=True, **flags), session, MagicMock(), MagicMock()
    )
    return agent, session


def _report():
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


def test_a_cve_target_with_a_web_surface_keeps_both_analyses():
    """Neither reading may overwrite the other: they answer different questions."""
    agent, session = _agent()
    session.kb.set("intel.ranked_cves", [_CVE], agent="intel")
    session.kb.set("recon.web_surface", _SURFACE, agent="recon")
    agent.llm.call.side_effect = ["attack path narrative", "web surface narrative"]

    with patch("cyberai.agents.exploit.agent.exploit_surface", return_value=_report()):
        result = agent.run("t.local")

    analysis = result["ai_analysis"]
    assert "attack path narrative" in analysis
    assert "web surface narrative" in analysis
    assert "--- Web surface ---" in analysis
    names = [c.kwargs["agent_name"] for c in agent.llm.call.call_args_list]
    assert names == ["exploit", "exploit_web"]


def test_a_failing_web_analysis_leaves_the_attack_path_narrative_intact():
    """'degrade, never abort' is a promise the code makes; this holds it to it."""
    agent, session = _agent()
    session.kb.set("intel.ranked_cves", [_CVE], agent="intel")
    session.kb.set("recon.web_surface", _SURFACE, agent="recon")
    agent.llm.call.side_effect = ["attack path narrative", RuntimeError("ollama down")]

    with patch("cyberai.agents.exploit.agent.exploit_surface", return_value=_report()):
        result = agent.run("t.local")

    assert result["ai_analysis"] == "attack path narrative"


def test_a_failing_web_analysis_on_a_cveless_target_keeps_the_summary():
    """The early path degrades to its deterministic wording, and the phase lives."""
    agent, session = _agent()
    session.kb.set("recon.web_surface", _SURFACE, agent="recon")
    agent.llm.call.side_effect = RuntimeError("ollama down")

    with patch("cyberai.agents.exploit.agent.exploit_surface", return_value=_report()):
        result = agent.run("t.local")

    assert "HTTP surface was walked" in result["ai_analysis"]
    assert result["web_exploit"]["confirmed"] == 1

"""Mass-open port data must reach the user as exactly one honest finding.

Agent-level tests pass while the wiring is broken, so this drives the real
Orchestrator: recon writes recon.nmap, intel reads it, and the assertion is
made on the session the user actually gets back.
"""

from unittest.mock import patch

from cyberai.core.config import CyberAIConfig
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanPhase, Severity

_MASS_OPEN_NMAP = {
    "target": "10.0.0.1",
    "ports": [
        {"port": n, "protocol": "tcp", "service": "unknown", "state": "open"} for n in range(1, 782)
    ],
    "mass_open": True,
    "open_count": 781,
    "returncode": 0,
}


def _run(phases):
    orch = Orchestrator(config=CyberAIConfig(), phases=phases, dry_run=False)
    with (
        patch("cyberai.agents.recon.agent.run_nmap", return_value=_MASS_OPEN_NMAP),
        patch("cyberai.agents.recon.agent.run_whois", return_value={}),
        patch("cyberai.agents.recon.agent.run_dns", return_value={}),
        patch("cyberai.agents.recon.agent.enumerate_subdomains", return_value={}),
        patch("cyberai.agents.recon.agent.detect_llm_endpoints", return_value={}),
        patch("cyberai.agents.intel.agent.search_cves") as mock_search,
    ):
        session = orch.run("10.0.0.1")
    return session, mock_search


def _port_findings(session):
    return [f for f in session.findings if "port" in f.title.lower()]


def test_recon_only_states_port_data_is_unreliable():
    """With intel never running, the honest statement must still be made."""
    session, _ = _run([ScanPhase.RECON])

    findings = _port_findings(session)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "proxy/tunnel" in findings[0].title
    assert not any("Open ports on" in f.title for f in session.findings)


def test_full_pipeline_states_it_once_not_twice():
    """Recon and intel both used to publish it, so the report said the same
    thing twice on every flagged scan."""
    session, mock_search = _run([ScanPhase.RECON, ScanPhase.INTEL])

    findings = _port_findings(session)
    assert len(findings) == 1
    assert findings[0].agent == "recon"
    assert "proxy/tunnel" in findings[0].title
    mock_search.assert_not_called()

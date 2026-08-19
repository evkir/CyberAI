"""TLS findings must reach the reader with their CVE context attached.

TLSCVEMapper sat in the tree with no product caller for as long as it
existed. A test that hands the mapper a findings list directly would have
been green the whole time and proved nothing, so every test here drives
IntelAgent.run() and reads what the agent left in the knowledge base --
the same path the orchestrator takes.

The recon.tls value below is the shape TLSTool.run actually returns: a dict
carrying a findings list of severity/issue/detail dicts.

Mutation-checked. Removing the call, or moving it below the no-ports early
return, reddens the three positive arms; dropping the empty-findings guard
reddens only the negative one. The position of the call is load-bearing, not
decorative.
"""

from __future__ import annotations

from cyberai.agents.intel.agent import IntelAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession


def _tls_recon(*findings: dict) -> dict:
    return {
        "domain": "example.com",
        "tls_version": "TLSv1.0",
        "score": "BAD",
        "cert_expiry_days": 90,
        "findings": list(findings),
    }


_LEGACY_TLS = {
    "severity": "HIGH",
    "issue": "Obsolete protocol TLSv1.0 accepted",
    "detail": "Server negotiated TLSv1.0",
}

_UNMAPPED = {
    "severity": "LOW",
    "issue": "Certificate chain includes an extra intermediate",
    "detail": "No known CVE for this condition",
}


def test_tls_findings_reach_the_kb_with_their_cves():
    session = ScanSession(target="example.com")
    session.kb.set("recon.tls", _tls_recon(_LEGACY_TLS))
    session.kb.set("recon.nmap", {"ports": []})

    IntelAgent(CyberAIConfig(), session).run("example.com")

    enriched = session.kb.get("intel.tls_findings")
    assert enriched is not None, "the agent never wrote the enriched findings"
    assert "CVE-2011-3389" in enriched[0]["cves"]
    assert enriched[0]["issue"] == _LEGACY_TLS["issue"]


def test_tls_context_survives_a_port_scan_that_found_nothing():
    """The reason the call sits above the early return.

    An HTTPS host behind a filtered port scan yields no ports, and run()
    leaves immediately. The TLS data recon already collected must not leave
    with it.
    """
    session = ScanSession(target="example.com")
    session.kb.set("recon.tls", _tls_recon(_LEGACY_TLS))
    session.kb.set("recon.nmap", {"ports": []})

    result = IntelAgent(CyberAIConfig(), session).run("example.com")

    assert result["status"] == "skipped"
    assert session.kb.get("intel.tls_findings") is not None


def test_a_finding_with_no_known_cve_keeps_its_place():
    session = ScanSession(target="example.com")
    session.kb.set("recon.tls", _tls_recon(_UNMAPPED))
    session.kb.set("recon.nmap", {"ports": []})

    IntelAgent(CyberAIConfig(), session).run("example.com")

    enriched = session.kb.get("intel.tls_findings")
    assert len(enriched) == 1
    assert enriched[0]["cves"] == []
    assert enriched[0]["remediation"]


def test_no_tls_data_writes_no_key():
    """Negative arm: without this, an implementation that always writes an
    empty list would pass every test above."""
    session = ScanSession(target="example.com")
    session.kb.set("recon.nmap", {"ports": []})

    IntelAgent(CyberAIConfig(), session).run("example.com")

    assert session.kb.get("intel.tls_findings") is None

"""TLS problems must reach the document, not just the knowledge base.

The mapper had no caller; a previous fix gave it one and wrote the enriched
list to `intel.tls_findings`. That key had no reader either -- a grep for it
across cyberai/ returns the write and nothing else -- and the report renders
session.findings, not the KB. So an expired certificate, a negotiated
TLS 1.0 and RC4 in the cipher suite were probed, classified, matched to CVEs,
and then absent from the document a client reads. The same disease as the
one being cured, one level up.

tests/unit/test_intel_tls_context.py already pins the KB write and would
stay green through all of that, which is the point: it tests the producer.
This file tests the consumer.

The findings are raised through IntelAgent.run() rather than by calling the
private method, because the two early returns above it -- no ports, and a
mass-open port list -- are exactly the runs where a TLS-only target ends up,
and a fix that worked on the full path only would miss them both.
"""

from __future__ import annotations

from cyberai.agents.intel.agent import IntelAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession, Severity

_DEPRECATED_TLS = {
    "severity": "HIGH",
    "issue": "Deprecated TLS version",
    "detail": "Server negotiated TLSv1.0 — deprecated since RFC 8996",
}

_WEAK_CIPHER = {
    "severity": "MEDIUM",
    "issue": "Weak cipher suite",
    "detail": "RC4 in negotiated suite ECDHE-RSA-RC4-SHA",
}

_NO_CVE = {
    "severity": "LOW",
    "issue": "Certificate chain includes an extra intermediate",
    "detail": "No known CVE for this condition",
}


def _session(nmap: dict, *tls: dict) -> ScanSession:
    session = ScanSession(target="example.com")
    session.kb.set("recon.nmap", nmap)
    if tls:
        session.kb.set("recon.tls", {"domain": "example.com", "findings": list(tls)})
    return session


def test_a_tls_problem_becomes_a_finding_with_its_cves() -> None:
    session = _session({"ports": []}, _DEPRECATED_TLS)
    IntelAgent(CyberAIConfig(), session).run("example.com")

    tls = [f for f in session.findings if f.title == _DEPRECATED_TLS["issue"]]
    assert len(tls) == 1
    assert tls[0].severity is Severity.HIGH
    assert "CVE-2011-3389" in tls[0].cve_ids


def test_severity_comes_from_the_tls_classifier() -> None:
    """Not re-decided here: it already knows deprecated beats weak cipher."""
    session = _session({"ports": []}, _DEPRECATED_TLS, _WEAK_CIPHER)
    IntelAgent(CyberAIConfig(), session).run("example.com")

    by_title = {f.title: f.severity for f in session.findings}
    assert by_title[_DEPRECATED_TLS["issue"]] is Severity.HIGH
    assert by_title[_WEAK_CIPHER["issue"]] is Severity.MEDIUM


def test_a_mass_open_scan_still_reports_its_tls_problems() -> None:
    """The run where this matters most.

    A fake-ip proxy answers every port, so the CVE lookup is skipped and the
    port list is noise -- but the TLS handshake was real and what it revealed
    is still true.
    """
    session = _session(
        {"ports": [{"port": 443, "service": "https"}], "mass_open": True, "open_count": 900},
        _DEPRECATED_TLS,
    )
    result = IntelAgent(CyberAIConfig(), session).run("example.com")

    assert result["reason"] == "mass_open"
    assert any(f.title == _DEPRECATED_TLS["issue"] for f in session.findings)


def test_a_condition_with_no_cve_still_reaches_the_report() -> None:
    """An unmapped condition is a configuration problem, not a non-problem."""
    session = _session({"ports": []}, _NO_CVE)
    IntelAgent(CyberAIConfig(), session).run("example.com")

    tls = [f for f in session.findings if f.title == _NO_CVE["issue"]]
    assert len(tls) == 1
    assert tls[0].cve_ids == []
    assert any("No CVE maps" in e for e in tls[0].evidence)


def test_the_remediation_travels_with_the_finding() -> None:
    session = _session({"ports": []}, _DEPRECATED_TLS)
    IntelAgent(CyberAIConfig(), session).run("example.com")

    tls = next(f for f in session.findings if f.title == _DEPRECATED_TLS["issue"])
    assert any("Remediation:" in e for e in tls.evidence)


def test_a_target_with_no_tls_data_raises_nothing() -> None:
    """Negative arm: an implementation that always adds a finding fails here."""
    session = _session({"ports": []})
    IntelAgent(CyberAIConfig(), session).run("example.com")

    assert session.findings == []

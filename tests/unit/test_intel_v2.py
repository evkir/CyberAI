"""
Tests for IntelAgent CVE scoring (formerly IntelAgentV2) and _normalize.

IntelAgentV2 is an alias for IntelAgent with
score_cves=True built in. These tests use the real BaseAgent contract.
"""

from __future__ import annotations

from unittest.mock import patch


from cyberai.agents.intel.agent import IntelAgent, IntelAgentV2, _normalize
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession


# ── normalize helper ─────────────────────────────────────────────────


def test_normalize_standard_nvd_format():
    cve = {
        "id": "CVE-2024-1234",
        "cvss": {"score": 9.8, "vector": "AV:N"},
        "description": "Remote code execution",
        "published": "2024-01-01T00:00:00+00:00",
    }
    n = _normalize(cve)
    assert n["cve_id"] == "CVE-2024-1234"
    assert n["cvss"] == 9.8
    assert n["published_date"] == "2024-01-01T00:00:00+00:00"


def test_normalize_flat_cvss_format():
    n = _normalize({"cve_id": "CVE-2023-9999", "cvss": 7.5})
    assert n["cvss"] == 7.5


def test_normalize_missing_fields():
    n = _normalize({})
    assert n["cve_id"] == ""
    assert n["cvss"] == 0.0
    assert n["poc_likely"] is False


def test_normalize_description_truncated():
    n = _normalize({"id": "CVE-X", "description": "A" * 200})
    assert len(n["description_short"]) == 120


# ── IntelAgent scoring ────────────────────────────────────────────────


SAMPLE_CVES = [
    {
        "id": "CVE-2024-0001",
        "cvss": {"score": 9.8},
        "description": "Critical HTTP server RCE",
        "published": "2024-11-01T00:00:00+00:00",
        "poc_likely": True,
    },
    {
        "id": "CVE-2023-0002",
        "cvss": {"score": 5.0},
        "description": "Medium HTTP config issue",
        "published": "2023-06-01T00:00:00+00:00",
    },
]


def _agent_with_recon(cves):
    """Build a real IntelAgent with recon data in the KB and mocked NVD."""
    session = ScanSession(target="10.0.0.1")
    session.kb.set("recon.nmap", {"ports": [{"port": 80, "service": "http"}]})
    agent = IntelAgent(CyberAIConfig(), session, score_cves=True)
    return agent, session


def test_v2_alias_is_intel_agent():
    assert IntelAgentV2 is IntelAgent


def test_v2_skipped_when_no_ports():
    session = ScanSession(target="10.0.0.1")
    session.kb.set("recon.nmap", {"ports": []})
    agent = IntelAgent(CyberAIConfig(), session)
    result = agent.run("10.0.0.1")
    assert result["status"] == "skipped"


def test_v2_returns_ranked_cves():
    agent, _ = _agent_with_recon(SAMPLE_CVES)
    with patch("cyberai.agents.intel.agent.search_cves", return_value={"cves": SAMPLE_CVES}):
        result = agent.run("10.0.0.1")
    assert "ranked_cves" in result
    assert len(result["ranked_cves"]) >= 1


def test_v2_ranked_sorted_desc():
    agent, _ = _agent_with_recon(SAMPLE_CVES)
    with patch("cyberai.agents.intel.agent.search_cves", return_value={"cves": SAMPLE_CVES}):
        result = agent.run("10.0.0.1")
    scores = [r["composite_score"] for r in result["ranked_cves"]]
    assert scores == sorted(scores, reverse=True)


def test_v2_risk_summary_present():
    agent, _ = _agent_with_recon(SAMPLE_CVES)
    with patch("cyberai.agents.intel.agent.search_cves", return_value={"cves": SAMPLE_CVES}):
        result = agent.run("10.0.0.1")
    assert "risk_summary" in result
    assert result["risk_summary"]["total"] >= 1


def test_v2_stores_in_kb():
    agent, session = _agent_with_recon(SAMPLE_CVES)
    with patch("cyberai.agents.intel.agent.search_cves", return_value={"cves": SAMPLE_CVES}):
        agent.run("10.0.0.1")
    assert "intel.ranked_cves" in session.kb
    assert "intel.risk_summary" in session.kb


def test_normalize_propagates_cvss_vector():
    """CVSS vector must survive normalization so the exploit agent renders
    real Vector/Complexity instead of Unknown (regression: dropped vector)."""
    from cyberai.agents.exploit.cvss_analyzer import analyze_attack_vector

    cve = {"id": "CVE-2024-1", "cvss": {"score": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N"}}
    n = _normalize(cve)
    assert n["cvss_vector"] == "AV:N/AC:L/PR:N/UI:N"

    av = analyze_attack_vector(n)
    assert av["attack_vector"] == "Network"
    assert av["attack_complexity"] == "Low"


def test_normalize_flat_cvss_has_empty_vector():
    """Flat/legacy CVE (cvss as float) must not crash and yields empty vector."""
    n = _normalize({"cve_id": "CVE-2023-9999", "cvss": 7.5})
    assert n["cvss_vector"] == ""


def test_findings_filter_cross_product_fp():
    """A sendmail CVE returned via keyword collision must not surface as a
    finding on an OpenSSH host, while the genuine OpenSSH CVE still does."""
    session = ScanSession(target="10.0.0.1")
    session.kb.set(
        "recon.nmap",
        {
            "ports": [
                {
                    "port": 22,
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "6.6.1p1",
                }
            ]
        },
    )
    agent = IntelAgent(CyberAIConfig(), session)
    cves = [
        {
            "id": "CVE-REL",
            "cvss": {"score": 9.8},
            "description": "OpenSSH remote code execution flaw",
        },
        {
            "id": "CVE-FP",
            "cvss": {"score": 10.0},
            "description": "Sendmail DEBUG command allows remote command execution",
        },
    ]
    with (
        patch("cyberai.agents.intel.agent.search_cves", return_value={"cves": cves}),
        patch("cyberai.agents.intel.agent.get_epss_scores", return_value={}),
    ):
        agent.run("10.0.0.1")

    titles = [f.title for f in session.findings]
    assert "CVE-REL" in titles
    assert "CVE-FP" not in titles


def test_ranked_cves_filter_cross_product_fp():
    """A sendmail CVE returned via keyword collision must not reach
    ranked_cves/attack paths on an OpenSSH host, while the genuine
    OpenSSH CVE still ranks (regression: FP leaked past findings guard
    into risk_prioritizer scoring)."""
    session = ScanSession(target="10.0.0.1")
    session.kb.set(
        "recon.nmap",
        {
            "ports": [
                {
                    "port": 22,
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "6.6.1p1",
                }
            ]
        },
    )
    agent = IntelAgent(CyberAIConfig(), session, score_cves=True)
    cves = [
        {
            "id": "CVE-REL",
            "cvss": {"score": 9.8},
            "description": "OpenSSH remote code execution flaw",
        },
        {
            "id": "CVE-FP",
            "cvss": {"score": 10.0},
            "description": "Sendmail DEBUG command allows remote command execution",
        },
    ]
    with (
        patch("cyberai.agents.intel.agent.search_cves", return_value={"cves": cves}),
        patch("cyberai.agents.intel.agent.get_epss_scores", return_value={}),
    ):
        result = agent.run("10.0.0.1")

    ranked_ids = [r["cve_id"] for r in result["ranked_cves"]]
    assert "CVE-REL" in ranked_ids
    assert "CVE-FP" not in ranked_ids
    kb_ids = [r["cve_id"] for r in session.kb.get("intel.ranked_cves")]
    assert "CVE-FP" not in kb_ids

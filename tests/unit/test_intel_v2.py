"""
Tests for IntelAgent CVE scoring (formerly IntelAgentV2) and _normalize.

Day 6 of STANDOFF: IntelAgentV2 is now an alias for IntelAgent with
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
        "description": "Critical RCE",
        "published": "2024-11-01T00:00:00+00:00",
        "poc_likely": True,
    },
    {
        "id": "CVE-2023-0002",
        "cvss": {"score": 5.0},
        "description": "Medium issue",
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

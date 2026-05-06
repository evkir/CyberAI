import pytest
from unittest.mock import patch, MagicMock
from cyberai.agents.intel.agent import IntelAgentV2, _normalize


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
    cve = {"cve_id": "CVE-2023-9999", "cvss": 7.5}
    n = _normalize(cve)
    assert n["cvss"] == 7.5


def test_normalize_missing_fields():
    n = _normalize({})
    assert n["cve_id"] == ""
    assert n["cvss"] == 0.0
    assert n["poc_likely"] is False


def test_normalize_description_truncated():
    cve = {"id": "CVE-X", "description": "A" * 200}
    n = _normalize(cve)
    assert len(n["description_short"]) == 120


# ── IntelAgentV2 ─────────────────────────────────────────────────────

def _make_agent(cves=None):
    """Build IntelAgentV2 with mocked session."""
    session = MagicMock()
    session.target = "10.0.0.1"
    session.knowledge_base = {
        "recon.nmap": {"ports": [{"port": 80, "service": "http"}]},
        "intel.cves": cves or [],
    }
    agent = IntelAgentV2.__new__(IntelAgentV2)
    agent.session         = session
    agent.min_score       = 0.0
    agent.top_n           = 10
    agent._iterations     = 0
    agent._max_iterations = 50
    agent.tools           = {}
    agent.audit           = MagicMock()
    agent.AGENT_NAME      = "intel"
    return agent


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


def test_v2_skipped_when_no_ports():
    agent = _make_agent()
    agent.session.knowledge_base["recon.nmap"] = {"ports": []}
    with patch("cyberai.agents.intel.agent.IntelAgent.run",
                   return_value={"status": "skipped", "reason": "no ports"}):
            result = agent.run({})
    assert result["status"] == "skipped"


def test_v2_returns_ranked_cves():
    agent = _make_agent(cves=SAMPLE_CVES)
    with patch("cyberai.agents.intel.agent.IntelAgent.run",
                   return_value={"status": "done", "cves_found": 2}):
            result = agent.run({})
    assert "ranked_cves" in result
    assert len(result["ranked_cves"]) == 2


def test_v2_ranked_sorted_desc():
    agent = _make_agent(cves=SAMPLE_CVES)
    with patch("cyberai.agents.intel.agent.IntelAgent.run",
                   return_value={"status": "done"}):
            result = agent.run({})
    scores = [r["composite_score"] for r in result["ranked_cves"]]
    assert scores == sorted(scores, reverse=True)


def test_v2_risk_summary_present():
    agent = _make_agent(cves=SAMPLE_CVES)
    with patch("cyberai.agents.intel.agent.IntelAgent.run",
                   return_value={"status": "done"}):
            result = agent.run({})
    assert result["risk_summary"]["total"] == 2
    assert result["risk_summary"]["top_cve"] == "CVE-2024-0001"


def test_v2_stores_in_kb():
    agent = _make_agent(cves=SAMPLE_CVES)
    with patch("cyberai.agents.intel.agent.IntelAgent.run",
                   return_value={"status": "done"}):
            agent.run({})
    assert "intel.ranked_cves" in agent.session.knowledge_base
    assert "intel.risk_summary" in agent.session.knowledge_base

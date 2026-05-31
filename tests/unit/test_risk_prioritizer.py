import pytest
from cyberai.agents.intel.risk_prioritizer import prioritize, group_by_tier, summarize

CVES = [
    {
        "cve_id": "CVE-2024-0001",
        "cvss": 9.8,
        "poc_likely": True,
        "published_date": "2024-11-01T00:00:00+00:00",
        "epss": 0.9,
    },
    {
        "cve_id": "CVE-2023-0002",
        "cvss": 6.5,
        "poc_likely": False,
        "published_date": "2023-06-01T00:00:00+00:00",
        "epss": 0.1,
    },
    {
        "cve_id": "CVE-2018-0003",
        "cvss": 3.0,
        "poc_likely": False,
        "published_date": "2018-01-01T00:00:00+00:00",
        "epss": 0.001,
    },
]


def test_prioritize_returns_list():
    result = prioritize(CVES)
    assert isinstance(result, list)
    assert len(result) == 3


def test_prioritize_sorted_desc():
    result = prioritize(CVES)
    scores = [r["composite_score"] for r in result]
    assert scores == sorted(scores, reverse=True)


def test_prioritize_min_score_filter():
    result = prioritize(CVES, min_score=0.5)
    assert all(r["composite_score"] >= 0.5 for r in result)


def test_prioritize_top_n():
    result = prioritize(CVES, top_n=1)
    assert len(result) == 1
    assert result[0]["cve_id"] == "CVE-2024-0001"


def test_prioritize_tier_filter():
    result = prioritize(CVES, tiers=["CRITICAL", "HIGH"])
    for r in result:
        assert r["severity_tier"] in ("CRITICAL", "HIGH")


def test_group_by_tier_keys():
    groups = group_by_tier(CVES)
    assert "CRITICAL" in groups
    assert "HIGH" in groups
    assert "LOW" in groups


def test_summarize_structure():
    s = summarize(CVES)
    assert s["total"] == 3
    assert "tiers" in s
    assert "top_cve" in s
    assert "avg_score" in s


def test_summarize_empty():
    s = summarize([])
    assert s["total"] == 0
    assert s["top_cve"] is None


def test_summarize_top_cve():
    s = summarize(CVES)
    assert s["top_cve"] == "CVE-2024-0001"

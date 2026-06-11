import pytest
from cyberai.agents.intel.cve_scorer import (
    score_cve,
    score_all,
    CVEScore,
    EXPLOIT_WEIGHT,
    EPSS_WEIGHT,
)

CRITICAL_CVE = {
    "cve_id": "CVE-2024-1111",
    "cvss": 9.8,
    "poc_likely": True,
    "metasploit": True,
    "exploited_in_wild": True,
    "published_date": "2024-12-01T00:00:00+00:00",
    "epss": 0.95,
}

LOW_CVE = {
    "cve_id": "CVE-2020-9999",
    "cvss": 3.1,
    "poc_likely": False,
    "published_date": "2018-01-01T00:00:00+00:00",
    "epss": 0.001,
}


def test_score_returns_cve_score():
    result = score_cve(CRITICAL_CVE)
    assert isinstance(result, CVEScore)


def test_critical_cve_high_score():
    s = score_cve(CRITICAL_CVE)
    assert s.composite_score >= 0.75
    assert s.severity_tier == "CRITICAL"


def test_low_cve_low_score():
    s = score_cve(LOW_CVE)
    assert s.composite_score < 0.35


def test_score_capped_at_1():
    s = score_cve(CRITICAL_CVE)
    assert s.composite_score <= 1.0


def test_no_cvss_gives_zero_cvss_component():
    s = score_cve({"cve_id": "CVE-X", "cvss": 0})
    assert s.cvss == 0.0


def test_score_all_sorted_desc():
    scores = score_all([LOW_CVE, CRITICAL_CVE])
    assert scores[0].cve_id == "CVE-2024-1111"
    assert scores[1].cve_id == "CVE-2020-9999"


def test_to_dict_keys():
    d = score_cve(CRITICAL_CVE).to_dict()
    for key in [
        "cve_id",
        "cvss",
        "composite_score",
        "severity_tier",
        "exploit_bonus",
        "recency_bonus",
        "epss_bonus",
        "reasoning",
    ]:
        assert key in d


def test_reasoning_contains_cvss():
    s = score_cve(CRITICAL_CVE)
    assert "CVSS=" in s.reasoning


def test_exploit_bonus_all_signals():
    s = score_cve(CRITICAL_CVE)
    assert s.exploit_bonus == EXPLOIT_WEIGHT


def test_epss_bonus_high():
    """High EPSS (>0.5) triggers the day-11 multiplier boost and clamps
    to the full EPSS_WEIGHT — strongest possible EPSS signal."""
    s = score_cve(CRITICAL_CVE)
    assert s.epss_bonus == pytest.approx(EPSS_WEIGHT, abs=1e-6)


def test_epss_bonus_low_is_linear():
    """Low EPSS (<= 0.5) is linear in weight — no boost."""
    cve = {"cve_id": "CVE-x", "cvss": 5.0, "epss": 0.10}
    s = score_cve(cve)
    assert s.epss_bonus == pytest.approx(0.10 * EPSS_WEIGHT, abs=1e-6)


def test_epss_bonus_zero():
    """Missing/zero EPSS contributes nothing."""
    cve = {"cve_id": "CVE-y", "cvss": 5.0, "epss": 0.0}
    s = score_cve(cve)
    assert s.epss_bonus == 0.0

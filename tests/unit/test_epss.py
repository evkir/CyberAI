"""Unit tests for EPSS client + prioritizer integration (day 11).

Uses a captured api.first.org response (epss_log4shell.json) to drive
deterministic tests without hitting the network.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from cyberai.agents.intel import epss_client
from cyberai.agents.intel.epss_client import get_epss_scores
from cyberai.agents.intel.risk_prioritizer import prioritize


FIXTURE = Path(__file__).parent.parent / "fixtures" / "epss_log4shell.json"


@pytest.fixture
def epss_response() -> dict:
    return json.loads(FIXTURE.read_text())


@pytest.fixture(autouse=True)
def _clean_epss_cache():
    """Each test starts with an empty cache."""
    epss_client._epss_cache.clear()
    yield
    epss_client._epss_cache.clear()


def _mock_resp(payload: dict) -> MagicMock:
    m = MagicMock()
    m.json.return_value = payload
    m.raise_for_status.return_value = None
    return m


# ── EPSS client ───────────────────────────────────────────────────────


def test_client_empty_input():
    assert get_epss_scores([]) == {}


def test_client_parses_fixture(epss_response):
    """Real-world api.first.org response shape must parse correctly."""
    with patch.object(epss_client.httpx, "get", return_value=_mock_resp(epss_response)):
        scores = get_epss_scores(["CVE-2021-44228", "CVE-2019-0708", "CVE-2020-1234"])
    assert scores["CVE-2021-44228"] == pytest.approx(0.97539)
    assert scores["CVE-2019-0708"] == pytest.approx(0.94120)
    assert scores["CVE-2020-1234"] == pytest.approx(0.00045)


def test_client_caches_after_fetch(epss_response):
    """Second call for the same CVE must come from cache, not HTTP."""
    with patch.object(epss_client.httpx, "get", return_value=_mock_resp(epss_response)) as m:
        get_epss_scores(["CVE-2021-44228"])
        get_epss_scores(["CVE-2021-44228"])
    assert m.call_count == 1


def test_client_missing_cve_defaults_to_zero(epss_response):
    """CVEs not returned by the API silently default to 0.0."""
    with patch.object(epss_client.httpx, "get", return_value=_mock_resp(epss_response)):
        scores = get_epss_scores(["CVE-2021-44228", "CVE-9999-9999"])
    assert scores["CVE-9999-9999"] == 0.0


def test_client_http_failure_silent_zero():
    """HTTP errors must degrade to 0.0, not crash the pipeline."""
    with patch.object(epss_client.httpx, "get", side_effect=Exception("boom")):
        scores = get_epss_scores(["CVE-2021-44228"])
    assert scores == {"CVE-2021-44228": 0.0}


# ── prioritizer with EPSS enrichment ──────────────────────────────────


def test_log4shell_tops_priority_thanks_to_epss():
    """Log4Shell (EPSS 0.97) must outrank an older high-CVSS CVE with
    no exploitation activity. This is the whole point of EPSS."""
    cves = [
        {
            "cve_id": "CVE-2019-OLD",
            "cvss": 9.0,
            "epss": 0.02,
            "description_short": "old high CVSS, no exploitation",
            "published_date": "2019-01-01T00:00:00",
        },
        {
            "cve_id": "CVE-2021-44228",
            "cvss": 10.0,
            "epss": 0.974,
            "description_short": "Log4Shell",
            "metasploit": True,
            "exploited_in_wild": True,
            "published_date": "2021-12-10T00:00:00",
        },
    ]
    ranked = prioritize(cves)
    assert ranked[0]["cve_id"] == "CVE-2021-44228"
    assert ranked[0]["composite_score"] > ranked[1]["composite_score"]


def test_high_epss_emoji_in_reasoning():
    """🔥 marker appears for EPSS > 0.5 (day-11 visual signal)."""
    cves = [
        {
            "cve_id": "CVE-2021-44228",
            "cvss": 10.0,
            "epss": 0.974,
            "published_date": "2021-12-10T00:00:00",
        }
    ]
    ranked = prioritize(cves)
    assert "\U0001f525" in ranked[0]["reasoning"]

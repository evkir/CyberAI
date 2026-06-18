"""
Real-world e2e tests against the NVD API.

Skipped if NVD_API_KEY is not set in env — unauthenticated NVD requests
have a 5/30s rate limit that's too tight for CI runs.
"""

import os

import pytest

from cyberai.agents.intel.nvd_client import get_cve, search_cves

pytestmark = [pytest.mark.slow, pytest.mark.network]

skip_without_key = pytest.mark.skipif(
    not os.getenv("NVD_API_KEY"),
    reason="NVD_API_KEY not set",
)


# NVD over the live network occasionally times out / rate-limits. A transient
# transport failure is not a code regression, so skip rather than fail.
_TRANSIENT = ("timed out", "timeout", "connection", "temporarily", "429", "503")


def _skip_on_transient(result):
    err = str(result.get("error", "")).lower()
    if any(m in err for m in _TRANSIENT):
        pytest.skip(f"NVD transient failure: {result.get('error')}")


@skip_without_key
def test_real_nvd_keyword_search_returns_high_severity_cve():
    """
    'openssh 7.4' is a well-known vulnerable version family — NVD must return
    multiple CVEs, at least one with CVSS >= 7.0.
    """
    result = search_cves("openssh 7.4", max_results=10)

    _skip_on_transient(result)
    assert "error" not in result, f"NVD failed: {result.get('error')}"
    cves = result.get("cves", [])
    assert len(cves) > 0, "expected at least one CVE for openssh 7.4"

    high_severity = [
        c
        for c in cves
        if isinstance(c.get("cvss", {}).get("score"), (int, float)) and c["cvss"]["score"] >= 7.0
    ]
    assert high_severity, f"no CVE with CVSS>=7.0 in {[c.get('id') for c in cves]}"


@skip_without_key
def test_real_nvd_get_specific_cve_log4shell():
    """
    CVE-2021-44228 (Log4Shell) — CVSS 10.0, well-known. Sanity-checks the
    single-CVE fetch path and CVSS parsing.
    """
    cve = get_cve("CVE-2021-44228")

    _skip_on_transient(cve)
    assert "error" not in cve, f"NVD failed: {cve.get('error')}"
    assert cve.get("id") == "CVE-2021-44228"
    assert cve.get("cvss", {}).get("score") == 10.0

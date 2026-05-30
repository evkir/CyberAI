import os

import httpx
from typing import Dict, Any, List, Optional

from cyberai.core.rate_limiter import get_nvd_limiter
from cyberai.utils.backoff import exponential_backoff

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """Shared NVD call: apiKey header + rate limiter + retry on 429/503."""
    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}

    def _do_call() -> Dict[str, Any]:
        get_nvd_limiter(api_key).acquire()
        response = httpx.get(NVD_BASE, params=params, headers=headers, timeout=30)
        if response.status_code in (429, 503):
            raise httpx.HTTPStatusError(
                f"NVD transient {response.status_code}",
                request=response.request, response=response,
            )
        response.raise_for_status()
        return response.json()

    return exponential_backoff(
        _do_call,
        max_retries=3,
        base_delay=2.0,
        max_delay=30.0,
        exceptions=(httpx.HTTPStatusError, httpx.TimeoutException),
    )


def search_cves(
    keyword: str,
    max_results: int = 10,
    severity: Optional[str] = None
) -> Dict[str, Any]:
    """
    Search NVD API 2.0 for CVEs matching keyword.
    severity: CRITICAL | HIGH | MEDIUM | LOW
    """
    params: Dict[str, Any] = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    if severity:
        params["cvssV3Severity"] = severity

    try:
        data = _nvd_request(params)
        return {
            "keyword": keyword,
            "total": data.get("totalResults", 0),
            "cves": _parse_cves(data.get("vulnerabilities", [])),
        }
    except httpx.TimeoutException:
        return {"keyword": keyword, "error": "NVD API timeout"}
    except Exception as e:
        return {"keyword": keyword, "error": str(e)}

def get_cve(cve_id: str) -> Dict[str, Any]:
    """Fetch single CVE by ID e.g. CVE-2024-1234"""
    try:
        data = _nvd_request({"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"cve_id": cve_id, "error": "not found"}
        return _parse_cves(vulns)[0]
    except Exception as e:
        return {"cve_id": cve_id, "error": str(e)}

def _parse_cves(vulns: List[Dict]) -> List[Dict]:
    """Extract key fields from NVD vulnerability objects"""
    results = []
    for v in vulns:
        cve = v.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = {}

        # Try CVSSv3.1 first, then v3.0
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                cvss = {
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString"),
                }
                break

        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description"
        )

        results.append({
            "id": cve.get("id"),
            "description": desc[:300],
            "cvss": cvss,
            "published": cve.get("published", ""),
            "references": [
                r["url"] for r in cve.get("references", [])[:3]
            ],
        })
    return results

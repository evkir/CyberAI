import asyncio
import os
from typing import Any, Dict, List, Optional

import httpx

from cyberai.core.rate_limiter import get_nvd_limiter
from cyberai.utils.backoff import exponential_backoff

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """Shared NVD call: apiKey header + rate limiter + retry on 429/503."""
    api_key = (os.getenv("NVD_API_KEY") or "").strip() or None
    headers = {"apiKey": api_key} if api_key else {}

    def _do_call() -> Dict[str, Any]:
        get_nvd_limiter(api_key).acquire()
        response = httpx.get(NVD_BASE, params=params, headers=headers, timeout=30)
        if response.status_code in (429, 503):
            raise httpx.HTTPStatusError(
                f"NVD transient {response.status_code}",
                request=response.request,
                response=response,
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
    keyword: str, max_results: int = 10, severity: Optional[str] = None
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


def _parse_cpe_configs(configs: List[Dict]) -> List[Dict]:
    """Flatten NVD ``configurations`` into a list of applicable-version rules.

    Each vulnerable ``cpeMatch`` becomes a dict carrying the CPE product plus
    whatever version constraint NVD supplies — either a concrete pinned
    version (from the CPE 2.3 ``criteria`` string, e.g. ``openssh:2.1``) or a
    range via ``versionStart*/versionEnd*``. Downstream this lets the intel
    layer drop CVEs whose ranges do not cover the detected service version,
    instead of matching purely on product keyword. Placeholder CVEs with no
    configurations yield an empty list (version-unconfirmable).

    CPE 2.3 layout: ``cpe:2.3:part:vendor:product:version:...`` — product is
    field 4, version is field 5.
    """
    rules: List[Dict] = []
    for cfg in configs or []:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                fields = match.get("criteria", "").split(":")
                rules.append(
                    {
                        "vendor": fields[3] if len(fields) > 3 else "",
                        "product": fields[4] if len(fields) > 4 else "",
                        "version": fields[5] if len(fields) > 5 else "*",
                        "version_start_including": match.get("versionStartIncluding"),
                        "version_start_excluding": match.get("versionStartExcluding"),
                        "version_end_including": match.get("versionEndIncluding"),
                        "version_end_excluding": match.get("versionEndExcluding"),
                    }
                )
    return rules


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

        # Fall back to CVSS v2 for legacy CVEs that have no v3 metrics in NVD
        # (common for pre-2015 CVEs on old services). In v2 the severity lives
        # on the metric entry, not inside cvssData.
        if not cvss and metrics.get("cvssMetricV2"):
            entry = metrics["cvssMetricV2"][0]
            cvss_data = entry.get("cvssData", {})
            cvss = {
                "score": cvss_data.get("baseScore"),
                "severity": entry.get("baseSeverity"),
                "vector": cvss_data.get("vectorString"),
            }

        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description",
        )

        results.append(
            {
                "id": cve.get("id"),
                "description": desc[:300],
                "cvss": cvss,
                "published": cve.get("published", ""),
                "references": [r["url"] for r in cve.get("references", [])[:3]],
                "cpe": _parse_cpe_configs(cve.get("configurations", [])),
            }
        )
    return results


async def _nvd_request_async(client: "httpx.AsyncClient", params: Dict[str, Any]) -> Dict[str, Any]:
    """Async equivalent of _nvd_request: shared rate-limiter + retry on 429/503."""
    api_key = (os.getenv("NVD_API_KEY") or "").strip() or None
    headers = {"apiKey": api_key} if api_key else {}
    limiter = get_nvd_limiter(api_key)

    async def _do_call() -> Dict[str, Any]:
        # Rate-limiter is sync (token bucket); offload its blocking wait to a
        # thread so the event loop stays responsive while we hold our slot.
        await asyncio.to_thread(limiter.acquire)
        response = await client.get(NVD_BASE, params=params, headers=headers, timeout=30)
        if response.status_code in (429, 503):
            raise httpx.HTTPStatusError(
                f"NVD transient {response.status_code}",
                request=response.request,
                response=response,
            )
        response.raise_for_status()
        return response.json()

    # Simple async retry — mirrors exponential_backoff for the 3 cases below.
    delay = 2.0
    last_exc: Optional[Exception] = None
    for _ in range(3):
        try:
            return await _do_call()
        except (httpx.HTTPStatusError, httpx.TimeoutException) as exc:
            last_exc = exc
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)
    raise last_exc if last_exc else RuntimeError("NVD request failed")


async def search_cves_async(
    client: "httpx.AsyncClient",
    keyword: str,
    max_results: int = 10,
    severity: Optional[str] = None,
) -> Dict[str, Any]:
    """Async equivalent of search_cves. Same return shape."""
    params: Dict[str, Any] = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    if severity:
        params["cvssV3Severity"] = severity
    try:
        data = await _nvd_request_async(client, params)
        return {
            "keyword": keyword,
            "total": data.get("totalResults", 0),
            "cves": _parse_cves(data.get("vulnerabilities", [])),
        }
    except httpx.TimeoutException:
        return {"keyword": keyword, "error": "NVD API timeout"}
    except Exception as e:
        return {"keyword": keyword, "error": str(e)}


async def search_cves_batch(
    keywords: List[str],
    max_results: int = 10,
    severity: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Run many keyword searches concurrently against NVD.

    Concurrency is gated by the shared NVD rate limiter (50/30s with API key,
    5/30s without) — see get_nvd_limiter. Returns results in the same order
    as the input keywords; failed queries appear as {"keyword", "error"}.
    """
    async with httpx.AsyncClient() as client:
        tasks = [
            search_cves_async(client, kw, max_results=max_results, severity=severity)
            for kw in keywords
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    out: List[Dict[str, Any]] = []
    for kw, res in zip(keywords, results):
        if isinstance(res, Exception):
            out.append({"keyword": kw, "error": str(res)})
        else:
            out.append(res)
    return out

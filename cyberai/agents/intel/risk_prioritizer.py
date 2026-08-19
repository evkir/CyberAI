"""
Risk Prioritizer — sorts and filters CVE findings by composite score.
Produces ranked list with threshold filtering and tier grouping.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .cve_scorer import CVEScore, score_all


def prioritize(
    cves: List[Dict[str, Any]],
    min_score: float = 0.0,
    top_n: Optional[int] = None,
    tiers: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Score, filter, and rank CVEs.

    Args:
        cves:      raw CVE dicts from IntelAgent
        min_score: minimum composite score (0.0-1.0)
        top_n:     return only top N results
        tiers:     filter by severity tiers e.g. ["CRITICAL","HIGH"]

    Returns:
        List of enriched CVE dicts sorted by composite_score desc
    """
    scored = score_all(cves)

    if min_score > 0.0:
        scored = [s for s in scored if s.composite_score >= min_score]

    if tiers:
        tiers_upper = [t.upper() for t in tiers]
        scored = [s for s in scored if s.severity_tier in tiers_upper]

    if top_n:
        scored = scored[:top_n]

    return _merge(cves, scored)


def group_by_tier(
    cves: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Group scored CVEs by severity tier."""
    scored = score_all(cves)
    merged = _merge(cves, scored)

    groups: Dict[str, List] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFO": [],
    }
    for item in merged:
        tier = item.get("severity_tier", "INFO")
        groups.setdefault(tier, []).append(item)

    return groups


def summarize(cves: List[Dict[str, Any]]) -> Dict[str, Any]:
    """High-level summary of risk distribution."""
    if not cves:
        return {"total": 0, "tiers": {}, "top_cve": None, "avg_score": 0.0}

    scored = score_all(cves)
    tier_counts: Dict[str, int] = {}
    for s in scored:
        tier_counts[s.severity_tier] = tier_counts.get(s.severity_tier, 0) + 1

    avg = sum(s.composite_score for s in scored) / len(scored)
    top = scored[0] if scored else None

    return {
        "total": len(scored),
        "tiers": tier_counts,
        "top_cve": top.cve_id if top else None,
        "top_score": round(top.composite_score, 3) if top else None,
        "avg_score": round(avg, 3),
    }


def _merge(
    original: List[Dict[str, Any]],
    scored: List[CVEScore],
) -> List[Dict[str, Any]]:
    """Merge original CVE data with scoring results."""
    score_map = {s.cve_id: s for s in scored}
    result = []
    for cve in original:
        cve_id = cve.get("cve_id", "")
        if cve_id not in score_map:
            continue
        s = score_map[cve_id]
        result.append({**cve, **s.to_dict()})
    result.sort(key=lambda x: x.get("composite_score", 0), reverse=True)
    return result

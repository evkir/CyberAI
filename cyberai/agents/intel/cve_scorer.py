"""
CVE Scoring Engine — composite risk score from multiple signals.
Score = CVSS weight + exploit availability + recency + epss
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional


CVSS_WEIGHT     = 0.45
EXPLOIT_WEIGHT  = 0.30
RECENCY_WEIGHT  = 0.15
EPSS_WEIGHT     = 0.10


@dataclass
class CVEScore:
    cve_id:          str
    cvss:            float
    composite_score: float
    severity_tier:   str
    exploit_bonus:   float
    recency_bonus:   float
    epss_bonus:      float
    reasoning:       str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id":          self.cve_id,
            "cvss":            self.cvss,
            "composite_score": round(self.composite_score, 3),
            "severity_tier":   self.severity_tier,
            "exploit_bonus":   round(self.exploit_bonus, 3),
            "recency_bonus":   round(self.recency_bonus, 3),
            "epss_bonus":      round(self.epss_bonus, 3),
            "reasoning":       self.reasoning,
        }


def score_cve(cve: Dict[str, Any]) -> CVEScore:
    cvss_val = float(cve.get("cvss") or 0.0)
    cvss_component = (cvss_val / 10.0) * CVSS_WEIGHT
    exploit_bonus  = _exploit_bonus(cve)
    recency_bonus  = _recency_bonus(cve)
    epss_bonus     = _epss_bonus(cve)
    composite = min(cvss_component + exploit_bonus + recency_bonus + epss_bonus, 1.0)
    return CVEScore(
        cve_id          = cve.get("cve_id", ""),
        cvss            = cvss_val,
        composite_score = composite,
        severity_tier   = _tier(composite),
        exploit_bonus   = exploit_bonus,
        recency_bonus   = recency_bonus,
        epss_bonus      = epss_bonus,
        reasoning       = _reasoning(cvss_val, exploit_bonus, recency_bonus, epss_bonus),
    )


def score_all(cves: list[Dict[str, Any]]) -> list[CVEScore]:
    scored = [score_cve(c) for c in cves]
    scored.sort(key=lambda s: s.composite_score, reverse=True)
    return scored


def _exploit_bonus(cve: Dict) -> float:
    bonus = 0.0
    if cve.get("poc_likely"):          bonus += 0.12
    if cve.get("metasploit"):          bonus += 0.10
    if cve.get("exploited_in_wild"):   bonus += 0.08
    return min(bonus * EXPLOIT_WEIGHT / 0.30, EXPLOIT_WEIGHT)


def _recency_bonus(cve: Dict) -> float:
    pub = cve.get("published_date") or cve.get("published") or ""
    if not pub:
        return RECENCY_WEIGHT * 0.3
    try:
        dt       = datetime.fromisoformat(pub.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - dt).days
        if age_days <= 30:    factor = 1.0
        elif age_days <= 90:  factor = 0.8
        elif age_days <= 365: factor = 0.5
        elif age_days <= 730: factor = 0.3
        else:                 factor = 0.1
        return RECENCY_WEIGHT * factor
    except Exception:
        return RECENCY_WEIGHT * 0.3


def _epss_bonus(cve: Dict) -> float:
    return min(float(cve.get("epss") or 0.0) * EPSS_WEIGHT, EPSS_WEIGHT)


def _tier(score: float) -> str:
    if score >= 0.80: return "CRITICAL"
    if score >= 0.60: return "HIGH"
    if score >= 0.35: return "MEDIUM"
    if score >= 0.15: return "LOW"
    return "INFO"


def _reasoning(cvss: float, exploit: float, recency: float, epss: float) -> str:
    parts = [f"CVSS={cvss:.1f}"]
    if exploit > 0.15: parts.append("exploit available")
    if exploit > 0.25: parts.append("weaponized/in-wild")
    if recency > 0.12: parts.append("recent CVE")
    if epss > 0.05:    parts.append(f"EPSS={epss/EPSS_WEIGHT:.0%}")
    return " | ".join(parts)

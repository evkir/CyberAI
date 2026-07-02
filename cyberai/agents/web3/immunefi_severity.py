"""Immunefi severity classification for slither findings.

Maps slither detector checks to Immunefi's severity tiers
(Critical / High / Medium / Low / Insight) following their bug-bounty
severity methodology for smart contracts. A per-check table gives precise
classification; an impact/confidence fallback covers unknown detectors.

Immunefi smart-contract impact reference (paraphrased):
  Critical — direct theft/loss/freezing of funds, contract takeover.
  High     — theft of unclaimed yield, temporary freezing, griefing with cost.
  Medium   — contract fails to deliver promised value (no fund loss).
  Low      — minor/contained issues, best-practice deviations.
  Insight  — informational, no security impact.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from .slither_tool import SlitherFinding

# Immunefi tiers, ordered high→low for ranking.
IMMUNEFI_TIERS = ["Critical", "High", "Medium", "Low", "Insight"]
_TIER_RANK = {t: i for i, t in enumerate(IMMUNEFI_TIERS)}

# Precise per-check mapping for high-signal slither detectors.
CHECK_TO_IMMUNEFI = {
    # direct fund loss / takeover -> Critical
    "reentrancy-eth": "Critical",
    "arbitrary-send-eth": "Critical",
    "arbitrary-send-erc20": "Critical",
    "suicidal": "Critical",
    "controlled-delegatecall": "Critical",
    "unprotected-upgrade": "Critical",
    "delegatecall-loop": "Critical",
    # exploitable but conditional / no direct theft -> High
    "reentrancy-no-eth": "High",
    "tx-origin": "High",
    "weak-prng": "High",
    "incorrect-equality": "High",
    "unchecked-transfer": "High",
    "controlled-array-length": "High",
    # logic/contained -> Medium
    "uninitialized-state": "Medium",
    "uninitialized-storage": "Medium",
    "divide-before-multiply": "Medium",
    "reentrancy-benign": "Medium",
    "timestamp": "Medium",
    "unchecked-lowlevel": "Medium",
    "unchecked-send": "Medium",
    # best-practice / contained -> Low
    "low-level-calls": "Low",
    "missing-zero-check": "Low",
    "calls-loop": "Low",
    "reentrancy-events": "Low",
    # informational -> Insight
    "solc-version": "Insight",
    "pragma": "Insight",
    "naming-convention": "Insight",
    "dead-code": "Insight",
    "assembly": "Insight",
    "external-function": "Insight",
}

# Fallback: slither impact + confidence -> Immunefi tier.
_IMPACT_FALLBACK = {
    ("High", "High"): "Critical",
    ("High", "Medium"): "High",
    ("High", "Low"): "High",
    ("Medium", "High"): "High",
    ("Medium", "Medium"): "Medium",
    ("Medium", "Low"): "Medium",
    ("Low", "High"): "Low",
    ("Low", "Medium"): "Low",
    ("Low", "Low"): "Low",
    ("Informational", "High"): "Insight",
    ("Informational", "Medium"): "Insight",
    ("Informational", "Low"): "Insight",
}


def classify(finding: "SlitherFinding") -> str:
    """Return the Immunefi tier for a single slither finding."""
    if finding.check in CHECK_TO_IMMUNEFI:
        return CHECK_TO_IMMUNEFI[finding.check]
    return _IMPACT_FALLBACK.get((finding.impact, finding.confidence), "Insight")


def classify_all(findings: List["SlitherFinding"]) -> List[dict]:
    """Classify findings, attaching an `immunefi_severity` field, sorted high→low."""
    rows = []
    for f in findings:
        d = f.to_dict()
        d["immunefi_severity"] = classify(f)
        rows.append(d)
    rows.sort(key=lambda r: _TIER_RANK.get(r["immunefi_severity"], 99))
    return rows


def highest_tier(findings: List["SlitherFinding"]) -> str:
    """Return the most severe Immunefi tier across findings (Insight if none)."""
    if not findings:
        return "Insight"
    return min(
        (classify(f) for f in findings),
        key=lambda t: _TIER_RANK.get(t, 99),
    )

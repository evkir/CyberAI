"""Merge Slither and aderyn findings with SWC-based cross-validation.

Both static analyzers are mapped onto the SWC Registry taxonomy. A weakness
reported by *both* tools for the same SWC is cross-validated (higher
confidence); single-tool findings are kept but flagged. Findings that do not map
to a known SWC are kept per-detector so nothing is silently dropped.

The aderyn detector coverage here is intentionally conservative (only verified
detector names); it is broadened from the live `aderyn registry` in a later
change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Union

from cyberai.agents.web3.aderyn_tool import AderynFinding
from cyberai.agents.web3.immunefi_severity import IMMUNEFI_TIERS, classify
from cyberai.agents.web3.slither_tool import SlitherFinding

_TIER_RANK = {t: i for i, t in enumerate(IMMUNEFI_TIERS)}

Finding = Union[SlitherFinding, AderynFinding]

# Detector name (slither check or aderyn detector_name) -> SWC Registry id.
# Slither names are well-established; aderyn names below are verified only.
DETECTOR_TO_SWC: Dict[str, str] = {
    # reentrancy -> SWC-107
    "reentrancy-eth": "SWC-107",
    "reentrancy-no-eth": "SWC-107",
    "reentrancy-benign": "SWC-107",
    "reentrancy-events": "SWC-107",
    # delegatecall to untrusted callee -> SWC-112
    "controlled-delegatecall": "SWC-112",
    "delegatecall-loop": "SWC-112",
    "delegate-call-in-loop": "SWC-112",  # aderyn (verified)
    # authorization through tx.origin -> SWC-115
    "tx-origin": "SWC-115",
    # unchecked call return value -> SWC-104
    "unchecked-lowlevel": "SWC-104",
    "unchecked-send": "SWC-104",
    "unchecked-transfer": "SWC-104",
    # unprotected SELFDESTRUCT -> SWC-106
    "suicidal": "SWC-106",
    # unprotected ether withdrawal / arbitrary send -> SWC-105
    "arbitrary-send-eth": "SWC-105",
    "arbitrary-send-erc20": "SWC-105",
    # block values as proxy for time -> SWC-116
    "timestamp": "SWC-116",
    # weak sources of randomness -> SWC-120
    "weak-prng": "SWC-120",
    # signature malleability -> SWC-117
    "ecrecover": "SWC-117",  # aderyn (verified)
    # uninitialized storage pointer -> SWC-109
    "uninitialized-storage": "SWC-109",
    "uninitialized-state": "SWC-109",
    # floating / outdated pragma -> SWC-103
    "solc-version": "SWC-103",
    "pragma": "SWC-103",
}


@dataclass
class MergedFinding:
    """A Slither/aderyn finding after SWC grouping and cross-validation."""

    check: str
    immunefi_severity: str
    confidence: str  # "cross-validated" | "single-tool"
    sources: List[str]
    swc: Optional[str] = None
    title: str = ""
    description: str = ""
    checks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "checks": self.checks,
            "swc": self.swc,
            "immunefi_severity": self.immunefi_severity,
            "confidence": self.confidence,
            "sources": self.sources,
            "title": self.title,
            "description": self.description,
        }


def _swc(finding: Finding) -> Optional[str]:
    return DETECTOR_TO_SWC.get(finding.check)


def _title(finding: Finding) -> str:
    return getattr(finding, "title", "") or finding.check


def merge_findings(
    slither: Sequence[SlitherFinding],
    aderyn: Sequence[AderynFinding],
) -> List[MergedFinding]:
    """Merge findings from both tools, cross-validating by SWC id.

    Returns merged findings sorted by Immunefi tier (high first), with
    cross-validated findings ahead of single-tool ones at the same tier.
    """
    groups: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    def add(finding: Finding, source: str) -> None:
        swc = _swc(finding)
        key = swc if swc else f"__{source}__{finding.check}"
        if key not in groups:
            groups[key] = {
                "swc": swc,
                "sources": [],
                "checks": [],
                "tiers": [],
                "title": _title(finding),
                "description": getattr(finding, "description", "") or "",
            }
            order.append(key)
        g = groups[key]
        if source not in g["sources"]:
            g["sources"].append(source)
        if finding.check not in g["checks"]:
            g["checks"].append(finding.check)
        g["tiers"].append(classify(finding))

    for f in slither:
        add(f, "slither")
    for f in aderyn:
        add(f, "aderyn")

    merged: List[MergedFinding] = []
    for key in order:
        g = groups[key]
        worst = min(g["tiers"], key=lambda t: _TIER_RANK.get(t, 99))
        confidence = "cross-validated" if len(g["sources"]) > 1 else "single-tool"
        merged.append(
            MergedFinding(
                check=g["checks"][0],
                checks=g["checks"],
                swc=g["swc"],
                immunefi_severity=worst,
                confidence=confidence,
                sources=sorted(g["sources"]),
                title=g["title"],
                description=g["description"].strip(),
            )
        )

    merged.sort(
        key=lambda m: (
            _TIER_RANK.get(m.immunefi_severity, 99),
            0 if m.confidence == "cross-validated" else 1,
        )
    )
    return merged

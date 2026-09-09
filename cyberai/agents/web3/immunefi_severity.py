"""Immunefi severity classification for slither and aderyn findings.

Maps slither/aderyn detector checks to Immunefi's severity tiers
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
SLITHER_CHECK_TO_IMMUNEFI = {
    # direct fund loss / takeover -> Critical
    "reentrancy-eth": "Critical",
    "arbitrary-send-eth": "Critical",
    "arbitrary-send-erc20": "Critical",
    "suicidal": "Critical",
    "controlled-delegatecall": "Critical",
    "unprotected-upgrade": "Critical",
    "delegatecall-loop": "Critical",
    # confirmed on-chain exploit (Foundry PoC replayed a real fund extraction on
    # a mainnet fork) -> Critical; deterministic whether classified from the
    # finding object or its serialized dict.
    "onchain-poc-exploit": "Critical",
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

# Aderyn detector_name -> Immunefi tier.
#
# Every key exists in `aderyn registry` for aderyn 0.1.9, snapshotted in
# tests/fixtures/aderyn_registry_0.1.9.json and guarded by a test. Sixteen keys
# earlier releases carried were not in that registry and could never classify a
# finding. Where the registry ships the same weakness under another spelling the
# mapping moved to the real name: selfdestruct -> selfdestruct-identifier,
# delegatecall-in-loop -> delegate-call-in-loop, eth-send-unchecked-address ->
# send-ether-no-checks, unchecked-low-level-call -> unchecked-return,
# non-reentrant-not-first -> non-reentrant-before-others, unsafe-casting ->
# unsafe-casting-detector, unsafe-erc20-operation -> unsafe-erc20-functions,
# strict-equality-contract-balance ->
# dangerous-strict-equailty-on-contract-balance (aderyn's own typo, copied
# verbatim because that is the string a finding carries), todo ->
# contract-with-todos. The rest had no counterpart and are gone.
ADERYN_CHECK_TO_IMMUNEFI = {
    # direct fund loss / takeover -> Critical
    "arbitrary-transfer-from": "Critical",
    "selfdestruct-identifier": "Critical",
    "delegate-call-unchecked-address": "Critical",
    "unprotected-initializer": "Critical",
    # exploitable / conditional -> High
    "delegate-call-in-loop": "High",
    "tx-origin-used-for-auth": "High",
    "weak-randomness": "High",
    "send-ether-no-checks": "High",
    "contract-locks-ether": "High",
    # logic / contained -> Medium
    "non-reentrant-before-others": "Medium",
    "unchecked-return": "Medium",
    "unsafe-casting-detector": "Medium",
    "dangerous-unary-operator": "Medium",
    "dangerous-strict-equailty-on-contract-balance": "Medium",
    "unsafe-erc20-functions": "Medium",
    "msg-value-in-loop": "Medium",
    "uninitialized-state-variable": "Medium",
    # best-practice / contained -> Low
    "block-timestamp-deadline": "Low",
    "ecrecover": "Low",
    "state-variable-shadowing": "Low",
    "rtlo": "Low",
    "zero-address-check": "Low",
    # informational -> Insight
    "centralization-risk": "Insight",
    "unspecific-solidity-pragma": "Insight",
    "contract-with-todos": "Insight",
    "empty-block": "Insight",
    "push-zero-opcode": "Insight",
    "useless-public-function": "Insight",
    "useless-modifier": "Insight",
    "unindexed-events": "Insight",
}

# Detector check (slither or aderyn) -> Immunefi tier.
CHECK_TO_IMMUNEFI = {**SLITHER_CHECK_TO_IMMUNEFI, **ADERYN_CHECK_TO_IMMUNEFI}

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

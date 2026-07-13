"""Immunefi exporter + Web3 report-bridge unit tests.

Covers the Markdown submission exporter (severity mapping, funds-at-risk and
proof-of-concept blocks), the finding-dict -> ReportSection bridge, the tier and
funds-at-risk heuristics, and the multi-finding submission builder. No external
toolchain or network.
"""

from __future__ import annotations

from cyberai.agents.report.immunefi_exporter import export_immunefi
from cyberai.agents.web3.immunefi_report import (
    build_immunefi_submissions,
    estimate_funds_at_risk,
    immunefi_tier,
    web3_finding_to_section,
)
from cyberai.core.types import ReportSection


# --- exporter --------------------------------------------------------------


def _section() -> ReportSection:
    return ReportSection(
        title="Reentrancy in withdraw",
        severity="CRITICAL",
        findings=["sends ETH before zeroing balance", "attacker re-enters"],
        recommendations=["checks-effects-interactions", "nonReentrant guard"],
        impact="Full drain of vault ETH.",
    )


def test_export_immunefi_full_sections():
    md = export_immunefi(
        _section(),
        funds_at_risk="~1200 ETH",
        proof_of_concept="forge test --match-test testExploit",
    )
    assert "**Severity:** Critical" in md
    assert "## Brief/Intro" in md
    assert "## Vulnerability Details" in md
    assert "## Impact" in md
    assert "## Proof of Concept" in md
    assert "## Recommendation" in md
    assert "**Funds at risk:** ~1200 ETH" in md
    assert "forge test --match-test testExploit" in md


def test_export_immunefi_severity_mapping():
    for internal, tier in [
        ("CRITICAL", "Critical"),
        ("HIGH", "High"),
        ("MEDIUM", "Medium"),
        ("LOW", "Low"),
        ("INFO", "Insight"),
    ]:
        md = export_immunefi(ReportSection(title="t", severity=internal))
        assert f"**Severity:** {tier}" in md


def test_export_immunefi_unknown_severity_defaults_insight():
    # ReportSection validator coerces unknown severities to INFO -> Insight.
    md = export_immunefi(ReportSection(title="t", severity="BOGUS"))
    assert "**Severity:** Insight" in md


def test_export_immunefi_empty_blocks_have_placeholders():
    md = export_immunefi(ReportSection(title="t", severity="LOW"))
    assert "_None provided._" in md  # empty findings + recommendations
    assert "_No proof of concept provided._" in md
    assert "_Impact not specified._" in md


def test_export_immunefi_no_funds_line_when_absent():
    md = export_immunefi(_section())
    assert "Funds at risk" not in md


# --- tier + funds-at-risk --------------------------------------------------


def test_immunefi_tier_from_check_table():
    assert immunefi_tier({"check": "reentrancy-eth"}) == "Critical"
    assert immunefi_tier({"check": "onchain-poc-exploit"}) == "Critical"


def test_immunefi_tier_from_impact_confidence_fallback():
    assert (
        immunefi_tier({"check": "unknown-x", "impact": "Medium", "confidence": "Medium"})
        == "Medium"
    )


def test_immunefi_tier_unknown_defaults_insight():
    assert immunefi_tier({"check": "totally-unknown"}) == "Insight"


def test_estimate_funds_at_risk_from_poc_profit():
    far = estimate_funds_at_risk({"profit_wei": 1500 * 10**18}, "Critical")
    assert "1500.000000 ETH" in far
    assert "on-chain proof of concept" in far


def test_estimate_funds_at_risk_qualitative_by_tier():
    assert "Direct loss" in estimate_funds_at_risk({}, "Critical")
    assert "Conditional" in estimate_funds_at_risk({}, "High")
    assert "No direct fund loss" in estimate_funds_at_risk({}, "Medium")
    assert "contained" in estimate_funds_at_risk({}, "Low")
    assert "No security impact" in estimate_funds_at_risk({}, "Insight")


def test_estimate_funds_at_risk_zero_profit_falls_back_to_tier():
    assert "Direct loss" in estimate_funds_at_risk({"profit_wei": 0}, "Critical")


def test_estimate_funds_at_risk_unknown_tier():
    assert estimate_funds_at_risk({}, "Nonsense") == "Impact not quantified"


# --- bridge ----------------------------------------------------------------


def test_web3_finding_to_section_maps_tier_and_location():
    section = web3_finding_to_section(
        {
            "check": "reentrancy-eth",
            "impact": "High",
            "confidence": "High",
            "description": "ETH sent before state update",
            "contract": "Vault",
            "function": "withdraw",
        }
    )
    assert section.severity == "CRITICAL"
    assert section.title == "reentrancy-eth in Vault.withdraw"
    assert section.findings == ["ETH sent before state update"]
    assert section.impact == "ETH sent before state update"


def test_web3_finding_to_section_contract_only_location():
    section = web3_finding_to_section({"check": "suicidal", "contract": "Vault"})
    assert section.title == "suicidal in Vault"


def test_web3_finding_to_section_no_location():
    section = web3_finding_to_section({"check": "solc-version"})
    assert section.title == "solc-version"
    assert section.findings == []


def test_web3_finding_to_section_missing_check():
    section = web3_finding_to_section({})
    assert section.title == "finding"


# --- submission builder ----------------------------------------------------


def _agent_result() -> dict:
    return {
        "mode": "local",
        "poc_findings": [
            {
                "check": "onchain-poc-exploit",
                "confirmed": True,
                "test": "testExploit()",
                "profit_wei": 1500 * 10**18,
                "contract": "Vault",
            }
        ],
        "findings": [
            {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "High",
                "description": "ETH before state",
                "contract": "Vault",
                "function": "withdraw",
            }
        ],
        "access_findings": [
            {
                "check": "missing-auth",
                "impact": "High",
                "confidence": "High",
                "description": "setOwner unguarded",
                "contract": "Token",
                "function": "setOwner",
            }
        ],
    }


def test_build_submissions_poc_first_and_critical():
    subs = build_immunefi_submissions(_agent_result())
    assert len(subs) == 3
    # poc bucket is rendered first
    assert "**Severity:** Critical" in subs[0]
    assert "passed on a mainnet fork" in subs[0]
    assert "1500.000000 ETH" in subs[0]


def test_build_submissions_empty_result():
    assert build_immunefi_submissions({}) == []


def test_build_submissions_skips_non_dict_findings():
    subs = build_immunefi_submissions({"findings": ["not-a-dict", None, 42]})
    assert subs == []


def test_build_submissions_poc_without_test_has_no_poc_block():
    result = {
        "poc_findings": [{"check": "onchain-poc-exploit", "confirmed": True, "profit_wei": 10**18}]
    }
    subs = build_immunefi_submissions(result)
    assert len(subs) == 1
    assert "_No proof of concept provided._" in subs[0]

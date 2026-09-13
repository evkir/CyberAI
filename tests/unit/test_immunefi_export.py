"""Immunefi exporter + Web3 report-bridge unit tests.

Covers the Markdown submission exporter (severity mapping, funds-at-risk and
proof-of-concept blocks), the finding-dict -> ReportSection bridge, the tier and
funds-at-risk heuristics, and the multi-finding submission builder. No external
toolchain or network.
"""

from __future__ import annotations

from pathlib import Path

from cyberai.agents.report.immunefi_exporter import export_immunefi
from cyberai.agents.web3.access_control import analyze_source, find_escalation_paths
from cyberai.agents.web3.immunefi_report import (
    build_immunefi_submissions,
    escalation_note,
    estimate_funds_at_risk,
    immunefi_tier,
    web3_finding_to_section,
)
from cyberai.core.types import ReportSection

MULTI_FIXTURE = Path(__file__).parent.parent / "fixtures" / "escalation_multi.sol"

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


# --- escalation paths ------------------------------------------------------


def _escalation_result() -> dict:
    """Findings on three functions, three paths: attached, orphan, dead-end."""
    return {
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
                "description": "setOwner has no guard",
                "contract": "Vault",
                "function": "setOwner",
            }
        ],
        "aderyn_findings": [
            {
                "check": "missing-zero-check",
                "impact": "Low",
                "confidence": "High",
                "description": "withdraw misses a zero check",
                "contract": "Vault",
                "function": "withdraw",
            },
            {
                "check": "unsafe-erc20-functions",
                "impact": "Medium",
                "confidence": "High",
                "description": "mint uses unsafe transfer",
                "contract": "Vault",
                "function": "mint",
            },
        ],
        "escalation_paths": [
            {
                "entry": "setOwner",
                "grants": "ownership",
                "unlocks": ["withdraw"],
                "contract": "Vault",
            },
            {
                "entry": "ghost",
                "grants": "ownership",
                "unlocks": ["mint", "withdraw"],
                "contract": "Vault",
            },
            {"entry": "lonely", "grants": "authority", "unlocks": [], "contract": "Vault"},
        ],
    }


def test_a_path_whose_entry_has_a_finding_is_folded_into_that_submission():
    """The path is evidence for that finding, so it must not become a second bug."""
    result = _escalation_result()
    result["escalation_paths"] = [result["escalation_paths"][0]]
    subs = build_immunefi_submissions(result)
    assert len(subs) == 4, subs
    owner = [s for s in subs if "missing-auth in Vault.setOwner" in s]
    assert len(owner) == 1, subs
    assert "setOwner grants ownership, which unlocks withdraw" in owner[0]
    assert "Privilege escalation via setOwner" not in "".join(subs)


def test_a_path_no_finding_covers_becomes_its_own_submission():
    """Dropping it was the defect; its tier is borrowed, never invented."""
    subs = build_immunefi_submissions(_escalation_result())
    ghost = [s for s in subs if "Privilege escalation via ghost" in s]
    assert len(ghost) == 1, subs
    # withdraw carries Critical and Low findings, mint a Medium one: the path
    # takes the strongest of the three tiers, not the first or the weakest.
    assert "**Severity:** Critical" in ghost[0]
    assert "ghost grants ownership, which unlocks mint, withdraw" in ghost[0]


def test_a_path_unlocking_nothing_known_is_named_rather_than_dropped():
    """Insight is the floor, but the title still says which entry point it is."""
    subs = build_immunefi_submissions(_escalation_result())
    lonely = [s for s in subs if "Privilege escalation via lonely" in s]
    assert len(lonely) == 1, subs
    assert "**Severity:** Insight" in lonely[0]
    assert "no guarded function found" in lonely[0]


def test_a_path_is_not_attached_to_the_same_name_in_another_contract():
    """Two heirs each declare setOwner; matching on the name alone crosses them.

    Measured on this fixture before the fix: four attachments where two are
    correct, and both submissions carried a note naming the other contract's
    unlocked function.
    """
    source = MULTI_FIXTURE.read_text()
    findings = [f.to_dict() for f in analyze_source(source)]
    paths = [p.to_dict() for p in find_escalation_paths(source)]
    assert [(p["contract"], p["entry"], p["unlocks"]) for p in paths] == [
        ("VaultV1", "setOwner", ["mint"]),
        ("VaultV2", "setOwner", ["sweep"]),
    ]
    subs = build_immunefi_submissions({"access_findings": findings, "escalation_paths": paths})
    assert len(subs) == 2, subs
    notes = [escalation_note(p) for p in paths]
    assert [sum(n in s for n in notes) for s in subs] == [1, 1], subs
    first = next(s for s in subs if "VaultV1.setOwner" in s)
    assert "unlocks mint" in first
    assert "unlocks sweep" not in first


def test_an_orphan_path_does_not_borrow_a_tier_from_another_contract():
    """An unlocked name alone is not a tier: the finding must sit in the same contract.

    The path comes from the production finder; the Critical finding sits on a
    same-named function of a contract the path never touches, so the path is an
    Insight rather than a Critical.
    """
    source = MULTI_FIXTURE.read_text()
    paths = [p.to_dict() for p in find_escalation_paths(source)]
    path = next(p for p in paths if p["contract"] == "VaultV1")
    assert path["unlocks"] == ["mint"]
    result = {
        "findings": [
            {
                "check": "arbitrary-send-eth",
                "impact": "High",
                "confidence": "High",
                "description": "mint sends ETH anywhere",
                "contract": "Unrelated",
                "function": "mint",
            }
        ],
        "escalation_paths": [path],
    }
    subs = build_immunefi_submissions(result)
    orphan = [s for s in subs if "Privilege escalation via setOwner" in s]
    assert len(orphan) == 1, subs
    assert "**Severity:** Insight" in orphan[0]
    assert "**Severity:** Critical" not in orphan[0]


def test_merged_findings_are_not_exported_a_second_time():
    """Measured: every merged check is already in a bucket, so reading it duplicates."""
    result = _escalation_result()
    result["merged_findings"] = [
        {
            "check": "reentrancy-eth",
            "checks": ["reentrancy-eth"],
            "swc": "SWC-107",
            "immunefi_severity": "Critical",
            "confidence": "cross-validated",
            "sources": ["slither", "aderyn"],
            "title": "Reentrancy",
            "description": "ETH before state",
        }
    ]
    del result["escalation_paths"]
    assert len(build_immunefi_submissions(result)) == 4

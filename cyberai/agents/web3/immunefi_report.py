"""Bridge Web3 findings into Immunefi-ready ReportSections.

The Web3 agent emits findings from several tools (Slither, Aderyn, the access-
control analyzer, and the Foundry on-chain PoC), each serialized to a dict with
a shared shape (`check`, and where available `impact`/`confidence`/`description`
/`contract`/`function`/`profit_wei`). This module turns one such finding dict
into a `ReportSection` carrying the Immunefi severity tier, and estimates the
funds-at-risk statement Immunefi triage weighs when confirming severity.

Severity is delegated to `immunefi_severity.classify` (calibrated per detector);
this module never re-derives it. The Immunefi tier is then mapped onto the
internal ReportSection vocabulary so the shared exporter can render it.
"""

from __future__ import annotations

from typing import Any

from cyberai.agents.web3.immunefi_severity import classify
from cyberai.core.types import ReportSection

# Immunefi tier -> internal ReportSection severity vocabulary.
# Insight has no internal equivalent and maps to INFO.
_TIER_TO_INTERNAL = {
    "Critical": "CRITICAL",
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Insight": "INFO",
}

# 1 ether in wei, for rendering a PoC's profit_wei as ETH.
_WEI_PER_ETH = 10**18


class _FindingView:
    """Adapt a finding dict to the attribute shape `classify` expects.

    `classify` reads `.check`, `.impact`, `.confidence`; a finding dict may omit
    impact/confidence (e.g. a confirmed PoC serializes neither), so missing
    values default to empty strings and fall through to the per-check table.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self.check = str(data.get("check", ""))
        self.impact = str(data.get("impact", ""))
        self.confidence = str(data.get("confidence", ""))


def immunefi_tier(finding: dict[str, Any]) -> str:
    """Return the Immunefi tier for a serialized Web3 finding dict."""
    return classify(_FindingView(finding))


def _finding_title(finding: dict[str, Any]) -> str:
    """Human-readable title from a finding's check and location."""
    check = str(finding.get("check", "finding")) or "finding"
    contract = str(finding.get("contract", "")).strip()
    function = str(finding.get("function", "")).strip()
    location = ""
    if contract and function:
        location = f" in {contract}.{function}"
    elif contract:
        location = f" in {contract}"
    return f"{check}{location}"


def estimate_funds_at_risk(finding: dict[str, Any], tier: str) -> str:
    """Estimate a funds-at-risk statement for Immunefi triage.

    A confirmed Foundry PoC carries a measured `profit_wei` — the strongest
    evidence, rendered as a concrete ETH figure. Otherwise the statement is a
    qualitative bound from the severity tier, never a fabricated number.
    """
    profit_wei = finding.get("profit_wei")
    if isinstance(profit_wei, int) and profit_wei > 0:
        eth = profit_wei / _WEI_PER_ETH
        return f"~{eth:.6f} ETH extracted in on-chain proof of concept"
    return {
        "Critical": "Direct loss or freezing of contract funds",
        "High": "Conditional or partial loss of funds",
        "Medium": "No direct fund loss; protocol fails to deliver value",
        "Low": "Minor, contained impact",
        "Insight": "No security impact",
    }.get(tier, "Impact not quantified")


def web3_finding_to_section(finding: dict[str, Any]) -> ReportSection:
    """Build an Immunefi-ready ReportSection from one Web3 finding dict.

    The section's severity is the internal-vocabulary form of the Immunefi tier;
    the shared Immunefi exporter maps it back for rendering. `description` and
    location populate `findings`; the recommendation is left to the caller/LLM
    layer, so it defaults to empty rather than inventing remediation text.
    """
    tier = immunefi_tier(finding)
    section = ReportSection(
        title=_finding_title(finding),
        severity=_TIER_TO_INTERNAL.get(tier, "INFO"),
        impact=str(finding.get("description", "")).strip(),
        findings=[str(finding.get("description", "")).strip()]
        if finding.get("description")
        else [],
    )
    return section


# Finding buckets in a Web3 agent local-audit result, in report priority order.
# poc_findings first: a confirmed on-chain exploit is the strongest evidence.
_FINDING_KEYS = (
    "poc_findings",
    "findings",
    "aderyn_findings",
    "access_findings",
    "halmos_findings",
)


def build_immunefi_submissions(agent_result: dict[str, Any]) -> list[str]:
    """Render every finding in a Web3 agent result as an Immunefi submission.

    Collects findings across the agent's tool buckets (confirmed PoC first),
    builds a ReportSection per finding, estimates funds-at-risk, and renders each
    with the shared Immunefi exporter. A confirmed PoC's transaction summary is
    passed through as the proof-of-concept block. Returns one Markdown document
    per finding; an empty result yields an empty list.
    """
    from cyberai.agents.report.immunefi_exporter import export_immunefi

    submissions: list[str] = []
    for key in _FINDING_KEYS:
        for finding in agent_result.get(key, []) or []:
            if not isinstance(finding, dict):
                continue
            tier = immunefi_tier(finding)
            section = web3_finding_to_section(finding)
            far = estimate_funds_at_risk(finding, tier)
            poc = ""
            if finding.get("confirmed") and finding.get("test"):
                poc = f"Foundry test `{finding['test']}` passed on a mainnet fork."
            submissions.append(export_immunefi(section, funds_at_risk=far, proof_of_concept=poc))
    return submissions

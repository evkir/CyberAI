"""Immunefi-compatible Markdown export for a ReportSection.

Renders a finding as an Immunefi bug-bounty submission following the structure
their triage expects, using the Vulnerability Severity Classification System
(VSCS v2.3) severity vocabulary: Critical / High / Medium / Low / Insight.

The internal ReportSection severity vocabulary (CRITICAL/HIGH/MEDIUM/LOW/INFO)
is mapped onto the Immunefi tiers here; INFO maps to Insight, the tier Immunefi
reserves for informational, no-security-impact findings.
"""

from __future__ import annotations

from cyberai.core.types import ReportSection

# Internal severity vocabulary -> Immunefi VSCS v2.3 tier.
_IMMUNEFI_SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Insight",
}


def _bullets(items: list[str]) -> str:
    """Render a list as Markdown bullets; placeholder if empty."""
    if not items:
        return "_None provided._"
    return "\n".join(f"- {it}" for it in items)


def export_immunefi(
    section: ReportSection,
    funds_at_risk: str = "",
    proof_of_concept: str = "",
) -> str:
    """Render a ReportSection as an Immunefi-style Markdown submission.

    Sections follow the layout Immunefi triage expects: Title, Severity, Brief,
    Vulnerability Details, Impact (with an optional funds-at-risk line), Proof of
    Concept, and Recommendation. `findings` populate Vulnerability Details;
    `recommendations` populate Recommendation.

    `proof_of_concept`, when provided, is rendered verbatim under Proof of
    Concept — this is where a Foundry exploit script or on-chain transaction
    trace goes. When absent, the block states none was provided rather than
    duplicating the vulnerability details.

    `funds_at_risk`, when provided, is surfaced under Impact — Immunefi weighs
    severity by realized impact, so an explicit funds-at-risk statement helps
    triage.
    """
    severity = _IMMUNEFI_SEVERITY.get(section.severity.upper(), "Insight")
    impact = section.impact.strip() or "_Impact not specified._"
    brief = section.title.strip()

    impact_block = impact
    if funds_at_risk.strip():
        impact_block = f"{impact}\n\n**Funds at risk:** {funds_at_risk.strip()}"

    poc_block = proof_of_concept.strip() or "_No proof of concept provided._"

    return (
        f"# {section.title}\n\n"
        f"**Severity:** {severity}\n\n"
        f"## Brief/Intro\n\n"
        f"{brief}\n\n"
        f"## Vulnerability Details\n\n"
        f"{_bullets(section.findings)}\n\n"
        f"## Impact\n\n"
        f"{impact_block}\n\n"
        f"## Proof of Concept\n\n"
        f"{poc_block}\n\n"
        f"## Recommendation\n\n"
        f"{_bullets(section.recommendations)}\n"
    )

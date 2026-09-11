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


# Immunefi tiers strongest first, for picking the tier of an escalation path
# from the findings it unlocks.
_TIER_ORDER = ("Critical", "High", "Medium", "Low", "Insight")


def escalation_note(path: dict[str, Any]) -> str:
    """One sentence naming the entry, what it grants and what that unlocks."""
    entry = str(path.get("entry", "")).strip() or "an unguarded entry point"
    grants = str(path.get("grants", "")).strip() or "authority"
    unlocks = [str(name).strip() for name in path.get("unlocks") or [] if str(name).strip()]
    reached = ", ".join(unlocks) if unlocks else "no guarded function found"
    return f"Escalation path: {entry} grants {grants}, which unlocks {reached}."


def _tier_of_unlocked(path: dict[str, Any], by_function: dict[str, str]) -> str:
    """The strongest tier among the findings on the functions this path unlocks.

    An escalation path carries no `check`, so `classify` has nothing to read and
    would call every path an Insight. The severity here is borrowed from
    findings that already exist rather than invented for the path.
    """
    tiers = [by_function[name] for name in path.get("unlocks") or [] if name in by_function]
    for tier in _TIER_ORDER:
        if tier in tiers:
            return tier
    return "Insight"


def escalation_path_to_section(path: dict[str, Any], tier: str) -> ReportSection:
    """A ReportSection for a path no finding covers, titled by its entry point."""
    entry = str(path.get("entry", "")).strip() or "unknown entry"
    note = escalation_note(path)
    return ReportSection(
        title=f"Privilege escalation via {entry}",
        severity=_TIER_TO_INTERNAL.get(tier, "INFO"),
        impact=note,
        findings=[note],
    )


def build_immunefi_submissions(agent_result: dict[str, Any]) -> list[str]:
    """Render every finding in a Web3 agent result as an Immunefi submission.

    Collects findings across the agent's tool buckets (confirmed PoC first),
    builds a ReportSection per finding, estimates funds-at-risk, and renders each
    with the shared Immunefi exporter. A confirmed PoC's transaction summary is
    passed through as the proof-of-concept block.

    Escalation paths are evidence for the finding on their entry function, not
    separate bugs, so a path whose entry carries a finding is folded into that
    submission. A path no finding covers becomes its own submission rather than
    being dropped, and takes the strongest tier among the functions it unlocks.

    `merged_findings` is deliberately not read: measured on the access-control
    fixture, all twelve of its checks already appear in the buckets above and
    its stored severity agreed with the derived one twelve times out of twelve,
    so reading it would duplicate twelve submissions and add nothing.

    Returns one Markdown document per finding; an empty result yields an empty
    list.
    """
    from cyberai.agents.report.immunefi_exporter import export_immunefi

    paths = [p for p in agent_result.get("escalation_paths") or [] if isinstance(p, dict)]
    by_entry: dict[str, list[dict[str, Any]]] = {}
    for path in paths:
        by_entry.setdefault(str(path.get("entry", "")).strip(), []).append(path)

    by_function: dict[str, str] = {}
    for key in _FINDING_KEYS:
        for finding in agent_result.get(key, []) or []:
            if isinstance(finding, dict) and finding.get("function"):
                name = str(finding["function"]).strip()
                tier = immunefi_tier(finding)
                current = by_function.get(name)
                if current is None or _TIER_ORDER.index(tier) < _TIER_ORDER.index(current):
                    by_function[name] = tier

    submissions: list[str] = []
    attached: set[int] = set()
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
            for path in by_entry.get(str(finding.get("function", "")).strip(), []):
                note = escalation_note(path)
                section.findings.append(note)
                section.impact = f"{section.impact}\n\n{note}".strip()
                attached.add(id(path))
            submissions.append(export_immunefi(section, funds_at_risk=far, proof_of_concept=poc))

    for path in paths:
        if id(path) in attached:
            continue
        tier = _tier_of_unlocked(path, by_function)
        section = escalation_path_to_section(path, tier)
        submissions.append(
            export_immunefi(section, funds_at_risk=estimate_funds_at_risk(path, tier))
        )
    return submissions

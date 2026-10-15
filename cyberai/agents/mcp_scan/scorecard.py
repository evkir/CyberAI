"""STRIDE scorecard rendering for an MCP scan result.

This is a representation layer, not a detector: it reads the summaries already
produced by the analysis stages (poisoning, over-privilege, exposure,
attestation, trust) and folds them into a deterministic STRIDE table. The
findings themselves are created by those stages; the scorecard never adds one.

The mapping ties each STRIDE category to the analysis that actually evidences
it, so a published scorecard traces back to concrete signals rather than a
generic checklist:

* Spoofing        - unauthenticated endpoint + self-asserted server identity
* Tampering       - poisoned / mutable tool metadata (rug-pull class)
* Repudiation     - MCP does not sign or attest invocations (context only)
* Info disclosure - over-privileged exfiltration capability combinations
* Denial of svc   - network reachability of the endpoint (rebinding surface)
* Elevation       - cross-server shadowing / confused-deputy + unauth invoke,
                    and session text summoning a tool the server never advertised
"""

from __future__ import annotations

from typing import Any

from cyberai.core.scan_session import Severity

# Worst-first ordering for folding several severities into one row.
_ORDER = [
    Severity.CRITICAL.value,
    Severity.HIGH.value,
    Severity.MEDIUM.value,
    Severity.LOW.value,
    Severity.INFO.value,
]
_RANK = {sev: i for i, sev in enumerate(_ORDER)}


def _worst(severities: list[str]) -> str:
    """Return the highest-severity value in the list, or INFO if empty."""
    ranked = [s for s in severities if s in _RANK]
    if not ranked:
        return Severity.INFO.value
    return min(ranked, key=lambda s: _RANK[s])


def _row(category: str, severity: str, signals: int | None, source: str) -> str:
    """One STRIDE row. ``signals`` is None when the stage never read its input.

    A row reading INFO / 0 is a measurement: nothing was found. A stage whose
    tool list failed to arrive found nothing because it looked at nothing, and
    printing the same row states a clean result the scan cannot support.
    """
    count = "n/a" if signals is None else str(signals)
    return f"| {category} | {severity} | {count} | {source} |"


def _unmeasured_stage(stage: dict[str, Any]) -> bool:
    """Whether a stage summary says its surface was never read."""
    return stage.get("measured") is False


def _either(stage: dict[str, Any], severity: str) -> str:
    """The severity to print: an unread stage asserts nothing, not INFO."""
    return "n/a" if _unmeasured_stage(stage) else severity


def build_mcp_scorecard(result: dict[str, Any]) -> str:
    """Render a deterministic STRIDE scorecard (Markdown) from a scan result.

    ``result`` is the dict returned by :meth:`MCPScanAgent.run`. Only the
    per-stage summaries are read; the function is pure and side-effect free.
    """
    poisoning = result.get("poisoning", {})
    overpriv = result.get("overprivilege", {})
    exposure = result.get("exposure", {})
    attestation = result.get("attestation", {})
    trust = result.get("trust", {})
    instructions = result.get("instructions", {})

    poison_sevs = [t.get("severity", "INFO") for t in poisoning.get("tools", [])]
    overpriv_sevs = [t.get("severity", "INFO") for t in overpriv.get("tools", [])]
    trust_sevs = [t.get("severity", "INFO") for t in trust.get("tools", [])]

    exp_scan = exposure.get("scan", {})
    exp_sev = exp_scan.get("severity", Severity.INFO.value)
    exposed = bool(exposure.get("exposed"))
    dangerous = exp_scan.get("dangerous_capabilities", []) or []

    att_scan = attestation.get("scan", {})
    att_sev = att_scan.get("severity", Severity.INFO.value)
    unauth = bool(attestation.get("unauthenticated"))

    # Info-disclosure and elevation draw on more than one stage.
    info_sevs = list(overpriv_sevs) + ([exp_sev] if dangerous else [])
    # None propagates: an unread over-privilege stage makes the whole row
    # unmeasured rather than contributing a zero to a sum that then reads as
    # a clean count.
    overpriv_count = overpriv.get("overprivileged")
    info_signals = None if overpriv_count is None else overpriv_count + (1 if dangerous else 0)
    inst_scan = instructions.get("scan", {})
    steering = bool(instructions.get("is_finding"))
    inst_sev = str(inst_scan.get("severity", Severity.INFO.value))
    elev_sevs = (
        list(trust_sevs)
        + ([att_sev] if unauth else [])
        + ([exp_sev] if dangerous else [])
        + ([inst_sev] if steering else [])
    )
    shadowing_count = trust.get("shadowing")
    elev_signals = (
        None
        if shadowing_count is None
        else shadowing_count
        + (1 if unauth else 0)
        + (1 if dangerous else 0)
        + (1 if steering else 0)
    )

    lines: list[str] = []
    lines.append(f"# MCP Red-Team Scorecard - `{result.get('endpoint', '?')}`")
    lines.append("")
    lines.append(f"- transport: {result.get('transport', '?')}")
    lines.append(f"- connected: {result.get('connected', False)}")
    surface_errors: dict[str, Any] = result.get("surface_errors") or {}
    if "tools" in surface_errors:
        # The count is the length of a list that never arrived.
        lines.append(f"- tools probed: not read ({surface_errors['tools']})")
    else:
        lines.append(f"- tools probed: {result.get('tools', 0)}")
    lines.append("")
    lines.append("## STRIDE")
    lines.append("")
    lines.append("| Category | Severity | Signals | Source |")
    lines.append("| --- | --- | --- | --- |")
    lines.append(
        _row(
            "Spoofing",
            att_sev if unauth else Severity.INFO.value,
            1 if unauth else 0,
            "unauthenticated endpoint / self-asserted identity (attestation)",
        )
    )
    lines.append(
        _row(
            "Tampering",
            _either(poisoning, _worst(poison_sevs)),
            poisoning.get("suspicious"),
            "poisoned / mutable tool metadata (poisoning)",
        )
    )
    lines.append(
        _row(
            "Repudiation",
            Severity.INFO.value,
            0,
            "MCP does not sign or attest invocations; not observable from a scan",
        )
    )
    lines.append(
        _row(
            "Information disclosure",
            _either(overpriv, _worst(info_sevs)),
            info_signals,
            "over-privileged exfil capability combinations (over-privilege/exposure)",
        )
    )
    lines.append(
        _row(
            "Denial of service",
            exp_sev if exposed else Severity.INFO.value,
            1 if exposed else 0,
            "network reachability / rebinding surface (exposure)",
        )
    )
    lines.append(
        _row(
            "Elevation of privilege",
            # Mixed row: attestation and instructions are read whatever the
            # tool list did, so their severities stand. Only when trust is the
            # sole possible contributor does the row assert nothing.
            "n/a" if _unmeasured_stage(trust) and not elev_sevs else _worst(elev_sevs),
            elev_signals,
            "cross-server shadowing / confused-deputy + unauth invoke, "
            "server instructions summoning an unadvertised tool "
            "(trust/attestation/instructions)"
            + (" -- tool surface not read" if _unmeasured_stage(trust) else ""),
        )
    )
    lines.append("")
    return "\n".join(lines)

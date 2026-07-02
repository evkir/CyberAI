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
* Elevation       - cross-server shadowing / confused-deputy + unauth invoke
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


def _row(category: str, severity: str, signals: int, source: str) -> str:
    return f"| {category} | {severity} | {signals} | {source} |"


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
    info_signals = overpriv.get("overprivileged", 0) + (1 if dangerous else 0)
    elev_sevs = list(trust_sevs) + ([att_sev] if unauth else []) + ([exp_sev] if dangerous else [])
    elev_signals = trust.get("shadowing", 0) + (1 if unauth else 0) + (1 if dangerous else 0)

    lines: list[str] = []
    lines.append(f"# MCP Red-Team Scorecard - `{result.get('endpoint', '?')}`")
    lines.append("")
    lines.append(f"- transport: {result.get('transport', '?')}")
    lines.append(f"- connected: {result.get('connected', False)}")
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
            _worst(poison_sevs),
            poisoning.get("suspicious", 0),
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
            _worst(info_sevs),
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
            _worst(elev_sevs),
            elev_signals,
            "cross-server shadowing / confused-deputy + unauth invoke (trust/attestation)",
        )
    )
    lines.append("")
    return "\n".join(lines)

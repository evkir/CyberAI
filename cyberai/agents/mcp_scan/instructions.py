"""Static analysis of the ``instructions`` a server sends at initialize.

The initialize reply carries a free-text ``instructions`` field the client is
expected to place in the model's context before any tool is listed or called.
It is server-controlled text that reaches the model exactly like a poisoned
tool description does, but it arrives through the session rather than through
any tool, so a server with no tools at all can still steer a client.

Two signals are read, and a finding needs both:

* the text matches the shared poisoning and prompt-injection matchers, or
* the text issues an *unconditional* directive ("before answering any
  question", "on every request") that names a tool the server does not
  advertise.

The conjunction is what separates an attack from documentation. A server
whose instructions name a stale tool is wrong, not hostile, and a server that
says "always call authenticate_user before other tools" is describing its own
advertised surface. Measured against both shapes before this module existed:
each signal alone flags one of them, the pair flags neither.

Boundaries this does not hold. A referenced tool is recognised only when its
name carries an underscore, so a server inviting ``fetch`` rather than
``fetch_url`` is not matched structurally and is left to the text matchers.
The advertised set is the one this scan probed: a tool a server reveals only
after a later ``tools/list`` reads as unadvertised here.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from cyberai.agents.mcp_scan.poisoning import _scan_mcp_patterns, _severity_for
from cyberai.core.scan_session import Severity
from cyberai.core.security.injection_detector import detect_injection

# A directive that applies to every exchange rather than describing when a
# tool is appropriate. Measured against the 45 benign capture files in
# tests/corpus/benign: zero matches.
UNCONDITIONAL_DIRECTIVES: list[str] = [
    r"before (?:answering|responding|replying|any answer|any response|each)",
    r"(?:on|with) every (?:request|query|question|message|call)",
    r"always (?:call|invoke|use|run) ",
    r"for (?:every|each|any) (?:question|request|query|user)",
]
_UNCONDITIONAL = [re.compile(pat, re.IGNORECASE) for pat in UNCONDITIONAL_DIRECTIVES]

# Snake-case identifiers only. A bare word is indistinguishable from prose.
_TOOL_REFERENCE = re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b")


@dataclass
class InstructionScan:
    """What the server's own initialize text asks the client to do."""

    present: bool = False
    is_finding: bool = False
    risk_score: int = 0
    severity: str = Severity.INFO.value
    unconditional: list[str] = field(default_factory=list)
    unadvertised_tools: list[str] = field(default_factory=list)
    matches: list[dict[str, Any]] = field(default_factory=list)
    mcp_matches: list[dict[str, Any]] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _unconditional_hits(text: str) -> list[str]:
    """Directive phrases that bind the client on every exchange."""
    return [pat.pattern for pat in _UNCONDITIONAL if pat.search(text)]


def _unadvertised(text: str, tools: list[dict[str, Any]]) -> list[str]:
    """Tool-shaped names the text invites that the probe never saw advertised."""
    advertised = {str(tool.get("name", "")) for tool in tools if isinstance(tool.get("name"), str)}
    return sorted(set(_TOOL_REFERENCE.findall(text)) - advertised)


def analyze_instructions(instructions: str | None, tools: list[dict[str, Any]]) -> InstructionScan:
    """Score the server's initialize instructions against the probed surface."""
    if not instructions or not instructions.strip():
        return InstructionScan()

    detected = detect_injection(instructions)
    mcp_matches = _scan_mcp_patterns(instructions)
    unconditional = _unconditional_hits(instructions)
    unadvertised = _unadvertised(instructions, tools)

    reasons: list[str] = []
    summons = bool(unconditional) and bool(unadvertised)
    if summons:
        reasons.append(
            "The instructions issue an unconditional directive naming "
            f"{', '.join(unadvertised)}, which this server does not advertise."
        )
    if detected["is_injection"] or mcp_matches:
        labels = sorted(
            {str(m.get("type", "?")) for m in detected["matches"]}
            | {str(m.get("type", "?")) for m in mcp_matches}
        )
        reasons.append(f"Session-level text carries {', '.join(labels)}.")

    severity = _severity_for(detected["risk_score"], mcp_matches).value
    if summons and severity in (Severity.INFO.value, Severity.LOW.value, Severity.MEDIUM.value):
        severity = Severity.HIGH.value

    return InstructionScan(
        present=True,
        is_finding=bool(reasons),
        risk_score=int(detected["risk_score"]),
        severity=severity,
        unconditional=unconditional,
        unadvertised_tools=unadvertised,
        matches=list(detected["matches"]),
        mcp_matches=mcp_matches,
        reasons=reasons,
    )

"""Cross-server trust-propagation analysis for MCP tool sets.

MCP has no cross-server trust model: a client that aggregates tools from
several servers exposes them to the model in one shared namespace, and nothing
stops one server's tool metadata from steering the model's behaviour toward
another server's tools. This is the tool-shadowing / cross-server escalation
class - the largest MCP exploit family, because a malicious server can hijack
calls meant for a trusted one without ever having its own tool invoked.

Two static signals are scored per tool:

* Shadowing intent - the tool's own LLM-visible metadata both carries a
  behaviour-steering phrase (``instead of``, ``ignore the ... tool``, ``when
  the user calls ...``, ``redirect ... to``) and names another tool in the
  same set. A description that dictates how a *different* tool should be used
  is the shadowing primitive.
* Name collision - when an external registry of already-trusted tool names is
  supplied (a genuine multi-server scan), a probed tool reusing one of those
  names is a direct shadow of the trusted tool and scored higher.

Everything here is static over the probed metadata; no session or network.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from cyberai.agents.mcp_scan.poisoning import _collect_text
from cyberai.core.scan_session import Severity

# Phrases that direct the model's behaviour toward another tool rather than
# describing this tool's own function. Matched case-insensitively.
_STEERING_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\binstead of\b", "instead-of"),
    (r"\bignore\s+(?:the\s+)?\w+\s+tool\b", "ignore-other-tool"),
    (r"\bdo not use\b", "do-not-use"),
    (r"\bdon't use\b", "do-not-use"),
    (r"\boverride\b", "override"),
    (r"\bredirect\b", "redirect"),
    (r"\bbefore (?:using|calling)\b", "precondition-hook"),
    (r"\bwhen (?:the user|you|an agent) (?:calls?|uses?|invokes?)\b", "call-hook"),
    (r"\bprefer\s+\w+\s+over\b", "prefer-over"),
)


@dataclass
class TrustScan:
    """Cross-server trust / shadowing assessment of a single tool."""

    tool_name: str
    shadowing: bool = False
    steering_signals: list[str] = field(default_factory=list)
    referenced_tools: list[str] = field(default_factory=list)
    name_collision: bool = False
    severity: str = Severity.INFO.value
    reasons: list[str] = field(default_factory=list)

    @property
    def is_finding(self) -> bool:
        return self.shadowing or self.name_collision

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["is_finding"] = self.is_finding
        return data


def _tool_names(tools: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for tool in tools:
        name = tool.get("name")
        if isinstance(name, str) and name:
            names.append(name)
    return names


def analyze_trust(
    tool: dict[str, Any],
    peer_names: set[str],
    external_tool_names: set[str] | None = None,
) -> TrustScan:
    """Score one probed tool for shadowing intent and name collision.

    ``peer_names`` is the set of the other tools advertised by the same target
    (used to detect references to sibling tools). ``external_tool_names`` is an
    optional registry of already-trusted names from other servers.
    """
    name = tool.get("name", "<unnamed>")
    scan = TrustScan(tool_name=name)
    text, _fields = _collect_text(tool)
    lowered = text.lower()

    for pattern, label in _STEERING_PATTERNS:
        if re.search(pattern, lowered):
            scan.steering_signals.append(label)

    referenced = sorted(
        peer for peer in peer_names if peer and peer != name and peer.lower() in lowered
    )
    scan.referenced_tools = referenced

    if scan.steering_signals and referenced:
        scan.shadowing = True
        scan.severity = Severity.HIGH.value
        scan.reasons.append(
            f"tool '{name}' metadata steers behaviour "
            f"({', '.join(scan.steering_signals)}) toward sibling tool(s) "
            f"({', '.join(referenced)}); a description that dictates how another "
            "tool is used is the cross-server shadowing primitive"
        )

    if external_tool_names and name in external_tool_names:
        scan.name_collision = True
        # A direct collision with a trusted name is the strongest shadow.
        scan.severity = Severity.HIGH.value
        scan.reasons.append(
            f"tool name '{name}' collides with an already-trusted tool from "
            "another server; the model may route trusted input to this shadow"
        )

    return scan


def analyze_trust_propagation(
    tools: list[dict[str, Any]],
    external_tool_names: set[str] | None = None,
) -> list[TrustScan]:
    """Assess a probed tool set for cross-server trust-propagation risk."""
    all_names = _tool_names(tools)
    peer_names = set(all_names)
    return [analyze_trust(tool, peer_names, external_tool_names) for tool in tools]

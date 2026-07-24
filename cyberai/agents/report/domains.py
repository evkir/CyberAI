"""Finding-domain classification for the unified report.

CyberAI runs three families of agents against a single session — the
network pentest pipeline, the offensive MCP/LLM red-team, and the Web3
audit — and all of them append to the same finding list. A report grouped
only by severity therefore hides which attack surface a finding came from.
The domain is derived from the finding's originating agent; anything
unrecognised falls back to the network pipeline the report was built for,
so new agents degrade into a correct-if-coarse bucket rather than vanish.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

NETWORK = "Network"
MCP = "MCP"
WEB3 = "Web3"

# Rendering order — network first, it is the default pipeline.
DOMAIN_ORDER = (NETWORK, MCP, WEB3)

_AGENT_DOMAIN: Dict[str, str] = {
    "mcp_scan": MCP,
    "web3": WEB3,
}


def domain_for(finding: Any) -> str:
    """Return the report domain a finding belongs to."""
    agent = getattr(finding, "agent", None)
    if agent is None and isinstance(finding, dict):
        agent = finding.get("agent")
    return _AGENT_DOMAIN.get(str(agent or "").strip().lower(), NETWORK)


def group_by_domain(findings: Iterable[Any]) -> Dict[str, List[Any]]:
    """Group findings by domain, preserving order and dropping empty domains."""
    buckets: Dict[str, List[Any]] = {domain: [] for domain in DOMAIN_ORDER}
    for finding in findings:
        buckets[domain_for(finding)].append(finding)
    return {domain: items for domain, items in buckets.items() if items}

"""CyberAI MCP tool registry.

Each entry maps a tool name to its MCP spec (description + JSON Schema) and a
sync handler. Recon tools land in commit 2, intel tools in commit 3.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, TypedDict


class ToolSpec(TypedDict):
    description: str
    inputSchema: Dict[str, Any]
    handler: Callable[..., Any]


# Populated by register() calls below; recon/intel tools added in later commits.
TOOL_REGISTRY: Dict[str, ToolSpec] = {}


def register(
    name: str,
    description: str,
    input_schema: Dict[str, Any],
    handler: Callable[..., Any],
) -> None:
    """Register a tool in the global MCP registry."""
    TOOL_REGISTRY[name] = ToolSpec(
        description=description,
        inputSchema=input_schema,
        handler=handler,
    )


# ── recon tools (day 25 commit 2) ─────────────────────────────────────

from cyberai.agents.recon.dns_tool import (  # noqa: E402
    detect_subdomains,
    run_dns,
    run_whois,
)
from cyberai.agents.recon.nmap_tool import run_nmap  # noqa: E402

register(
    name="nmap_scan",
    description="Port-scan a target host with nmap and return parsed results.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host or IP to scan"},
            "flags": {
                "type": "string",
                "description": "nmap flags (whitelisted)",
                "default": "-sV -T4 --top-ports 1000",
            },
        },
        "required": ["target"],
    },
    handler=run_nmap,
)

register(
    name="dns_enum",
    description="Resolve DNS records (A/AAAA/MX/NS/TXT) for a domain.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Domain to resolve"},
        },
        "required": ["target"],
    },
    handler=run_dns,
)

register(
    name="whois_lookup",
    description="WHOIS lookup for domain registration info.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Domain to query"},
        },
        "required": ["target"],
    },
    handler=run_whois,
)


def _subdomain_handler(target: str, wordlist: list[str] | None = None) -> dict:
    """Adapt detect_subdomains to MCP (wordlist optional)."""
    return detect_subdomains(target, wordlist)


register(
    name="subdomain_enum",
    description="Enumerate subdomains for a domain via a wordlist probe.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Base domain"},
            "wordlist": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional subdomain candidates",
            },
        },
        "required": ["target"],
    },
    handler=_subdomain_handler,
)

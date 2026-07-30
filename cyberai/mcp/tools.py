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


# ── recon tools ───────────────────────────────────────────────────────

from cyberai.agents.recon.dns_tool import (  # noqa: E402
    run_dns,
    run_whois,
)
from cyberai.agents.recon.subdomain_enum import enumerate_subdomains  # noqa: E402
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
    """Adapt enumerate_subdomains to MCP (wordlist optional)."""
    return enumerate_subdomains(target, wordlist)


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


# ── intel tools ───────────────────────────────────────────────────────

from cyberai.agents.intel.epss_client import get_epss_scores  # noqa: E402
from cyberai.agents.intel.nvd_client import get_cve, search_cves  # noqa: E402

register(
    name="cve_search",
    description="Search the NVD for CVEs matching a keyword, optionally by severity.",
    input_schema={
        "type": "object",
        "properties": {
            "keyword": {"type": "string", "description": "Search term"},
            "max_results": {
                "type": "integer",
                "description": "Max CVEs to return",
                "default": 10,
            },
            "severity": {
                "type": "string",
                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                "description": "Filter by CVSS v3 severity",
            },
        },
        "required": ["keyword"],
    },
    handler=search_cves,
)

register(
    name="cve_detail",
    description="Fetch a single CVE by id (e.g. CVE-2021-44228).",
    input_schema={
        "type": "object",
        "properties": {
            "cve_id": {"type": "string", "description": "CVE identifier"},
        },
        "required": ["cve_id"],
    },
    handler=get_cve,
)

register(
    name="epss_score",
    description="Fetch EPSS exploitation-probability scores for CVE ids.",
    input_schema={
        "type": "object",
        "properties": {
            "cve_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of CVE identifiers",
            },
        },
        "required": ["cve_ids"],
    },
    handler=get_epss_scores,
)


# ── mcp red-team tool ─────────────────────────────────────────────────
#
# Meta capability: the CyberAI MCP server exposes an offensive tool that scans
# *other* MCP servers / LLM endpoints. The handler runs a one-shot scan in a
# throwaway session and returns the full result (capability inventory plus the
# poisoning / over-privilege / exposure / attestation / trust analyses and the
# STRIDE scorecard).


def run_mcp_scan(endpoint: str, transport: str | None = None) -> Dict[str, Any]:
    """Scan a target MCP server or LLM endpoint; return the full result dict.

    Imports are deferred so importing the tool registry stays cheap. The target
    is scanned in a fresh, throwaway ScanSession.
    """
    from cyberai.agents.mcp_scan import MCPScanAgent
    from cyberai.core.config import CyberAIConfig
    from cyberai.core.llm_client import LLMClient
    from cyberai.core.logger import AuditLogger
    from cyberai.core.scan_session import ScanSession

    config = CyberAIConfig.from_env()
    session = ScanSession(target=endpoint)
    llm = LLMClient(config.llm)
    audit = AuditLogger(session.session_id, output_dir=config.output_dir)
    agent = MCPScanAgent(config, session, llm, audit)
    context = {"transport": transport} if transport else None
    return agent.run(endpoint, context=context)


register(
    name="mcp_scan",
    description=(
        "Offensively scan a target MCP server or LLM endpoint: inventory its "
        "tools/prompts/resources and analyze for tool poisoning, over-privilege, "
        "network exposure, weak attestation, and cross-server trust risks."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "MCP endpoint: stdio command, http(s):// or sse:// URL",
            },
            "transport": {
                "type": "string",
                "enum": ["stdio", "sse", "http"],
                "description": "Force transport instead of inferring from the endpoint",
            },
        },
        "required": ["endpoint"],
    },
    handler=run_mcp_scan,
)

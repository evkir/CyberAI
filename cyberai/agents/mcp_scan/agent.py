"""MCPScanAgent — offensive reconnaissance of MCP servers and LLM endpoints.

Standalone agent (not in the recon -> intel -> exploit -> report network
pipeline): the target is an MCP endpoint (stdio command or HTTP/SSE URL) rather
than a network host. This skeleton connects to the target and inventories its
advertised capability surface; metadata analysis (tool-poisoning,
over-privilege) and live injection are layered on in later commits.

The underlying probe is async; this agent is driven synchronously from the CLI,
so the probe is run via ``asyncio.run`` inside the tool handler.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from rich.console import Console

from cyberai.core.base_agent import BaseAgent, Tool
from cyberai.mcp.client_probe import probe

console = Console()


class MCPScanAgent(BaseAgent):
    """Inventory and (later) attack a target MCP server or LLM endpoint."""

    AGENT_NAME = "mcp_scan"
    ROLE = "MCP/LLM Red-Team Operator"

    def _register_tools(self) -> None:
        self.register_tool(
            Tool(
                name="mcp_probe",
                description="Connect to a target MCP endpoint and inventory its surface",
                func=self._probe,
                parameters={"endpoint": "str", "transport": "str"},
            )
        )

    def _probe(self, endpoint: str, transport: Optional[str] = None) -> dict[str, Any]:
        """Run the async probe to completion and return a plain dict."""
        result = asyncio.run(probe(endpoint, transport))  # type: ignore[arg-type]
        return result.to_dict()

    def run(self, target: str, context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Scan a target MCP endpoint.

        ``target`` is an MCP endpoint: a stdio command line, an ``http(s)://``
        URL (streamable-HTTP), or an ``sse://`` URL. An explicit transport may
        be supplied via ``context["transport"]``. This skeleton records the
        capability inventory; findings are produced by later analysis stages.
        """
        transport = (context or {}).get("transport")
        self._log(f"MCP scan target: {target}")
        probe_result = self.call_tool("mcp_probe", endpoint=target, transport=transport)
        summary = {
            "endpoint": target,
            "transport": probe_result["transport"],
            "connected": probe_result["connected"],
            "tools": len(probe_result["tools"]),
            "prompts": len(probe_result["prompts"]),
            "resources": len(probe_result["resources"]),
            "error": probe_result["error"],
        }
        result: dict[str, Any] = {**summary, "probe": probe_result}
        self.kb.set("mcp_scan", result, agent=self.AGENT_NAME)
        self._log("MCP scan complete", summary)
        return result

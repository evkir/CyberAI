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

from cyberai.agents.mcp_scan.attestation import assess_attestation
from cyberai.agents.mcp_scan.exposure import assess_exposure
from cyberai.agents.mcp_scan.overprivilege import analyze_overprivilege
from cyberai.agents.mcp_scan.poisoning import analyze_tools
from cyberai.agents.mcp_scan.scorecard import build_mcp_scorecard
from cyberai.agents.mcp_scan.trust import analyze_trust_propagation
from cyberai.core.base_agent import BaseAgent, Tool
from cyberai.core.scan_session import Severity
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
        poisoning = self._analyze_poisoning(target, probe_result["tools"])
        overprivilege = self._analyze_overprivilege(target, probe_result["tools"])
        exposure = self._assess_exposure(target, probe_result["transport"], probe_result["tools"])
        attestation = self._assess_attestation(
            target, probe_result["transport"], probe_result["connected"], probe_result["error"]
        )
        trust = self._analyze_trust(target, probe_result["tools"])
        mst = self._run_mst(target, probe_result["transport"], context)
        result: dict[str, Any] = {
            **summary,
            "poisoning": poisoning,
            "overprivilege": overprivilege,
            "exposure": exposure,
            "attestation": attestation,
            "trust": trust,
            "mst": mst,
            "probe": probe_result,
        }
        result["scorecard"] = build_mcp_scorecard(result)
        self.kb.set("mcp_scan", result, agent=self.AGENT_NAME)
        self._log(
            "MCP scan complete",
            {
                **summary,
                "poisoned_tools": poisoning["suspicious"],
                "overprivileged_tools": overprivilege["overprivileged"],
                "exposed": exposure["exposed"],
                "unauthenticated": attestation["unauthenticated"],
                "shadowing_tools": trust["shadowing"],
                "mst_findings": len(mst),
            },
        )
        return result

    def _run_mst(
        self,
        target: str,
        transport: Optional[str],
        context: Optional[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Optionally run the MST low-level MCP fuzzer and record its findings.

        Off by default; enabled via ``context["mst_fuzz"]``. Degrades to [] when
        MST is not installed. Non-lab targets are fuzzed only when scope is
        confirmed (``context["confirm_scope"]`` or a session authorized scope).
        """
        ctx = context or {}
        if not ctx.get("mst_fuzz"):
            return []
        from cyberai.agents.mcp_scan.mst_bridge import MSTBridge

        bridge = MSTBridge()
        if not bridge.available:
            self._log("MST not available - skipping low-level MCP fuzzing")
            return []
        confirm = bool(ctx.get("confirm_scope")) or bool(self.session.authorized_scope)
        findings = bridge.fuzz(target, transport, confirm_scope=confirm)
        for finding in findings:
            self.session.add_finding(
                severity=finding.severity,
                title=f"MCP low-level fuzzing: {finding.check}",
                description=finding.detail,
                agent=self.AGENT_NAME,
                target=target,
            )
        self._log("MST low-level fuzzing complete", {"findings": len(findings)})
        return [f.to_dict() for f in findings]

    def _analyze_poisoning(self, target: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
        """Run static poisoning analysis on probed tools and record findings.

        Each suspicious tool becomes a Finding on the session; clean tools are
        not recorded. The returned summary is attached to the scan result.
        """
        scans = analyze_tools(tools)
        suspicious = [scan for scan in scans if scan.is_suspicious]
        for scan in suspicious:
            labels = sorted(
                {m["type"] for m in scan.matches} | {m["type"] for m in scan.mcp_matches}
            )
            self.session.add_finding(
                severity=Severity(scan.severity),
                title=f"MCP tool poisoning in '{scan.tool_name}'",
                description=(
                    f"Tool '{scan.tool_name}' carries suspicious metadata "
                    f"({', '.join(labels)}) in fields: {', '.join(scan.scanned_fields)}. "
                    "An LLM reading this metadata could be steered before any tool runs."
                ),
                agent=self.AGENT_NAME,
                target=target,
                evidence=[scan.to_dict()],
            )
        return {
            "scanned": len(scans),
            "suspicious": len(suspicious),
            "tools": [scan.to_dict() for scan in suspicious],
        }

    def _analyze_overprivilege(self, target: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
        """Score probed tools for over-privileged capability combinations.

        Tools assessed at MEDIUM severity or above become Findings on the
        session; LOW/INFO tools are kept only in the returned inventory so the
        report is not flooded with benign single-capability tools.
        """
        scans = analyze_overprivilege(tools)
        flagged = [scan for scan in scans if scan.is_overprivileged]
        for scan in flagged:
            self.session.add_finding(
                severity=Severity(scan.severity),
                title=f"Over-privileged MCP tool '{scan.tool_name}'",
                description=(
                    f"Tool '{scan.tool_name}' exposes capabilities "
                    f"({', '.join(scan.capabilities)}). {' '.join(scan.reasons)}"
                ),
                agent=self.AGENT_NAME,
                target=target,
                evidence=[scan.to_dict()],
            )
        return {
            "scanned": len(scans),
            "overprivileged": len(flagged),
            "tools": [scan.to_dict() for scan in flagged],
        }

    def _assess_exposure(
        self, target: str, transport: str, tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Assess DNS-rebinding / network exposure of the target endpoint.

        Unlike poisoning and over-privilege (per-tool), exposure is a property
        of the server endpoint, so at most one Finding is recorded. stdio
        endpoints are not network-reachable and produce no Finding.
        """
        scan = assess_exposure(target, transport, tools)
        if scan.is_exposed:
            self.session.add_finding(
                severity=Severity(scan.severity),
                title=f"MCP endpoint exposed to DNS rebinding ({target})",
                description=(
                    f"Endpoint '{target}' over {transport} is reachable by DNS "
                    f"rebinding. {' '.join(scan.reasons)}"
                ),
                agent=self.AGENT_NAME,
                target=target,
                evidence=[scan.to_dict()],
            )
        return {"exposed": scan.is_exposed, "scan": scan.to_dict()}

    def _assess_attestation(
        self, target: str, transport: str, connected: bool, error: str | None
    ) -> dict[str, Any]:
        """Assess the transport-authentication posture of the target endpoint.

        Like exposure this is an endpoint property, so at most one Finding is
        recorded, and only when the endpoint accepted an unauthenticated
        session. stdio and undetermined remote endpoints produce no Finding.
        """
        scan = assess_attestation(target, transport, connected, error)
        if scan.is_finding:
            self.session.add_finding(
                severity=Severity(scan.severity),
                title=f"Unauthenticated MCP endpoint ({target})",
                description=(
                    f"Endpoint '{target}' over {transport} accepted an MCP session "
                    f"with no credential. {' '.join(scan.reasons)}"
                ),
                agent=self.AGENT_NAME,
                target=target,
                evidence=[scan.to_dict()],
            )
        return {
            "unauthenticated": scan.unauthenticated,
            "scan": scan.to_dict(),
        }

    def _analyze_trust(self, target: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
        """Score probed tools for cross-server trust-propagation / shadowing.

        Each tool whose metadata steers behaviour toward a sibling tool, or
        whose name collides with a trusted tool, becomes a Finding. Clean tools
        stay only in the returned inventory.
        """
        scans = analyze_trust_propagation(tools)
        flagged = [scan for scan in scans if scan.is_finding]
        for scan in flagged:
            self.session.add_finding(
                severity=Severity(scan.severity),
                title=f"MCP tool-shadowing risk in '{scan.tool_name}'",
                description=(
                    f"Tool '{scan.tool_name}' presents cross-server "
                    f"trust-propagation risk. {' '.join(scan.reasons)}"
                ),
                agent=self.AGENT_NAME,
                target=target,
                evidence=[scan.to_dict()],
            )
        return {
            "scanned": len(scans),
            "shadowing": len(flagged),
            "tools": [scan.to_dict() for scan in flagged],
        }

"""MCPScanAgent — offensive reconnaissance of MCP servers and LLM endpoints.

Standalone agent (not in the recon -> intel -> exploit -> report network
pipeline): the target is an MCP endpoint (stdio command or HTTP/SSE URL) rather
than a network host. It connects to the target, inventories its advertised
capability surface, and runs the static red-team stages over that surface:
tool-poisoning, over-privilege, cross-server trust, transport attestation,
network exposure, authorization metadata, and an optional MST low-level
fuzzer, folded into an OWASP-MCP / MITRE-ATLAS report and a STRIDE scorecard.

The underlying probe is async; this agent is driven synchronously from the CLI,
so the probe is run via ``asyncio.run`` inside the tool handler.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from rich.console import Console

from cyberai.agents.mcp_scan.attestation import assess_attestation
from cyberai.agents.mcp_scan.exposure import assess_exposure
from cyberai.agents.mcp_scan.instructions import analyze_instructions
from cyberai.agents.mcp_scan.overprivilege import analyze_overprivilege
from cyberai.agents.mcp_scan.poisoning import analyze_tools
from cyberai.agents.mcp_scan.scorecard import build_mcp_scorecard
from cyberai.agents.mcp_scan.trust import analyze_trust_propagation
from cyberai.core.base_agent import BaseAgent, Tool
from cyberai.core.scan_session import Severity
from cyberai.mcp.auth_metadata import probe_auth_metadata
from cyberai.mcp.client_probe import MCPProbeResult, probe


def _run_coro(coro: Any) -> Any:
    """Run a coroutine whether or not a loop is already turning.

    This agent is driven both from the CLI (no loop) and from inside the MCP
    server's own request handler (loop running). asyncio.run raises in the
    second case, and the handler reports that as the scan result -- an error
    payload where a capability dump belongs. The probe opens its own streams,
    so it gets a private loop on a worker thread rather than joining the
    server's.
    """
    from concurrent.futures import ThreadPoolExecutor

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


console = Console()


def _unmeasured(reason: str) -> dict[str, Any]:
    """The stage summary for a tool surface that was never read.

    Distinct from a clean result by the ``measured`` key, not by the counts: a
    stage that saw nothing and a stage that saw nothing wrong both report an
    empty tool list, so every consumer that turns this into a verdict has to
    read the flag.

    The per-stage count keys are present and ``None`` rather than absent. Every
    stage summary is read positionally by the scan log and the report, so
    dropping a key turns an unread surface into a KeyError at the end of a
    scan; filling it with ``0`` would state a measurement instead. ``None`` is
    the only value that keeps the shape and makes no claim.
    """
    return {
        "measured": False,
        "unread": reason,
        "scanned": None,
        "suspicious": None,
        "overprivileged": None,
        "shadowing": None,
        "tools": [],
    }


class MCPScanAgent(BaseAgent):
    """Inventory and statically red-team a target MCP server or LLM endpoint."""

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
        # _run_coro is deliberately untyped -- it takes any coroutine -- so the
        # probe's own result type is what says this is a dict, not the runner.
        result: MCPProbeResult = _run_coro(probe(endpoint, transport))  # type: ignore[arg-type]
        return result.to_dict()

    def run(self, target: str, context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Scan a target MCP endpoint.

        ``target`` is an MCP endpoint: a stdio command line, an ``http(s)://``
        URL (streamable-HTTP), or an ``sse://`` URL. An explicit transport may
        be supplied via ``context["transport"]``. The capability inventory and
        the findings from each analysis stage are collected into the returned
        dict.
        """
        transport = (context or {}).get("transport")
        self._log(f"MCP scan target: {target}")
        probe_result = self.call_tool("mcp_probe", endpoint=target, transport=transport)
        summary = {
            "endpoint": target,
            "transport": probe_result["transport"],
            "connected": probe_result["connected"],
            "protocol_version": probe_result["protocol_version"],
            "tools": len(probe_result["tools"]),
            "prompts": len(probe_result["prompts"]),
            "resources": len(probe_result["resources"]),
            "error": probe_result["error"],
            # Counts above are lengths of whatever arrived. A capability whose
            # read failed contributes a zero that means "not read", so the
            # reasons travel with the counts rather than being inferred later.
            "surface_errors": probe_result.get("surface_errors") or {},
        }
        # An empty tool list is only a measurement when the server answered it.
        # The probe records why a capability read came back empty; when it did
        # not complete, every stage below would be scoring a surface nobody
        # saw, so each reports the surface as unmeasured instead of clean.
        surface_errors: dict[str, str] = probe_result.get("surface_errors") or {}
        tools_unread = surface_errors.get("tools")
        poisoning = self._analyze_poisoning(target, probe_result["tools"], tools_unread)
        overprivilege = self._analyze_overprivilege(target, probe_result["tools"], tools_unread)
        exposure = self._assess_exposure(
            target, probe_result["transport"], probe_result["tools"], tools_unread
        )
        attestation = self._assess_attestation(
            target,
            probe_result["transport"],
            probe_result["connected"],
            probe_result["error"],
            probe_result["capabilities"],
        )
        trust = self._analyze_trust(target, probe_result["tools"], tools_unread)
        # Not passed tools_unread: the summons rule already reads an empty
        # advertised set correctly. Gating it on a non-empty tool list was
        # measured and rejected in instructions.py -- it drops a summons from a
        # server that advertises nothing -- and sentence scope is what keeps an
        # unread list from convicting a server of documenting itself.
        instructions = self._analyze_instructions(
            target, probe_result["instructions"], probe_result["tools"]
        )
        auth_metadata = probe_auth_metadata(target, probe_result["transport"]).to_dict()
        mst = self._run_mst(target, probe_result["transport"], context)
        result: dict[str, Any] = {
            **summary,
            "poisoning": poisoning,
            "overprivilege": overprivilege,
            "exposure": exposure,
            "attestation": attestation,
            "trust": trust,
            "instructions": instructions,
            "auth_metadata": auth_metadata,
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
                "steering_instructions": instructions["is_finding"],
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

    def _analyze_poisoning(
        self, target: str, tools: list[dict[str, Any]], unread: str | None = None
    ) -> dict[str, Any]:
        """Run static poisoning analysis on probed tools and record findings.

        Each suspicious tool becomes a Finding on the session; clean tools are
        not recorded. The returned summary is attached to the scan result. When
        ``unread`` is set the tool list never arrived, and a stage that reports
        zero suspicious tools would be making a claim about an unseen surface.
        """
        if unread is not None:
            return _unmeasured(unread)
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

    def _analyze_overprivilege(
        self, target: str, tools: list[dict[str, Any]], unread: str | None = None
    ) -> dict[str, Any]:
        """Score probed tools for over-privileged capability combinations.

        Tools assessed at MEDIUM severity or above become Findings on the
        session; LOW/INFO tools are kept only in the returned inventory so the
        report is not flooded with benign single-capability tools. An unread
        surface is reported as such rather than as zero over-privileged tools.
        """
        if unread is not None:
            return _unmeasured(unread)
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
        self,
        target: str,
        transport: str,
        tools: list[dict[str, Any]],
        unread: str | None = None,
    ) -> dict[str, Any]:
        """Assess DNS-rebinding / network exposure of the target endpoint.

        Unlike poisoning and over-privilege (per-tool), exposure is a property
        of the server endpoint, so at most one Finding is recorded. stdio
        endpoints are not network-reachable and produce no Finding.

        This stage keeps running on an unread surface, unlike the per-tool
        ones. A non-loopback HTTP bind is a rebinding target whatever it
        serves, so suppressing the stage would lose a real finding; the tool
        list only escalates the severity. The result is therefore marked
        unmeasured rather than withheld: the risk may be worse than stated,
        never better.
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
        summary: dict[str, Any] = {"exposed": scan.is_exposed, "scan": scan.to_dict()}
        if unread is not None:
            # The endpoint verdict stands; the escalation half did not run.
            summary["measured"] = False
            summary["unread"] = unread
        return summary

    def _assess_attestation(
        self,
        target: str,
        transport: str,
        connected: bool,
        error: str | None,
        capabilities: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Assess the transport-authentication posture of the target endpoint.

        Like exposure this is an endpoint property, so at most one Finding is
        recorded, and only when the endpoint accepted an unauthenticated
        session. stdio and undetermined remote endpoints produce no Finding.
        """
        scan = assess_attestation(target, transport, connected, error, capabilities)
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

    def _analyze_instructions(
        self, target: str, instructions: str | None, tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Score the free text the server sends with its initialize reply.

        Like exposure and attestation this is a property of the endpoint, not
        of any tool, so at most one Finding is recorded. A server that sends no
        instructions is reported absent rather than clean: the two are
        different answers and INFO alone cannot tell them apart.
        """
        scan = analyze_instructions(instructions, tools)
        if scan.is_finding:
            self.session.add_finding(
                severity=Severity(scan.severity),
                title=f"MCP server instructions steer the client ({target})",
                description=(
                    f"The initialize reply from '{target}' carries instructions the "
                    f"client places in model context before any tool is listed. "
                    f"{' '.join(scan.reasons)}"
                ),
                agent=self.AGENT_NAME,
                target=target,
                evidence=[scan.to_dict()],
            )
        return {
            "present": scan.present,
            "is_finding": scan.is_finding,
            "scan": scan.to_dict(),
        }

    def _analyze_trust(
        self, target: str, tools: list[dict[str, Any]], unread: str | None = None
    ) -> dict[str, Any]:
        """Score probed tools for cross-server trust-propagation / shadowing.

        Each tool whose metadata steers behaviour toward a sibling tool, or
        whose name collides with a trusted tool, becomes a Finding. Clean tools
        stay only in the returned inventory. Shadowing is scored across the
        whole advertised set, so a surface that did not arrive cannot be
        scored at all.
        """
        if unread is not None:
            return _unmeasured(unread)
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

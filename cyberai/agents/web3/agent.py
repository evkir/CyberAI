"""SmartContractAgent — Solidity static analysis & severity triage.

Standalone agent (not in the recon→intel→exploit→report network pipeline):
takes a contract address or local .sol path, runs static analysis, and triages
findings against Immunefi severity. Etherscan fetch is optional; local source
is the primary path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from cyberai.core.base_agent import BaseAgent, Tool

from .aderyn_tool import AderynTool
from .etherscan import EtherscanClient
from .foundry_poc import ForgePoCTool, PoCFinding
from .halmos_tool import HalmosTool
from .immunefi_severity import classify_all, highest_tier
from .merge import merge_findings
from .poc_synth import ExploitSynthesizer
from .slither_tool import SlitherTool

console = Console()


class SmartContractAgent(BaseAgent):
    """Web3 agent — static analysis of Solidity contracts."""

    AGENT_NAME = "web3"
    ROLE = "Smart Contract Auditor"

    def _register_tools(self) -> None:
        self.register_tool(
            Tool(
                name="fetch_source",
                description="Fetch verified contract source from Etherscan",
                func=self._fetch_source,
                parameters={"address": "str"},
            )
        )
        self.register_tool(
            Tool(
                name="slither_scan",
                description="Static-analyze a Solidity file with slither",
                func=self._slither_scan,
                parameters={"path": "str"},
            )
        )
        self.register_tool(
            Tool(
                name="aderyn_scan",
                description="Static-analyze a Solidity file with aderyn",
                func=self._aderyn_scan,
                parameters={"path": "str"},
            )
        )
        self.register_tool(
            Tool(
                name="halmos_scan",
                description="Symbolically test a Foundry project with halmos",
                func=self._halmos_scan,
                parameters={"project": "str"},
            )
        )
        self.register_tool(
            Tool(
                name="synthesize_poc",
                description="Synthesize a Foundry exploit PoC scaffold from a finding",
                func=self._synthesize_poc,
                parameters={"finding": "dict", "contract_name": "str"},
            )
        )

    def _fetch_source(self, address: str) -> Dict[str, Any]:
        client = EtherscanClient()
        src = client.get_source(address)
        if src is None:
            return {"verified": False, "source_code": ""}
        return {
            "address": src.address,
            "name": src.name,
            "verified": src.verified,
            "compiler_version": src.compiler_version,
            "source_len": len(src.source_code),
        }

    def _slither_scan(self, path: str) -> Dict[str, Any]:
        tool = SlitherTool()
        findings = tool.analyze(path)
        classified = classify_all(findings)
        return {
            "available": tool.available,
            "findings": classified,
            "highest_severity": highest_tier(findings),
            "count": len(classified),
        }

    def _aderyn_scan(self, path: str) -> Dict[str, Any]:
        tool = AderynTool()
        findings = tool.analyze(path)
        return {
            "available": tool.available,
            "findings": [f.to_dict() for f in findings],
            "count": len(findings),
        }

    def _halmos_scan(self, project: str) -> Dict[str, Any]:
        tool = HalmosTool()
        findings = tool.analyze(project)
        return {
            "available": tool.available,
            "findings": [f.to_dict() for f in findings],
            "count": len(findings),
        }

    def _synthesize_poc(
        self, finding: Dict[str, Any], contract_name: str = "Target"
    ) -> Dict[str, Any]:
        """Render a Foundry exploit PoC scaffold for a finding (offline)."""
        script = ExploitSynthesizer().synthesize(finding, contract_name)
        return {"script": script}

    def _run_halmos(self, context: Optional[Dict[str, Any]], tool: HalmosTool) -> list:
        """Run halmos when a prepared Foundry project is supplied via context.

        halmos builds a Foundry project via forge and executes symbolic tests, so
        it needs a project root rather than a raw .sol file. It runs only when
        `context["halmos_project"]` is given and the binary is present; otherwise
        it degrades to no findings.
        """
        ctx = context or {}
        project = ctx.get("halmos_project")
        if not tool.available or not project:
            return []
        return tool.analyze(
            project,
            contract=ctx.get("halmos_contract"),
            loop=ctx.get("halmos_loop", 2),
        )

    def _run_foundry_poc(
        self, context: Optional[Dict[str, Any]], tool: ForgePoCTool
    ) -> List[PoCFinding]:
        """Run a Foundry on-chain PoC when a prepared project is in context.

        The runner replays an exploit test against a fork, so it needs a Foundry
        project root (and optionally a fork RPC via `context["fork_rpc"]`). It
        runs only when `context["foundry_project"]` is given and forge is
        present; otherwise it degrades to no findings.
        """
        ctx = context or {}
        project = ctx.get("foundry_project")
        if not tool.available or not project:
            return []
        return tool.run(
            project,
            rpc_url=ctx.get("fork_rpc"),
            match=ctx.get("poc_match", "testExploit"),
        )

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze a contract.

        `target` is either a local .sol path or a contract address. Local source
        drives static analysis (slither + aderyn), optional symbolic testing
        (halmos), and optional on-chain PoC validation (foundry) when a prepared
        project is supplied via context.
        """
        self._log(f"Smart-contract analysis target: {target}")
        is_local = Path(target).exists() and target.endswith(".sol")
        result: Dict[str, Any] = {
            "target": target,
            "mode": "local" if is_local else "address",
            "findings": [],
        }
        if is_local:
            slither_tool = SlitherTool()
            aderyn_tool = AderynTool()
            halmos_tool = HalmosTool()
            poc_tool = ForgePoCTool()
            slither_findings = slither_tool.analyze(target)
            aderyn_findings = aderyn_tool.analyze(target)
            halmos_findings = self._run_halmos(context, halmos_tool)
            poc_findings = self._run_foundry_poc(context, poc_tool)
            merged = merge_findings(slither_findings, aderyn_findings)
            result["findings"] = classify_all(slither_findings)
            result["aderyn_findings"] = [f.to_dict() for f in aderyn_findings]
            result["halmos_findings"] = [f.to_dict() for f in halmos_findings]
            result["poc_findings"] = [f.to_dict() for f in poc_findings]
            result["merged_findings"] = [m.to_dict() for m in merged]
            result["highest_severity"] = highest_tier(
                [*slither_findings, *halmos_findings, *poc_findings]
            )
            result["slither_available"] = slither_tool.available
            result["aderyn_available"] = aderyn_tool.available
            result["halmos_available"] = halmos_tool.available
            result["poc_available"] = poc_tool.available
        else:
            result["source_meta"] = self.call_tool("fetch_source", address=target)
        self.kb.set("web3", result, agent=self.AGENT_NAME)
        self._log(
            "Smart-contract analysis complete",
            {"mode": result["mode"], "findings": len(result["findings"])},
        )
        return result

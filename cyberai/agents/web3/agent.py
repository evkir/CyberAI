"""SmartContractAgent — Solidity static analysis & severity triage.

Standalone agent (not in the recon→intel→exploit→report network pipeline):
takes a contract address or local .sol path, runs static analysis, and triages
findings against Immunefi severity. Etherscan fetch is optional; local source
is the primary path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from rich.console import Console

from cyberai.core.base_agent import BaseAgent, Tool

from .aderyn_tool import AderynTool
from .etherscan import EtherscanClient
from .immunefi_severity import classify_all, highest_tier
from .merge import merge_findings
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

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze a contract.

        `target` is either a local .sol path or a contract address. Slither
        wiring + severity arrive in later commits; this skeleton resolves the
        source and records intent.
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
            slither_findings = slither_tool.analyze(target)
            aderyn_findings = aderyn_tool.analyze(target)
            merged = merge_findings(slither_findings, aderyn_findings)
            result["findings"] = classify_all(slither_findings)
            result["aderyn_findings"] = [f.to_dict() for f in aderyn_findings]
            result["merged_findings"] = [m.to_dict() for m in merged]
            result["highest_severity"] = highest_tier(slither_findings)
            result["slither_available"] = slither_tool.available
            result["aderyn_available"] = aderyn_tool.available
        else:
            result["source_meta"] = self.call_tool("fetch_source", address=target)
        self.kb.set("web3", result, agent=self.AGENT_NAME)
        self._log(
            "Smart-contract analysis complete",
            {"mode": result["mode"], "findings": len(result["findings"])},
        )
        return result

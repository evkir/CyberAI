"""SmartContractAgent — Solidity static analysis & severity triage (day 24).

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

from .etherscan import EtherscanClient

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
        if not is_local:
            result["source_meta"] = self.call_tool("fetch_source", address=target)
        self.kb.set("web3", result, agent=self.AGENT_NAME)
        self._log("Smart-contract skeleton complete", {"mode": result["mode"]})
        return result

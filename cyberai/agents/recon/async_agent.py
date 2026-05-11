"""
Async ReconAgent — parallel DNS, nmap, TLS in one gather() call.
"""
import asyncio
import logging
from cyberai.core.async_base_agent import AsyncBaseAgent
from cyberai.agents.recon.nmap_tool import NmapTool
from cyberai.agents.recon.dns_tool import DNSTool
from cyberai.agents.recon.tls_tool import TLSTool

logger = logging.getLogger("cyberai.recon.async")


class AsyncReconAgent(AsyncBaseAgent):
    name = "recon"

    def __init__(self):
        super().__init__()
        self.nmap = NmapTool()
        self.dns = DNSTool()
        self.tls = TLSTool()

    async def run(self, target: str, **kwargs) -> dict:
        """
        Run nmap + DNS + TLS in parallel.
        All three fire simultaneously — total time ≈ slowest tool.
        """
        logger.info(f"[AsyncReconAgent] starting parallel recon on {target}")

        nmap_task = self.run_tool(self.nmap.run, target)
        dns_task  = self.run_tool(self.dns.run, target)
        tls_task  = self.run_tool(self.tls.run, target)

        nmap_result, dns_result, tls_result = await asyncio.gather(
            nmap_task, dns_task, tls_task
        )

        logger.info(f"[AsyncReconAgent] parallel recon complete for {target}")

        return {
            "target": target,
            "nmap": nmap_result,
            "dns": dns_result,
            "tls": tls_result,
        }


class AsyncIntelAgent(AsyncBaseAgent):
    name = "intel"

    async def run(self, recon_result: dict, **kwargs) -> dict:
        """Intel runs after recon — enriches findings with CVE data."""
        from cyberai.agents.intel.agent import IntelAgent
        intel = IntelAgent()
        return await self.run_tool(intel.run, recon_result)


class AsyncExploitAgent(AsyncBaseAgent):
    name = "exploit"

    async def run(self, intel_result: dict, **kwargs) -> dict:
        """Exploit analysis runs after intel."""
        from cyberai.agents.exploit.agent import ExploitAgent
        exploit = ExploitAgent()
        return await self.run_tool(exploit.run, intel_result)

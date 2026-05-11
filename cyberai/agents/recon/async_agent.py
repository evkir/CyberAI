"""
Async ReconAgent — parallel nmap + DNS + TLS via asyncio.
"""
import asyncio
import logging
from cyberai.core.async_base_agent import AsyncBaseAgent
from cyberai.agents.recon.nmap_tool import run_nmap
from cyberai.agents.recon.dns_tool import run_dns
from cyberai.agents.recon.tls_tool import TLSTool

logger = logging.getLogger("cyberai.recon.async")


class AsyncReconAgent(AsyncBaseAgent):
    name = "recon"

    def __init__(self):
        super().__init__()
        self.tls = TLSTool()

    async def run(self, target: str, **kwargs) -> dict:
        logger.info(f"[AsyncReconAgent] parallel recon on {target}")

        nmap_task = self.run_tool(run_nmap, target)
        dns_task  = self.run_tool(run_dns, target)
        tls_task  = self.run_tool(self.tls.run, target)

        nmap_result, dns_result, tls_result = await asyncio.gather(
            nmap_task, dns_task, tls_task
        )

        return {
            "target": target,
            "nmap": nmap_result,
            "dns": dns_result,
            "tls": tls_result,
        }


class AsyncIntelAgent(AsyncBaseAgent):
    name = "intel"

    async def run(self, recon_result: dict, **kwargs) -> dict:
        from cyberai.agents.intel.agent import IntelAgent
        intel = IntelAgent()
        return await self.run_tool(intel.run, recon_result)


class AsyncExploitAgent(AsyncBaseAgent):
    name = "exploit"

    async def run(self, intel_result: dict, **kwargs) -> dict:
        from cyberai.agents.exploit.agent import ExploitAgent
        exploit = ExploitAgent()
        return await self.run_tool(exploit.run, intel_result)

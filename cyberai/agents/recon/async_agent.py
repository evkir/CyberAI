"""
Async ReconAgent — parallel nmap + DNS + subdomains + TLS via asyncio.
"""

import asyncio
import logging

from cyberai.core.async_base_agent import AsyncBaseAgent
from cyberai.agents.recon.nmap_tool import run_nmap
from cyberai.agents.recon.dns_tool import run_dns_async
from cyberai.agents.recon.subdomain_enum import enumerate_subdomains_async
from cyberai.agents.recon.tls_tool import TLSTool

logger = logging.getLogger("cyberai.recon.async")


class AsyncReconAgent(AsyncBaseAgent):
    name = "recon"

    def __init__(self):
        super().__init__()
        self.tls = TLSTool()

    async def run(self, target: str, **kwargs) -> dict:
        """
        Run all recon tools concurrently.

        nmap & tls remain executor-wrapped (subprocess / blocking HTTPS),
        but DNS and subdomain enumeration are natively async — no thread
        overhead, proper cancellation on timeout.
        """
        logger.info(f"[AsyncReconAgent] parallel recon on {target}")

        nmap_task = self.run_tool(run_nmap, target)
        dns_task = run_dns_async(target)
        subdomains_task = enumerate_subdomains_async(target)
        tls_task = self.run_tool(self.tls.run, target)

        nmap_result, dns_result, subdomains_result, tls_result = await asyncio.gather(
            nmap_task, dns_task, subdomains_task, tls_task
        )

        return {
            "target": target,
            "nmap": nmap_result,
            "dns": dns_result,
            "subdomains": subdomains_result,
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

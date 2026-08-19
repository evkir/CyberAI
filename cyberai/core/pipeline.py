"""
Parallel agent pipeline executor.
Runs independent phases concurrently, enforces ordering for dependent phases.

Pipeline topology:
  [ReconAgent] ──┐
                 ├──► [IntelAgent] ──► [ExploitAgent] ──► [ReportAgent]
  (parallel ok)  │
  [TLS scan]  ───┘

Recon phases are parallel. Intel/Exploit/Report are sequential
(each depends on previous output).
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from cyberai.agents.recon.async_agent import (
    AsyncExploitAgent,
    AsyncIntelAgent,
    AsyncReconAgent,
)

logger = logging.getLogger("cyberai.core.pipeline")


@dataclass
class PipelineResult:
    target: str
    recon: dict = field(default_factory=dict)
    intel: dict = field(default_factory=dict)
    exploit: dict = field(default_factory=dict)
    duration_seconds: float = 0.0
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None


class AsyncPipeline:
    """
    Orchestrates the full recon→intel→exploit pipeline asynchronously.
    Recon tools run in parallel; subsequent stages are sequential.
    """

    def __init__(self):
        self.recon_agent = AsyncReconAgent()
        self.intel_agent = AsyncIntelAgent()
        self.exploit_agent = AsyncExploitAgent()

    async def run(self, target: str) -> PipelineResult:
        start = time.monotonic()
        result = PipelineResult(target=target)

        try:
            # Phase 1: Recon (parallel tools internally)
            logger.info(f"[Pipeline] Phase 1: recon → {target}")
            result.recon = await self.recon_agent.run(target)

            # Phase 2: Intel (depends on recon)
            logger.info("[Pipeline] Phase 2: intel")
            result.intel = await self.intel_agent.run(result.recon)

            # Phase 3: Exploit analysis (depends on intel)
            logger.info("[Pipeline] Phase 3: exploit analysis")
            result.exploit = await self.exploit_agent.run(result.intel)

        except Exception as e:
            logger.error(f"[Pipeline] failed: {e}")
            result.error = str(e)

        result.duration_seconds = time.monotonic() - start
        logger.info(
            f"[Pipeline] complete in {result.duration_seconds:.1f}s success={result.success}"
        )
        return result

    @classmethod
    def execute(cls, target: str) -> PipelineResult:
        """Sync entry point — runs async pipeline from sync context."""
        pipeline = cls()
        return asyncio.run(pipeline.run(target))

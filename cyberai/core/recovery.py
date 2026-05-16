"""
Error recovery strategies for the Orchestrator pipeline.
Defines fallback behaviours when agents fail.
"""
import logging
from typing import Any, Callable, Optional
from dataclasses import dataclass

logger = logging.getLogger("cyberai.core.recovery")


@dataclass
class FallbackResult:
    agent: str
    error: str
    fallback_used: bool
    data: dict


def with_fallback(
    agent_name: str,
    fn: Callable,
    fallback: Optional[dict] = None,
    *args,
    **kwargs,
) -> dict:
    """
    Run fn(*args, **kwargs). On any exception return fallback dict.
    Logs the failure — pipeline continues with degraded output.

    Usage:
        result = with_fallback("intel", intel_agent.run, {}, recon_data)
    """
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        logger.error(
            f"[recovery] {agent_name} failed: {e} — "
            f"{'using fallback' if fallback is not None else 'propagating'}"
        )
        if fallback is not None:
            return {**(fallback or {}), "_error": str(e), "_agent": agent_name}
        raise


class PipelineRecovery:
    """
    Orchestrator-level recovery: defines per-phase fallback strategy.

    Strategy:
      - recon failure  → HARD STOP (no target data = nothing to work with)
      - intel failure  → SOFT FAIL (continue with empty CVE context)
      - exploit failure → SOFT FAIL (continue with empty paths)
      - report failure  → SOFT FAIL (log error, return raw data)
    """

    @staticmethod
    def recon(fn: Callable, *args, **kwargs) -> dict:
        """Recon is mandatory — propagate failure."""
        return fn(*args, **kwargs)

    @staticmethod
    def intel(fn: Callable, *args, **kwargs) -> dict:
        """Intel is optional — fallback to empty context."""
        return with_fallback(
            "intel", fn,
            fallback={"cves": [], "risk": "UNKNOWN", "_degraded": True},
            *args, **kwargs,
        )

    @staticmethod
    def exploit(fn: Callable, *args, **kwargs) -> dict:
        """Exploit is optional — fallback to empty paths."""
        return with_fallback(
            "exploit", fn,
            fallback={"attack_paths": [], "_degraded": True},
            *args, **kwargs,
        )

    @staticmethod
    def report(fn: Callable, *args, **kwargs) -> dict:
        """Report is optional — fallback to raw data passthrough."""
        return with_fallback(
            "report", fn,
            fallback={"status": "report_failed", "_degraded": True},
            *args, **kwargs,
        )

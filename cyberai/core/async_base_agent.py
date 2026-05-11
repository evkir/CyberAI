"""
Async base agent — non-blocking tool execution via asyncio.
Drop-in async companion to BaseAgent.
"""
import asyncio
import logging
from typing import Any, Optional
from cyberai.core.timeout import AgentTimeoutManager

logger = logging.getLogger("cyberai.core.async_agent")


class AsyncBaseAgent:
    """
    Base class for all async agents.
    Wraps blocking tool calls in asyncio executor so they
    don't block the event loop.
    """

    name: str = "base"

    def __init__(self, timeout: Optional[int] = None):
        self.timeout = timeout or AgentTimeoutManager.get_timeout(self.name)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    async def run(self, target: str, **kwargs) -> dict:
        """Override in subclass."""
        raise NotImplementedError

    async def run_tool(self, fn, *args, **kwargs) -> Any:
        """
        Run a blocking tool function in a thread executor.
        Prevents blocking the event loop during nmap/HTTP calls.
        """
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: fn(*args, **kwargs)),
                timeout=self.timeout,
            )
            return result
        except asyncio.TimeoutError:
            logger.warning(
                f"[{self.name}] tool call timed out after {self.timeout}s"
            )
            return {"error": f"timeout after {self.timeout}s"}
        except Exception as e:
            logger.error(f"[{self.name}] tool call failed: {e}")
            return {"error": str(e)}

    async def run_tools_parallel(self, tasks: list[tuple]) -> list[Any]:
        """
        Run multiple tool calls in parallel.
        tasks: list of (fn, *args) tuples
        """
        coroutines = [self.run_tool(fn, *args) for fn, *args in tasks]
        return await asyncio.gather(*coroutines, return_exceptions=True)

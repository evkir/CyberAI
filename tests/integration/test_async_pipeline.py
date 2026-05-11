"""
Async pipeline integration tests.
Uses mocked agents — no live targets needed.
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from cyberai.core.async_base_agent import AsyncBaseAgent
from cyberai.core.pipeline import AsyncPipeline, PipelineResult


# ── AsyncBaseAgent unit tests ──────────────────────────────────────

class TestAsyncBaseAgent:

    def test_run_tool_success(self):
        agent = AsyncBaseAgent()
        agent.name = "test"
        agent.timeout = 5

        result = asyncio.run(
            agent.run_tool(lambda: {"ok": True})
        )
        assert result == {"ok": True}

    def test_run_tool_timeout(self):
        import time
        agent = AsyncBaseAgent()
        agent.name = "test"
        agent.timeout = 1

        def slow():
            time.sleep(5)
            return {"ok": True}

        result = asyncio.run(agent.run_tool(slow))
        assert "error" in result
        assert "timeout" in result["error"]

    def test_run_tools_parallel_all_succeed(self):
        agent = AsyncBaseAgent()
        agent.name = "test"
        agent.timeout = 5

        results = asyncio.run(
            agent.run_tools_parallel([
                (lambda: {"tool": "a"},),
                (lambda: {"tool": "b"},),
                (lambda: {"tool": "c"},),
            ])
        )
        assert len(results) == 3

    def test_run_tools_parallel_faster_than_sequential(self):
        import time

        agent = AsyncBaseAgent()
        agent.name = "test"
        agent.timeout = 10

        def slow_task():
            time.sleep(0.3)
            return {"ok": True}

        start = time.monotonic()
        asyncio.run(
            agent.run_tools_parallel([
                (slow_task,),
                (slow_task,),
                (slow_task,),
            ])
        )
        elapsed = time.monotonic() - start
        # 3 x 0.3s sequential = 0.9s; parallel should be ~0.3s
        assert elapsed < 0.7, f"Parallel execution too slow: {elapsed:.2f}s"


# ── AsyncPipeline integration tests ───────────────────────────────

class TestAsyncPipeline:

    def _make_pipeline(self):
        pipeline = AsyncPipeline()
        pipeline.recon_agent.run   = AsyncMock(return_value={"ports": [80, 443]})
        pipeline.intel_agent.run   = AsyncMock(return_value={"cves": ["CVE-2024-1234"]})
        pipeline.exploit_agent.run = AsyncMock(return_value={"paths": ["sqli"]})
        return pipeline

    def test_pipeline_runs_all_phases(self):
        pipeline = self._make_pipeline()
        result = asyncio.run(pipeline.run("10.10.10.1"))

        assert result.success
        assert result.recon == {"ports": [80, 443]}
        assert result.intel == {"cves": ["CVE-2024-1234"]}
        assert result.exploit == {"paths": ["sqli"]}

    def test_pipeline_records_duration(self):
        pipeline = self._make_pipeline()
        result = asyncio.run(pipeline.run("10.10.10.1"))
        assert result.duration_seconds > 0

    def test_pipeline_handles_agent_failure(self):
        pipeline = AsyncPipeline()
        pipeline.recon_agent.run = AsyncMock(side_effect=RuntimeError("nmap failed"))
        pipeline.intel_agent.run = AsyncMock(return_value={})
        pipeline.exploit_agent.run = AsyncMock(return_value={})

        result = asyncio.run(pipeline.run("10.10.10.1"))
        assert not result.success
        assert "nmap failed" in result.error

    def test_execute_sync_entrypoint(self):
        pipeline = AsyncPipeline()
        pipeline.recon_agent.run   = AsyncMock(return_value={"ports": []})
        pipeline.intel_agent.run   = AsyncMock(return_value={})
        pipeline.exploit_agent.run = AsyncMock(return_value={})

        with patch("cyberai.core.pipeline.AsyncPipeline", return_value=pipeline):
            result = asyncio.run(pipeline.run("10.10.10.2"))
        assert isinstance(result, PipelineResult)

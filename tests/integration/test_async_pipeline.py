"""
Async pipeline integration tests.
Uses mocked agents — no live targets needed.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from cyberai.core.async_base_agent import AsyncBaseAgent
from cyberai.core.pipeline import AsyncPipeline, PipelineResult


# ── AsyncBaseAgent unit tests ──────────────────────────────────────


class TestAsyncBaseAgent:
    def test_run_tool_success(self):
        agent = AsyncBaseAgent()
        agent.name = "test"
        agent.timeout = 5

        result = asyncio.run(agent.run_tool(lambda: {"ok": True}))
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
            agent.run_tools_parallel(
                [
                    (lambda: {"tool": "a"},),
                    (lambda: {"tool": "b"},),
                    (lambda: {"tool": "c"},),
                ]
            )
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
            agent.run_tools_parallel(
                [
                    (slow_task,),
                    (slow_task,),
                    (slow_task,),
                ]
            )
        )
        elapsed = time.monotonic() - start
        # 3 x 0.3s sequential = 0.9s; parallel should be ~0.3s
        assert elapsed < 0.7, f"Parallel execution too slow: {elapsed:.2f}s"


# ── AsyncPipeline integration tests ───────────────────────────────


class TestAsyncPipeline:
    def _make_pipeline(self):
        pipeline = AsyncPipeline()
        pipeline.recon_agent.run = AsyncMock(return_value={"ports": [80, 443]})
        pipeline.intel_agent.run = AsyncMock(return_value={"cves": ["CVE-2024-1234"]})
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
        pipeline.recon_agent.run = AsyncMock(return_value={"ports": []})
        pipeline.intel_agent.run = AsyncMock(return_value={})
        pipeline.exploit_agent.run = AsyncMock(return_value={})

        with patch("cyberai.core.pipeline.AsyncPipeline", return_value=pipeline):
            result = asyncio.run(pipeline.run("10.10.10.2"))
        assert isinstance(result, PipelineResult)


# ── AsyncOrchestrator integration tests ───────────────────────────


class TestAsyncOrchestrator:
    """
    Full async pipeline through ScanSession + injection check between phases.
    All agents and the LLM are mocked — no live targets, no API keys.
    """

    def _orchestrator(self):
        from cyberai.core.orchestrator import AsyncOrchestrator
        from cyberai.core.config import CyberAIConfig

        return AsyncOrchestrator(config=CyberAIConfig(), dry_run=False)

    def test_dry_run_completes_all_four_phases(self):
        """Without dry_run mocks below, prove the happy path runs end-to-end."""
        from cyberai.core.orchestrator import AsyncOrchestrator
        from cyberai.core.config import CyberAIConfig

        orch = AsyncOrchestrator(config=CyberAIConfig(), dry_run=True)
        session = asyncio.run(orch.run("dryrun.local"))

        assert session.state.value == "completed"
        phase_names = [p.phase.value for p in session.phases]
        assert phase_names == ["recon", "intel", "exploit", "report"]
        assert all(p.success for p in session.phases)

    def test_runs_recon_via_async_agent(self):
        """Recon must dispatch to AsyncReconAgent, not the sync ReconAgent."""
        orch = self._orchestrator()
        orch.phases = []  # not used here — we test _run_recon_async directly

        recon_payload = {"target": "t.local", "nmap": {"ports": [22]}, "dns": {}}
        with (
            patch(
                "cyberai.agents.recon.async_agent.AsyncReconAgent.run",
                new_callable=AsyncMock,
                return_value=recon_payload,
            ),
            patch(
                "cyberai.agents.recon.llm_detector.detect_llm_endpoints",
                return_value={"is_llm_target": False},
            ),
        ):
            from cyberai.core.scan_session import ScanSession

            session = ScanSession(target="t.local")
            result = asyncio.run(orch._run_recon_async(session))

        assert result == recon_payload
        assert session.kb_get("recon") == recon_payload

    def test_async_recon_writes_granular_kb_keys(self):
        """Async recon must mirror sync ReconAgent's granular recon.* keys
        so downstream sync IntelAgent (offloaded via to_thread) finds ports."""
        orch = self._orchestrator()
        recon_payload = {
            "target": "t.local",
            "nmap": {"ports": [22]},
            "dns": {"records": []},
            "subdomains": {"found": []},
            "tls": {},
        }
        with (
            patch(
                "cyberai.agents.recon.async_agent.AsyncReconAgent.run",
                new_callable=AsyncMock,
                return_value=recon_payload,
            ),
            patch(
                "cyberai.agents.recon.llm_detector.detect_llm_endpoints",
                return_value={"is_llm_target": False},
            ),
        ):
            from cyberai.core.scan_session import ScanSession

            session = ScanSession(target="t.local")
            asyncio.run(orch._run_recon_async(session))

        assert session.kb.get("recon.nmap") == {"ports": [22]}
        assert session.kb.get("recon.dns") == {"records": []}
        assert session.kb.get("recon.subdomains") == {"found": []}
        assert session.kb.get("recon.nmap", {}).get("ports") == [22]

    def test_async_recon_populates_result_and_llm_for_planner_graph(self):
        """Async recon must set recon.result and recon.llm_endpoints so the
        planner KB graph builds port/service/subdomain/LLM nodes like sync."""
        orch = self._orchestrator()
        recon_payload = {
            "target": "t.local",
            "nmap": {"ports": [{"port": 22, "protocol": "tcp", "service": "ssh", "state": "open"}]},
            "dns": {"records": []},
            "subdomains": {"found": [{"fqdn": "dev.t.local"}]},
            "tls": {},
        }
        llm_payload = {
            "is_llm_target": True,
            "llm_endpoints": [{"url": "http://t.local/v1/chat/completions"}],
        }
        with (
            patch(
                "cyberai.agents.recon.async_agent.AsyncReconAgent.run",
                new_callable=AsyncMock,
                return_value=recon_payload,
            ),
            patch(
                "cyberai.agents.recon.llm_detector.detect_llm_endpoints",
                return_value=llm_payload,
            ),
        ):
            from cyberai.core.scan_session import ScanSession

            session = ScanSession(target="t.local")
            asyncio.run(orch._run_recon_async(session))

        result = session.kb.get("recon.result")
        assert result["target"] == "t.local"
        assert result["ports"] == [
            {"port": 22, "protocol": "tcp", "service": "ssh", "version": None}
        ]
        assert result["subdomains"] == ["dev.t.local"]
        assert session.kb.get("recon.llm_endpoints") == llm_payload

        # The planner graph now sees port + LLM nodes on the async path.
        from cyberai.core.kb_graph import build_kb_graph

        graph = build_kb_graph(session.kb, "t.local")
        ntypes = {d["ntype"] for _, d in graph.nodes(data=True)}
        assert "port" in ntypes and "llm_endpoint" in ntypes

    def test_async_recon_writes_whois_like_sync(self):
        """AsyncReconAgent runs only nmap/dns/subdomains/tls, so whois has to
        be offloaded by the orchestrator or recon.whois and ReconResult.whois
        stay empty on the async path while the sync agent fills both."""
        recon_payload = {"target": "t.local", "nmap": {"ports": []}, "dns": {}}
        whois_payload = {"target": "t.local", "registrar": "Example Registrar"}
        from cyberai.core.config import CyberAIConfig
        from cyberai.core.orchestrator import AsyncOrchestrator
        from cyberai.core.scan_session import ScanSession

        orch = AsyncOrchestrator(config=CyberAIConfig(), dry_run=False)
        session = ScanSession(target="t.local")
        with (
            patch(
                "cyberai.agents.recon.async_agent.AsyncReconAgent.run",
                new_callable=AsyncMock,
                return_value=recon_payload,
            ),
            patch(
                "cyberai.agents.recon.llm_detector.detect_llm_endpoints",
                return_value={},
            ),
            patch("cyberai.agents.recon.dns_tool.run_whois", return_value=whois_payload),
        ):
            asyncio.run(orch._run_recon_async(session))

        assert session.kb.get("recon.whois") == whois_payload
        assert session.kb.get("recon.result")["whois"] == whois_payload

    def test_async_recon_runs_web_surface_when_flag_is_on(self):
        """AsyncReconAgent has no web branch. Without the orchestrator running
        one, recon.web_surface is absent on the async path and build_kb_graph
        plus ExploitAgent see an empty surface — the whole web layer is dead
        under AsyncOrchestrator while it works under the sync one."""
        from cyberai.core.config import CyberAIConfig
        from cyberai.core.orchestrator import AsyncOrchestrator
        from cyberai.core.scan_session import ScanSession

        recon_payload = {"target": "t.local", "nmap": {"ports": []}, "dns": {}}
        surface = {
            "endpoints": [{"method": "GET", "url": "http://t.local/search", "params": ["q"]}]
        }
        orch = AsyncOrchestrator(config=CyberAIConfig(use_web_recon=True), dry_run=False)
        session = ScanSession(target="t.local")
        with (
            patch(
                "cyberai.agents.recon.async_agent.AsyncReconAgent.run",
                new_callable=AsyncMock,
                return_value=recon_payload,
            ),
            patch("cyberai.agents.recon.llm_detector.detect_llm_endpoints", return_value={}),
            patch("cyberai.agents.recon.dns_tool.run_whois", return_value={}),
            patch("cyberai.agents.recon.agent.discover_surface", return_value=surface),
        ):
            asyncio.run(orch._run_recon_async(session))

        assert session.kb.get("recon.web_surface") == surface

    def test_async_recon_skips_web_surface_when_flag_is_off(self):
        """Default config must not start crawling: the flag gates the async
        path exactly as it gates the sync one."""
        from cyberai.core.config import CyberAIConfig
        from cyberai.core.orchestrator import AsyncOrchestrator
        from cyberai.core.scan_session import ScanSession

        recon_payload = {"target": "t.local", "nmap": {"ports": []}, "dns": {}}
        orch = AsyncOrchestrator(config=CyberAIConfig(), dry_run=False)
        session = ScanSession(target="t.local")
        with (
            patch(
                "cyberai.agents.recon.async_agent.AsyncReconAgent.run",
                new_callable=AsyncMock,
                return_value=recon_payload,
            ),
            patch("cyberai.agents.recon.llm_detector.detect_llm_endpoints", return_value={}),
            patch("cyberai.agents.recon.dns_tool.run_whois", return_value={}),
            patch("cyberai.agents.recon.agent.discover_surface") as crawl,
        ):
            asyncio.run(orch._run_recon_async(session))

        crawl.assert_not_called()
        assert session.kb.get("recon.web_surface") is None

    def test_sync_intel_runs_under_to_thread(self):
        """Intel/exploit/report stay sync; AsyncOrchestrator must offload them."""
        from cyberai.core.scan_session import ScanSession, ScanPhase

        orch = self._orchestrator()
        orch.audit = MagicMock()
        session = ScanSession(target="t.local")

        # _run_intel is the sync handler inherited from Orchestrator;
        # _dispatch_async should await it via asyncio.to_thread.
        with patch.object(
            orch, "_run_intel", return_value={"ranked_cves": [{"id": "CVE-X"}]}
        ) as mock_intel:
            data = asyncio.run(orch._dispatch_async(session, ScanPhase.INTEL))

        mock_intel.assert_called_once_with(session)
        assert data == {"ranked_cves": [{"id": "CVE-X"}]}

    def test_phase_failure_does_not_abort_remaining_phases(self):
        """Sync Orchestrator continues past a failed phase — async must too."""
        from cyberai.core.orchestrator import AsyncOrchestrator
        from cyberai.core.config import CyberAIConfig

        orch = AsyncOrchestrator(config=CyberAIConfig(), dry_run=False)

        with (
            patch.object(
                orch,
                "_run_recon_async",
                new_callable=AsyncMock,
                side_effect=RuntimeError("nmap blew up"),
            ),
            patch.object(orch, "_run_intel", return_value={"ranked_cves": []}),
            patch.object(orch, "_run_exploit", return_value={"paths": []}),
            patch.object(orch, "_run_report", return_value={"html_report": "x.html"}),
        ):
            session = asyncio.run(orch.run("t.local"))

        results = {p.phase.value: p.success for p in session.phases}
        assert results["recon"] is False
        assert results["intel"] is True
        assert results["exploit"] is True
        assert results["report"] is True
        assert session.state.value == "failed"  # any failed phase → overall failed

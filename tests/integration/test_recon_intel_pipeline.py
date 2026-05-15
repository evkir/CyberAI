"""
ReconAgent → IntelAgent handoff tests.
"""
import asyncio
from unittest.mock import AsyncMock
from cyberai.core.pipeline import AsyncPipeline

class TestReconIntelHandoff:
    def test_recon_ports_reach_intel(self):
        recon_out = {"target": "10.10.10.5", "nmap": {"ports": [21, 22, 8080]}, "dns": {}, "tls": {}}
        p = AsyncPipeline()
        p.recon_agent.run   = AsyncMock(return_value=recon_out)
        p.intel_agent.run   = AsyncMock(return_value={})
        p.exploit_agent.run = AsyncMock(return_value={})
        asyncio.run(p.run("10.10.10.5"))
        assert p.intel_agent.run.call_args[0][0]["nmap"]["ports"] == [21, 22, 8080]

    def test_tls_findings_reach_intel(self):
        recon_out = {"target": "10.10.10.5", "nmap": {}, "dns": {},
                     "tls": {"score": "POOR", "findings": [{"severity": "HIGH", "issue": "TLSv1.0"}]}}
        p = AsyncPipeline()
        p.recon_agent.run   = AsyncMock(return_value=recon_out)
        p.intel_agent.run   = AsyncMock(return_value={})
        p.exploit_agent.run = AsyncMock(return_value={})
        asyncio.run(p.run("10.10.10.5"))
        findings = p.intel_agent.run.call_args[0][0]["tls"]["findings"]
        assert any(f["severity"] == "HIGH" for f in findings)

    def test_multiple_targets_isolated(self):
        results = []
        for ip in ["10.10.10.1", "10.10.10.2"]:
            p = AsyncPipeline()
            p.recon_agent.run   = AsyncMock(return_value={"target": ip})
            p.intel_agent.run   = AsyncMock(return_value={})
            p.exploit_agent.run = AsyncMock(return_value={})
            results.append(asyncio.run(p.run(ip)))
        assert results[0].recon["target"] == "10.10.10.1"
        assert results[1].recon["target"] == "10.10.10.2"

    def test_intel_not_called_on_recon_error(self):
        p = AsyncPipeline()
        p.recon_agent.run   = AsyncMock(side_effect=Exception("blocked"))
        p.intel_agent.run   = AsyncMock(return_value={})
        p.exploit_agent.run = AsyncMock(return_value={})
        result = asyncio.run(p.run("10.10.10.1"))
        assert not result.success
        p.intel_agent.run.assert_not_called()

"""
ReconAgent → IntelAgent handoff integration tests.
Validates data flows correctly between the two agents.
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from cyberai.core.pipeline import AsyncPipeline


class TestReconIntelHandoff:

    def test_recon_ports_reach_intel(self):
        """Intel agent must receive the full recon dict including ports."""
        recon_output = {
            "target": "10.10.10.5",
            "nmap": {"ports": [21, 22, 8080]},
            "dns":  {},
            "tls":  {},
        }
        p = AsyncPipeline()
        p.recon_agent.run   = AsyncMock(return_value=recon_output)
        p.intel_agent.run   = AsyncMock(return_value={"cves": []})
        p.exploit_agent.run = AsyncMock(return_value={})

        asyncio.run(p.run("10.10.10.5"))

        call_arg = p.intel_agent.run.call_args[0][0]
        assert call_arg["nmap"]["ports"] == [21, 22, 8080]

    def test_tls_findings_reach_intel(self):
        """TLS HIGH severity findings must flow through to intel."""
        recon_output = {
            "target": "10.10.10.5",
            "nmap": {},
            "dns":  {},
            "tls":  {
                "score": "POOR",
                "findings": [{"severity": "HIGH", "issue": "TLSv1.0"}],
            },
        }
        p = AsyncPipeline()
        p.recon_agent.run   = AsyncMock(return_value=recon_output)
        p.intel_agent.run   = AsyncMock(return_value={})
        p.exploit_agent.run = AsyncMock(return_value={})

        asyncio.run(p.run("10.10.10.5"))

        call_arg = p.intel_agent.run.call_args[0][0]
        findings = call_arg["tls"]["findings"]
        assert any(f["severity"] == "HIGH" for f in findings)

    def test_multiple_targets_isolated(self):
        """Each pipeline run is independent — no state bleed between runs."""
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
        """Intel must NOT run if recon fails."""
        p = AsyncPipeline()
        p.recon_agent.run   = AsyncMock(side_effect=Exception("scan blocked"))
        p.intel_agent.run   = AsyncMock(return_value={})
        p.exploit_agent.run = AsyncMock(return_value={})

        result = asyncio.run(p.run("10.10.10.1"))
        assert not result.success
        p.intel_agent.run.assert_not_called()

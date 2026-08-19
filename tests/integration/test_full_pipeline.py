"""
Full pipeline integration tests with mock targets.
"""

import asyncio
from unittest.mock import AsyncMock

from cyberai.core.pipeline import AsyncPipeline

MOCK_RECON = {
    "target": "10.10.10.1",
    "nmap": {"ports": [22, 80, 443]},
    "dns": {},
    "tls": {},
}
MOCK_INTEL = {"cves": ["CVE-2024-1234"], "risk": "HIGH"}
MOCK_EXPLOIT = {"attack_paths": [{"technique": "SSH brute force"}]}


def make_pipeline(recon=None, intel=None, exploit=None):
    p = AsyncPipeline()
    p.recon_agent.run = AsyncMock(return_value=recon or MOCK_RECON)
    p.intel_agent.run = AsyncMock(return_value=intel or MOCK_INTEL)
    p.exploit_agent.run = AsyncMock(return_value=exploit or MOCK_EXPLOIT)
    return p


class TestFullPipeline:
    def test_all_phases_execute(self):
        result = asyncio.run(make_pipeline().run("10.10.10.1"))
        assert result.success
        assert result.recon == MOCK_RECON
        assert result.intel == MOCK_INTEL
        assert result.exploit == MOCK_EXPLOIT

    def test_intel_receives_recon_output(self):
        p = make_pipeline()
        asyncio.run(p.run("10.10.10.1"))
        p.intel_agent.run.assert_called_once_with(MOCK_RECON)

    def test_exploit_receives_intel_output(self):
        p = make_pipeline()
        asyncio.run(p.run("10.10.10.1"))
        p.exploit_agent.run.assert_called_once_with(MOCK_INTEL)

    def test_recon_failure_stops_pipeline(self):
        p = AsyncPipeline()
        p.recon_agent.run = AsyncMock(side_effect=RuntimeError("nmap timeout"))
        p.intel_agent.run = AsyncMock(return_value=MOCK_INTEL)
        p.exploit_agent.run = AsyncMock(return_value=MOCK_EXPLOIT)
        result = asyncio.run(p.run("10.10.10.1"))
        assert not result.success
        p.intel_agent.run.assert_not_called()

    def test_result_has_duration(self):
        result = asyncio.run(make_pipeline().run("10.10.10.1"))
        assert result.duration_seconds > 0

    def test_empty_result_still_completes(self):
        result = asyncio.run(make_pipeline(recon={}, intel={}, exploit={}).run("10.10.10.1"))
        assert result.success

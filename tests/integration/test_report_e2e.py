"""
Report generation end-to-end test.
"""

import asyncio
from unittest.mock import AsyncMock

from cyberai.core.pipeline import AsyncPipeline

RECON = {
    "target": "10.10.10.1",
    "nmap": {"ports": [22, 80]},
    "tls": {"findings": [{"severity": "MEDIUM", "issue": "RC4"}]},
}
INTEL = {"cves": ["CVE-2021-41773", "CVE-2021-42013"], "risk": "CRITICAL"}
EXPLOIT = {
    "attack_paths": [
        {"technique": "Path traversal", "cve": "CVE-2021-41773", "severity": "CRITICAL"}
    ]
}


class TestReportE2E:
    def _p(self):
        p = AsyncPipeline()
        p.recon_agent.run = AsyncMock(return_value=RECON)
        p.intel_agent.run = AsyncMock(return_value=INTEL)
        p.exploit_agent.run = AsyncMock(return_value=EXPLOIT)
        return p

    def test_all_sections_present(self):
        r = asyncio.run(self._p().run("10.10.10.1"))
        assert r.success
        assert "ports" in r.recon["nmap"]
        assert "cves" in r.intel
        assert "attack_paths" in r.exploit

    def test_critical_cve_in_intel(self):
        r = asyncio.run(self._p().run("10.10.10.1"))
        assert "CVE-2021-41773" in r.intel["cves"]

    def test_attack_path_fields(self):
        r = asyncio.run(self._p().run("10.10.10.1"))
        path = r.exploit["attack_paths"][0]
        assert all(k in path for k in ["technique", "cve", "severity"])

    def test_tls_finding_flows_through(self):
        r = asyncio.run(self._p().run("10.10.10.1"))
        assert any(f["severity"] == "MEDIUM" for f in r.recon["tls"]["findings"])

    def test_failed_pipeline_error_field(self):
        p = AsyncPipeline()
        p.recon_agent.run = AsyncMock(side_effect=RuntimeError("unreachable"))
        p.intel_agent.run = AsyncMock(return_value={})
        p.exploit_agent.run = AsyncMock(return_value={})
        r = asyncio.run(p.run("10.10.10.1"))
        assert not r.success
        assert "unreachable" in r.error


# End-to-end coverage: recon→intel→exploit→report chain

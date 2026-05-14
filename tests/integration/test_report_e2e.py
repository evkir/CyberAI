"""
Report generation end-to-end test.
Full pipeline → report output validation.
"""
import asyncio
import pytest
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock
from cyberai.core.pipeline import AsyncPipeline


FULL_PIPELINE_RESULT = {
    "recon": {
        "target": "10.10.10.1",
        "nmap": {
            "ports": [22, 80, 443],
            "services": {"22": "OpenSSH 8.2", "80": "Apache 2.4.51"},
        },
        "tls": {
            "score": "AVERAGE",
            "findings": [
                {"severity": "MEDIUM", "issue": "Weak cipher", "detail": "RC4"}
            ],
        },
    },
    "intel": {
        "cves": ["CVE-2021-41773", "CVE-2021-42013"],
        "risk": "CRITICAL",
    },
    "exploit": {
        "attack_paths": [
            {"technique": "Path traversal", "cve": "CVE-2021-41773", "severity": "CRITICAL"}
        ],
    },
}


class TestReportE2E:

    def _make_pipeline(self):
        p = AsyncPipeline()
        p.recon_agent.run   = AsyncMock(return_value=FULL_PIPELINE_RESULT["recon"])
        p.intel_agent.run   = AsyncMock(return_value=FULL_PIPELINE_RESULT["intel"])
        p.exploit_agent.run = AsyncMock(return_value=FULL_PIPELINE_RESULT["exploit"])
        return p

    def test_pipeline_result_has_all_sections(self):
        p = self._make_pipeline()
        result = asyncio.run(p.run("10.10.10.1"))

        assert result.success
        assert "ports" in result.recon.get("nmap", {})
        assert "cves" in result.intel
        assert "attack_paths" in result.exploit

    def test_critical_cve_present_in_intel(self):
        p = self._make_pipeline()
        result = asyncio.run(p.run("10.10.10.1"))
        assert "CVE-2021-41773" in result.intel["cves"]

    def test_attack_path_has_required_fields(self):
        p = self._make_pipeline()
        result = asyncio.run(p.run("10.10.10.1"))
        path = result.exploit["attack_paths"][0]
        assert "technique" in path
        assert "cve" in path
        assert "severity" in path

    def test_tls_finding_flows_end_to_end(self):
        p = self._make_pipeline()
        result = asyncio.run(p.run("10.10.10.1"))
        findings = result.recon.get("tls", {}).get("findings", [])
        assert any(f["severity"] == "MEDIUM" for f in findings)

    def test_pipeline_duration_recorded(self):
        p = self._make_pipeline()
        result = asyncio.run(p.run("10.10.10.1"))
        assert result.duration_seconds >= 0

    def test_failed_pipeline_has_error_field(self):
        p = AsyncPipeline()
        p.recon_agent.run   = AsyncMock(side_effect=RuntimeError("network unreachable"))
        p.intel_agent.run   = AsyncMock(return_value={})
        p.exploit_agent.run = AsyncMock(return_value={})

        result = asyncio.run(p.run("10.10.10.1"))
        assert not result.success
        assert result.error is not None
        assert "network unreachable" in result.error

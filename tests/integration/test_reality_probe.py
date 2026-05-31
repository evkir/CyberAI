"""
reality-probe integration tests — mock client, no live server needed.
"""

import pytest
from unittest.mock import MagicMock, patch
from cyberai.integrations.reality_probe_client import RealityProbeClient, TLSResult
from cyberai.agents.recon.tls_tool import TLSTool
from cyberai.agents.intel.tls_cve_mapper import TLSCVEMapper


def make_result(**kwargs) -> TLSResult:
    defaults = dict(
        domain="test.example.com",
        tls_version="TLSv1.3",
        alpn=["h2"],
        cert_expiry_days=90,
        weak_ciphers=[],
        score="IDEAL",
        raw={},
    )
    return TLSResult(**{**defaults, **kwargs})


class TestTLSResult:
    def test_not_expired(self):
        r = make_result(cert_expiry_days=90)
        assert not r.is_expired

    def test_expired(self):
        r = make_result(cert_expiry_days=-1)
        assert r.is_expired

    def test_expiring_soon(self):
        r = make_result(cert_expiry_days=15)
        assert r.is_expiring_soon

    def test_weak_ciphers_flag(self):
        r = make_result(weak_ciphers=["RC4"])
        assert r.has_weak_ciphers


class TestTLSTool:
    def _mock_client(self, result):
        client = MagicMock(spec=RealityProbeClient)
        client.probe.return_value = result
        return client

    def test_ideal_tls_no_findings(self):
        tool = TLSTool(client=self._mock_client(make_result()))
        out = tool.run("test.example.com")
        assert out["score"] == "IDEAL"
        assert out["findings"] == []

    def test_expired_cert_critical(self):
        tool = TLSTool(client=self._mock_client(make_result(cert_expiry_days=-5)))
        out = tool.run("test.example.com")
        severities = [f["severity"] for f in out["findings"]]
        assert "CRITICAL" in severities

    def test_deprecated_tls_high(self):
        tool = TLSTool(client=self._mock_client(make_result(tls_version="TLSv1.0")))
        out = tool.run("test.example.com")
        severities = [f["severity"] for f in out["findings"]]
        assert "HIGH" in severities

    def test_probe_failure_returns_error(self):
        client = MagicMock(spec=RealityProbeClient)
        client.probe.return_value = None
        tool = TLSTool(client=client)
        out = tool.run("dead.example.com")
        assert "error" in out

    def test_weak_cipher_finding(self):
        tool = TLSTool(client=self._mock_client(make_result(weak_ciphers=["RC4"])))
        out = tool.run("test.example.com")
        issues = [f["issue"] for f in out["findings"]]
        assert any("cipher" in i.lower() for i in issues)


class TestTLSCVEMapper:
    def test_tls10_maps_to_cves(self):
        mapper = TLSCVEMapper()
        findings = [{"issue": "Deprecated TLS version", "detail": "TLSv1.0"}]
        enriched = mapper.enrich(findings)
        assert "CVE-2014-3566" in enriched[0]["cves"]

    def test_unknown_issue_empty_cves(self):
        mapper = TLSCVEMapper()
        findings = [{"issue": "Unknown issue", "detail": "something"}]
        enriched = mapper.enrich(findings)
        assert enriched[0]["cves"] == []

    def test_enriched_has_remediation(self):
        mapper = TLSCVEMapper()
        findings = [{"issue": "Certificate expired", "detail": "cert_expired"}]
        enriched = mapper.enrich(findings)
        assert "remediation" in enriched[0]

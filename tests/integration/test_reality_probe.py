"""
reality-probe client and TLS CVE mapping tests.

TLSTool is no longer covered here: its tests drove a MagicMock(spec=...) that
answered whatever the test told it to, so they passed regardless of what the
tool did. Real-socket coverage lives in tests/unit/test_tls_probe.py.
"""

from cyberai.agents.intel.tls_cve_mapper import TLSCVEMapper
from cyberai.integrations.reality_probe_client import TLSResult


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

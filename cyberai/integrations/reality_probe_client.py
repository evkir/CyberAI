"""
reality-probe TLS Analyzer client wrapper.
Talks to reality-probe REST API, parses TLS scan results.
"""
import httpx
from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger("cyberai.integrations.reality_probe")

@dataclass
class TLSResult:
    domain: str
    tls_version: str           # e.g. "TLSv1.3"
    alpn: list[str]            # e.g. ["h2", "http/1.1"]
    cert_expiry_days: int
    weak_ciphers: list[str]
    score: str                 # "IDEAL" | "GOOD" | "AVERAGE" | "POOR"
    raw: dict = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return self.cert_expiry_days <= 0

    @property
    def is_expiring_soon(self) -> bool:
        return 0 < self.cert_expiry_days <= 30

    @property
    def has_weak_ciphers(self) -> bool:
        return len(self.weak_ciphers) > 0


class RealityProbeClient:
    """
    HTTP client for reality-probe TLS analyzer.
    Assumes reality-probe is running at base_url (default: localhost:5000).
    """

    def __init__(self, base_url: str = "http://127.0.0.1:5000", timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def probe(self, domain: str) -> Optional[TLSResult]:
        """
        Probe a domain for TLS configuration.
        Returns TLSResult or None if probe fails.
        """
        try:
            resp = httpx.get(
                f"{self.base_url}/probe",
                params={"domain": domain},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return self._parse(domain, data)
        except httpx.HTTPError as e:
            logger.warning(f"reality-probe request failed for {domain}: {e}")
            return None

    def _parse(self, domain: str, data: dict) -> TLSResult:
        return TLSResult(
            domain=domain,
            tls_version=data.get("tls_version", "unknown"),
            alpn=data.get("alpn", []),
            cert_expiry_days=data.get("cert_expiry_days", -1),
            weak_ciphers=data.get("weak_ciphers", []),
            score=data.get("score", "POOR"),
            raw=data,
        )

    def batch_probe(self, domains: list[str]) -> dict[str, Optional[TLSResult]]:
        """Probe multiple domains, return dict domain→result"""
        return {d: self.probe(d) for d in domains}

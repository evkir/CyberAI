"""
TLS analysis tool for ReconAgent.
Surfaces cert expiry, weak ciphers, TLS version issues.
"""

from cyberai.integrations.reality_probe_client import RealityProbeClient, TLSResult
from cyberai.core.decorators import sanitize_input, log_agent_action
from dataclasses import dataclass
from typing import Optional
import logging

logger = logging.getLogger("cyberai.recon.tls")


@dataclass
class TLSFinding:
    domain: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    issue: str
    detail: str


def _classify_findings(result: TLSResult) -> list[TLSFinding]:
    findings = []

    if result.is_expired:
        findings.append(
            TLSFinding(
                domain=result.domain,
                severity="CRITICAL",
                issue="Certificate expired",
                detail=f"Cert expired {abs(result.cert_expiry_days)} days ago",
            )
        )
    elif result.is_expiring_soon:
        findings.append(
            TLSFinding(
                domain=result.domain,
                severity="HIGH",
                issue="Certificate expiring soon",
                detail=f"Expires in {result.cert_expiry_days} days",
            )
        )

    if result.tls_version in ("TLSv1.0", "TLSv1.1"):
        findings.append(
            TLSFinding(
                domain=result.domain,
                severity="HIGH",
                issue="Deprecated TLS version",
                detail=f"Server supports {result.tls_version} — deprecated since RFC 8996",
            )
        )

    for cipher in result.weak_ciphers:
        findings.append(
            TLSFinding(
                domain=result.domain,
                severity="MEDIUM",
                issue="Weak cipher suite",
                detail=f"Cipher {cipher} is considered weak",
            )
        )

    if result.score == "POOR":
        findings.append(
            TLSFinding(
                domain=result.domain,
                severity="HIGH",
                issue="Poor TLS score",
                detail="reality-probe scored this target POOR — review full TLS config",
            )
        )

    return findings


class TLSTool:
    """ReconAgent tool: runs TLS analysis via reality-probe"""

    def __init__(self, client: Optional[RealityProbeClient] = None):
        self.client = client or RealityProbeClient()

    @sanitize_input
    @log_agent_action
    def run(self, domain: str) -> dict:
        """
        Probe domain TLS config, return structured findings.
        """
        result = self.client.probe(domain)
        if result is None:
            return {"error": f"TLS probe failed for {domain}", "findings": []}

        findings = _classify_findings(result)

        logger.info(f"TLS scan {domain}: score={result.score}, findings={len(findings)}")

        return {
            "domain": domain,
            "tls_version": result.tls_version,
            "score": result.score,
            "cert_expiry_days": result.cert_expiry_days,
            "findings": [
                {
                    "severity": f.severity,
                    "issue": f.issue,
                    "detail": f.detail,
                }
                for f in findings
            ],
        }

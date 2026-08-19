"""
TLS analysis tool for ReconAgent.

Surfaces cert expiry, weak ciphers, and TLS version issues from a real
handshake against the target.

Finding details carry the mapper's issue keys verbatim (cert_expired, RC4,
NULL_cipher, TLSv1.0) so TLSCVEMapper can attach CVE context: it matches by
substring over issue and detail, and prose alone never matched.
"""

import logging
from dataclasses import dataclass

from cyberai.agents.recon.tls_probe import TLSProbeResult, probe_tls
from cyberai.core.decorators import log_agent_action, sanitize_input

logger = logging.getLogger("cyberai.recon.tls")

# Cipher name fragments that make a suite weak, mapped to the token the CVE
# mapper indexes on. Substring match over the negotiated suite name.
WEAK_CIPHER_TOKENS: dict[str, str] = {
    "RC4": "RC4",
    "NULL": "NULL_cipher",
    "DES": "DES",
    "MD5": "MD5",
    "EXPORT": "EXPORT",
    "anon": "anon",
}

DEPRECATED_TLS = ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2")


@dataclass
class TLSFinding:
    domain: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    issue: str
    detail: str


def _weak_tokens(cipher: str) -> list[str]:
    """Weakness tokens present in a negotiated cipher suite name."""
    upper = cipher.upper()
    return [token for fragment, token in WEAK_CIPHER_TOKENS.items() if fragment.upper() in upper]


def _classify_findings(result: TLSProbeResult) -> list[TLSFinding]:
    findings = []

    if result.is_expired:
        findings.append(
            TLSFinding(
                domain=result.domain,
                severity="CRITICAL",
                issue="Certificate expired",
                detail=f"cert_expired — expired {abs(result.cert_expiry_days)} days ago",
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
    elif not result.cert_valid and result.reachable and result.cert_error:
        # Untrusted for a reason other than expiry: self-signed, wrong host,
        # unknown issuer. Distinct from expiry, which has its own severity.
        findings.append(
            TLSFinding(
                domain=result.domain,
                severity="MEDIUM",
                issue="Certificate not trusted",
                detail=f"{result.cert_error} (issuer: {result.cert_issuer or 'unknown'})",
            )
        )

    if result.tls_version in DEPRECATED_TLS:
        findings.append(
            TLSFinding(
                domain=result.domain,
                severity="HIGH",
                issue="Deprecated TLS version",
                detail=f"Server negotiated {result.tls_version} — deprecated since RFC 8996",
            )
        )

    for token in _weak_tokens(result.cipher):
        findings.append(
            TLSFinding(
                domain=result.domain,
                severity="MEDIUM",
                issue="Weak cipher suite",
                detail=f"{token} in negotiated suite {result.cipher}",
            )
        )

    return findings


class TLSTool:
    """ReconAgent tool: runs TLS analysis against the target."""

    @sanitize_input
    @log_agent_action
    def run(self, domain: str) -> dict:
        """Probe domain TLS config, return structured findings."""
        result = probe_tls(domain)

        if not result.reachable:
            return {
                "error": f"TLS probe failed for {domain}: {result.error or 'no handshake'}",
                "findings": [],
            }

        findings = _classify_findings(result)
        logger.info(
            f"TLS scan {domain}: {result.tls_version}, cert_valid={result.cert_valid}, "
            f"findings={len(findings)}"
        )
        return {
            "domain": domain,
            "tls_version": result.tls_version,
            "cipher": result.cipher,
            "alpn": result.alpn,
            "cert_valid": result.cert_valid,
            "cert_issuer": result.cert_issuer,
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

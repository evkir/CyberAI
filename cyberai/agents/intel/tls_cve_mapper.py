"""
Maps TLS misconfigurations to known CVEs.
Gives IntelAgent context: "this TLS issue → these CVEs → this risk".
"""

from dataclasses import dataclass


@dataclass
class TLSCVEEntry:
    issue_key: str  # e.g. "TLSv1.0"
    cves: list[str]
    description: str
    remediation: str


# Static mapping — extend as needed
TLS_CVE_MAP: list[TLSCVEEntry] = [
    TLSCVEEntry(
        issue_key="TLSv1.0",
        cves=["CVE-2011-3389", "CVE-2014-3566"],
        description="TLS 1.0 vulnerable to BEAST and POODLE attacks",
        remediation="Disable TLS 1.0/1.1, enforce TLS 1.2 minimum",
    ),
    TLSCVEEntry(
        issue_key="TLSv1.1",
        cves=["CVE-2014-3566"],
        description="TLS 1.1 vulnerable to POODLE attack",
        remediation="Disable TLS 1.1, enforce TLS 1.2 minimum",
    ),
    TLSCVEEntry(
        issue_key="RC4",
        cves=["CVE-2013-2566", "CVE-2015-2808"],
        description="RC4 cipher is cryptographically broken",
        remediation="Remove RC4 from cipher suite configuration",
    ),
    TLSCVEEntry(
        issue_key="NULL_cipher",
        cves=["CVE-2014-0224"],
        description="NULL cipher provides no encryption",
        remediation="Remove NULL ciphers, enforce authenticated encryption",
    ),
    TLSCVEEntry(
        issue_key="cert_expired",
        cves=[],
        description="Expired certificate — clients will reject connection",
        remediation="Renew certificate immediately",
    ),
]


class TLSCVEMapper:
    """
    Given TLS findings from TLSTool, enrich with CVE context.
    """

    def __init__(self):
        self._index = {e.issue_key: e for e in TLS_CVE_MAP}

    def enrich(self, findings: list[dict]) -> list[dict]:
        """
        Takes TLSTool findings list, adds CVE context to each.
        """
        enriched = []
        for finding in findings:
            entry = self._match(finding)
            enriched.append(
                {
                    **finding,
                    "cves": entry.cves if entry else [],
                    "remediation": entry.remediation if entry else "Review TLS configuration",
                }
            )
        return enriched

    def _match(self, finding: dict):
        issue = finding.get("issue", "")
        detail = finding.get("detail", "")
        for key, entry in self._index.items():
            if key in issue or key in detail:
                return entry
        return None

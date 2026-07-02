"""Transport-authentication posture assessment for target MCP endpoints.

MCP has no in-protocol attestation of a server's identity or of the capability
set it advertises: ``serverInfo`` (name/version) is self-asserted and the
capabilities returned at ``initialize`` are unsigned. The only authentication
the protocol defines lives at the transport layer (OAuth 2.0 for HTTP/SSE;
RFC 9728 protected-resource metadata). There is nothing to verify per-message
or per-capability.

This module therefore does not look for a signature that cannot exist. It
reports the transport-authentication posture observed during the probe:

* stdio - no network origin; authentication is the local process trust
  boundary. Not a network finding.
* HTTP/SSE, session established - the probe completed ``initialize`` and dumped
  the tool surface without supplying any credential, so the endpoint accepts
  unauthenticated MCP sessions. Anyone able to reach it can enumerate and
  invoke its tools (the CVE-2025-49596 exposure class). Reported HIGH.
* HTTP/SSE, session not established - the probe could not complete a session. A
  protected endpoint answering an anonymous probe with an auth-required
  response is indistinguishable from an unreachable one, so the posture is
  undetermined rather than clean.

Plaintext ``http://`` is additionally noted: without TLS the transport offers
no origin integrity and the session is trivially machine-in-the-middle-able.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from cyberai.core.scan_session import Severity

_SELF_ASSERTED_IDENTITY = (
    "serverInfo (name/version) is self-asserted and unsigned; MCP has no "
    "in-protocol identity or capability attestation"
)


@dataclass
class AttestationScan:
    """Transport-authentication posture of a single MCP endpoint."""

    endpoint: str
    transport: str
    connected: bool = False
    unauthenticated: bool = False
    transport_encrypted: bool = True
    severity: str = Severity.INFO.value
    reasons: list[str] = field(default_factory=list)

    @property
    def is_finding(self) -> bool:
        # Only the positively observed case - an endpoint that let an anonymous
        # probe complete a session - is a finding. stdio and undetermined
        # remote postures stay in the inventory without one.
        return self.unauthenticated

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["is_finding"] = self.is_finding
        return data


def _is_encrypted(endpoint: str, transport: str) -> bool:
    # sse:// is mapped to https by the probe; only literal http:// is plaintext.
    if transport == "http" and endpoint.startswith("http://"):
        return False
    return True


def assess_attestation(
    endpoint: str,
    transport: str,
    connected: bool,
    error: str | None = None,
) -> AttestationScan:
    """Assess the transport-authentication posture of an MCP endpoint.

    Inputs come straight from :class:`MCPProbeResult`. The probe never supplies
    a credential, so ``connected`` on a remote transport means the endpoint
    accepted an anonymous session.
    """
    scan = AttestationScan(endpoint=endpoint, transport=transport)

    if transport == "stdio":
        scan.reasons.append(
            "stdio transport has no network origin; authentication is the local "
            "process trust boundary and message/origin auth does not apply"
        )
        return scan

    scan.transport_encrypted = _is_encrypted(endpoint, transport)
    scan.reasons.append(_SELF_ASSERTED_IDENTITY)

    if connected:
        scan.unauthenticated = True
        scan.severity = Severity.HIGH.value
        scan.reasons.append(
            "endpoint completed MCP initialize and exposed its tool surface with "
            "no credential supplied; any client that can reach it can enumerate "
            "and invoke tools (CVE-2025-49596 exposure class)"
        )
    else:
        scan.severity = Severity.LOW.value
        detail = f" (probe error: {error})" if error else ""
        scan.reasons.append(
            "probe did not complete a session; a protected endpoint returning an "
            "auth-required response is indistinguishable from an unreachable one "
            f"here, so the auth posture is undetermined{detail}"
        )

    if not scan.transport_encrypted:
        scan.reasons.append(
            "plaintext http:// transport provides no TLS origin integrity and is "
            "trivially machine-in-the-middle-able"
        )

    return scan

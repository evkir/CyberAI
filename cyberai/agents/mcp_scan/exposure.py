"""Network-exposure and DNS-rebinding risk assessment for MCP endpoints.

The MCP HTTP/SSE transports turn an MCP server into a localhost (or worse,
network-bound) HTTP service. The transport spec requires servers to validate
the ``Origin`` header and bind to 127.0.0.1 rather than 0.0.0.0; servers that
do neither are reachable by DNS-rebinding, where a malicious web page rebinds
its own domain to the victim's loopback and drives the local MCP server's tools
from the browser. Paired with an exec- or credential-capable tool, that is a
remote-code-execution / exfiltration primitive against a "local-only" server.

This stage assesses exposure purely from what the probe already knows — the
endpoint string and transport — and cross-references the tool capability
surface so a rebindable server that also exposes dangerous tools is escalated.
This is a static inference about reachability, not an executed rebinding attack.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

from cyberai.agents.mcp_scan.overprivilege import map_capability_surfaces
from cyberai.core.scan_session import Severity

# Hosts that expose the server beyond the loopback interface. 0.0.0.0 / :: bind
# to every interface; an empty host (relative URL) is treated as unknown-network.
_NON_LOOPBACK_BINDS = {"0.0.0.0", "::", "[::]"}
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
# Capability classes that turn browser-driven tool invocation into RCE / exfil.
_DANGEROUS_CAPS = {"exec", "cred", "fs_read", "fs_write", "db"}


@dataclass
class ExposureScan:
    """DNS-rebinding / network-exposure assessment of an MCP endpoint."""

    endpoint: str
    transport: str
    bind_host: str | None = None
    severity: str = Severity.INFO.value
    rebinding_risk: bool = False
    reasons: list[str] = field(default_factory=list)
    dangerous_capabilities: list[str] = field(default_factory=list)

    @property
    def is_exposed(self) -> bool:
        return self.rebinding_risk

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["is_exposed"] = self.is_exposed
        return data


def _parse_bind_host(endpoint: str, transport: str) -> str | None:
    """Extract the bind host from an HTTP/SSE endpoint, or None for stdio."""
    if transport == "stdio":
        return None
    url = endpoint
    if url.startswith("sse://"):
        url = url.replace("sse://", "https://", 1)
    host = urlparse(url).hostname
    return host


def assess_exposure(
    endpoint: str,
    transport: str,
    tools: list[dict[str, Any]],
) -> ExposureScan:
    """Assess DNS-rebinding / network-exposure risk of an MCP endpoint.

    stdio endpoints are not network-reachable and score INFO. HTTP/SSE
    endpoints are rebinding targets; a non-loopback bind (0.0.0.0) is worse
    than loopback, and either is escalated to CRITICAL when the server also
    advertises exec/credential/filesystem/database tools.
    """
    scan = ExposureScan(endpoint=endpoint, transport=transport)
    if transport == "stdio":
        scan.reasons.append(
            "stdio transport is not network-reachable; DNS rebinding does not apply"
        )
        return scan

    host = _parse_bind_host(endpoint, transport)
    scan.bind_host = host
    scan.rebinding_risk = True

    caps: set[str] = set()
    for surface in map_capability_surfaces(tools):
        caps.update(surface.capabilities)
    dangerous = sorted(caps & _DANGEROUS_CAPS)
    scan.dangerous_capabilities = dangerous

    non_loopback = host in _NON_LOOPBACK_BINDS or host is None
    if non_loopback:
        scan.reasons.append(
            f"{transport} transport bound to non-loopback host "
            f"({host or 'unspecified'}) is reachable across the network"
        )
    else:
        scan.reasons.append(
            f"{transport} transport on {host} is a DNS-rebinding target unless the "
            "server validates the Origin header (not observable from the client side)"
        )

    if dangerous:
        scan.severity = Severity.CRITICAL.value
        scan.reasons.append(
            f"browser-driven tool calls could reach dangerous capabilities "
            f"({', '.join(dangerous)}) for RCE / exfiltration"
        )
    elif non_loopback:
        scan.severity = Severity.HIGH.value
    else:
        scan.severity = Severity.MEDIUM.value

    return scan

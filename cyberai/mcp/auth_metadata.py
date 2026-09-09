"""OAuth metadata posture of an HTTP/SSE MCP endpoint.

MCP defines no in-protocol authentication; everything it has lives at the
transport layer, and since revision 2025-06-18 that means RFC 9728 protected
resource metadata plus RFC 8707 resource indicators. This module reads that
posture and reports it. It authenticates nothing and requests no token: every
document it fetches is one the server publishes for unauthenticated clients.

Two measured facts shaped the design.

First, the metadata pointer comes from the challenge, not from a guess. All
three public servers measured on 2026-09-09 answer an unauthenticated
initialize with ``401`` and a ``WWW-Authenticate`` header naming
``/.well-known/oauth-protected-resource/mcp`` -- the path-inserted form of
RFC 9728 section 3.1. One of them serves nothing at the bare well-known path,
so a scanner that only probes the bare path reports "no PRM" for a server that
publishes one. Guessing is kept as a fallback and is labelled as a guess.

Second, ``client_id_metadata_document_supported`` is already deployed while
``registration_endpoint`` is still advertised beside it, so CIMD and the
deprecated DCR path are not exclusive in the wild. Both are recorded; neither
is inferred from the other.

RFC 9207's ``authorization_response_iss_parameter_supported`` was absent from
all three documents. Absent is not false: it is recorded as ``None``, because
a server that never mentions the parameter and a server that declines it are
different measurements.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

_RESOURCE_METADATA = re.compile(r'resource_metadata="([^"]+)"')
_PRM_PATH = "/.well-known/oauth-protected-resource"
_AS_PATH = "/.well-known/oauth-authorization-server"
_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "cyberai", "version": "0"},
    },
}


@dataclass
class AuthMetadata:
    """Transport-layer authorization posture of one MCP endpoint."""

    endpoint: str
    applicable: bool = True
    challenged: bool | None = None
    resource_metadata_url: str | None = None
    prm_source: str = "none"
    prm_present: bool = False
    resource: str | None = None
    authorization_servers: list[str] = field(default_factory=list)
    issuer: str | None = None
    dcr_offered: bool | None = None
    cimd_supported: bool | None = None
    iss_parameter_advertised: bool | None = None
    error: str | None = None

    @property
    def resource_scope(self) -> str | None:
        """How the token audience relates to the endpoint actually scanned.

        RFC 8707 binds a token to the resource named here. ``exact`` is the
        intended case. ``wider`` means the resource is a prefix of the
        endpoint -- typically the bare origin -- so one token covers whatever
        else lives there. ``unrelated`` means the document describes something
        that is not this endpoint at all. ``None`` when no resource was read.
        """
        if not self.resource:
            return None
        resource = self.resource.rstrip("/")
        endpoint = self.endpoint.rstrip("/")
        if resource == endpoint:
            return "exact"
        if endpoint.startswith(resource + "/"):
            return "wider"
        return "unrelated"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["resource_scope"] = self.resource_scope
        return data


def _as_http(endpoint: str) -> str:
    return endpoint.replace("sse://", "https://", 1)


def _well_known(base: str, path: str) -> list[str]:
    """Candidate well-known URLs, path-inserted form first (RFC 9728 s3.1)."""
    parts = urlsplit(base)
    resource_path = parts.path.rstrip("/")
    candidates = []
    if resource_path:
        candidates.append(urlunsplit((parts.scheme, parts.netloc, path + resource_path, "", "")))
    candidates.append(urlunsplit((parts.scheme, parts.netloc, path, "", "")))
    return candidates


def _json(client: httpx.Client, url: str) -> dict[str, Any] | None:
    try:
        response = client.get(url)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        body = response.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def probe_auth_metadata(
    endpoint: str,
    mcp_transport: str,
    *,
    client: httpx.Client | None = None,
) -> AuthMetadata:
    """Read the published authorization metadata for one MCP endpoint.

    ``stdio`` has no network origin, so none of this applies to it and saying
    "no PRM" there would be a finding invented out of a category error.
    """
    if mcp_transport == "stdio":
        return AuthMetadata(endpoint=endpoint, applicable=False)

    url = _as_http(endpoint)
    result = AuthMetadata(endpoint=url)
    owned = client is None
    client = client or httpx.Client(timeout=10.0, follow_redirects=True)
    try:
        try:
            challenge = client.post(
                url,
                json=_INITIALIZE,
                headers={"Accept": "application/json, text/event-stream"},
            )
        except httpx.HTTPError as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            return result

        result.challenged = challenge.status_code == 401
        header = challenge.headers.get("www-authenticate", "")
        match = _RESOURCE_METADATA.search(header)
        if match:
            result.resource_metadata_url = match.group(1)
            result.prm_source = "header"
            candidates = [match.group(1)]
        else:
            candidates = _well_known(url, _PRM_PATH)

        prm = None
        for candidate in candidates:
            prm = _json(client, candidate)
            if prm is not None:
                result.resource_metadata_url = candidate
                if result.prm_source != "header":
                    result.prm_source = "guessed"
                break
        if prm is None:
            return result

        result.prm_present = True
        resource = prm.get("resource")
        result.resource = str(resource) if isinstance(resource, str) else None
        servers = prm.get("authorization_servers")
        if isinstance(servers, list):
            result.authorization_servers = [str(s) for s in servers]
        if not result.authorization_servers:
            return result

        for candidate in _well_known(result.authorization_servers[0], _AS_PATH):
            metadata = _json(client, candidate)
            if metadata is None:
                continue
            issuer = metadata.get("issuer")
            result.issuer = str(issuer) if isinstance(issuer, str) else None
            result.dcr_offered = "registration_endpoint" in metadata
            # Absent is not false: a document that never mentions the key is
            # not a server that declined the capability.
            result.cimd_supported = (
                bool(metadata["client_id_metadata_document_supported"])
                if "client_id_metadata_document_supported" in metadata
                else None
            )
            result.iss_parameter_advertised = (
                bool(metadata["authorization_response_iss_parameter_supported"])
                if "authorization_response_iss_parameter_supported" in metadata
                else None
            )
            break
        return result
    finally:
        if owned:
            client.close()

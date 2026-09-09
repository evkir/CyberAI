"""Authorization posture of an MCP endpoint, against the shapes measured live.

The fixtures below reproduce what three public MCP servers answered on
2026-09-09: a 401 whose WWW-Authenticate names a path-inserted metadata
document, nothing at all at the bare well-known path, CIMD advertised
alongside a still-offered registration endpoint, and no mention of the RFC
9207 iss parameter anywhere.
"""

from __future__ import annotations

import json

import httpx

from cyberai.mcp.auth_metadata import probe_auth_metadata

ENDPOINT = "https://mcp.example.dev/mcp"
POINTED = "https://mcp.example.dev/.well-known/oauth-protected-resource/mcp"
BARE = "https://mcp.example.dev/.well-known/oauth-protected-resource"
AS_METADATA = "https://mcp.example.dev/.well-known/oauth-authorization-server"

PRM = {
    "resource": "https://mcp.example.dev/mcp",
    "authorization_servers": ["https://mcp.example.dev"],
    "scopes_supported": ["org:read"],
    "bearer_methods_supported": ["header"],
}
AS_DOC = {
    "issuer": "https://mcp.example.dev",
    "authorization_endpoint": "https://mcp.example.dev/oauth/authorize",
    "token_endpoint": "https://mcp.example.dev/oauth/token",
    "registration_endpoint": "https://mcp.example.dev/oauth/register",
    "client_id_metadata_document_supported": True,
}
CHALLENGE = f'Bearer realm="OAuth", error="invalid_token", resource_metadata="{POINTED}"'


def _client(*, prm_at_bare: bool = False, challenge: bool = True, as_doc=AS_DOC) -> httpx.Client:
    """A server that publishes PRM only where the challenge points, as measured."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "POST" and url == ENDPOINT:
            if not challenge:
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})
            return httpx.Response(401, headers={"WWW-Authenticate": CHALLENGE}, json={})
        if url == POINTED:
            return httpx.Response(200, json=PRM)
        if url == BARE:
            return httpx.Response(200, json=PRM) if prm_at_bare else httpx.Response(404)
        if url == AS_METADATA:
            if as_doc is None:
                return httpx.Response(404)
            return httpx.Response(
                200,
                content=json.dumps(as_doc),
                headers={"content-type": "application/json"},
            )
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_stdio_has_no_network_origin_so_nothing_applies():
    result = probe_auth_metadata("python3 -m server", "stdio")

    assert result.applicable is False
    assert result.prm_present is False
    assert result.challenged is None


def test_the_metadata_pointer_comes_from_the_challenge_not_from_a_guess():
    """The bare well-known path 404s here, exactly as one live server does."""
    with _client() as client:
        result = probe_auth_metadata(ENDPOINT, "http", client=client)

    assert result.challenged is True
    assert result.prm_source == "header"
    assert result.resource_metadata_url == POINTED
    assert result.prm_present is True


def test_a_server_that_does_not_challenge_still_gets_the_well_known_guess():
    with _client(challenge=False, prm_at_bare=True) as client:
        result = probe_auth_metadata(ENDPOINT, "http", client=client)

    assert result.challenged is False
    assert result.prm_source == "guessed"
    assert result.prm_present is True


def test_registration_and_cimd_are_recorded_separately():
    """Both were advertised together on every live server measured."""
    with _client() as client:
        result = probe_auth_metadata(ENDPOINT, "http", client=client)

    assert result.issuer == "https://mcp.example.dev"
    assert result.dcr_offered is True
    assert result.cimd_supported is True


def test_an_absent_iss_parameter_is_unknown_not_refused():
    with _client() as client:
        result = probe_auth_metadata(ENDPOINT, "http", client=client)

    assert result.iss_parameter_advertised is None


def test_a_declared_iss_parameter_is_read_as_declared():
    doc = dict(AS_DOC, authorization_response_iss_parameter_supported=False)
    with _client(as_doc=doc) as client:
        result = probe_auth_metadata(ENDPOINT, "http", client=client)

    assert result.iss_parameter_advertised is False


def test_a_resource_equal_to_the_endpoint_is_an_exact_audience():
    with _client() as client:
        result = probe_auth_metadata(ENDPOINT, "http", client=client)

    assert result.resource == ENDPOINT
    assert result.resource_scope == "exact"


def test_a_resource_at_the_bare_origin_is_a_wider_audience():
    """One live server's bare-path document named the origin, not the endpoint."""
    prm = dict(PRM, resource="https://mcp.example.dev")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(401, headers={"WWW-Authenticate": CHALLENGE}, json={})
        if str(request.url) == POINTED:
            return httpx.Response(200, json=prm)
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = probe_auth_metadata(ENDPOINT, "http", client=client)

    assert result.resource == "https://mcp.example.dev"
    assert result.resource_scope == "wider"


def test_an_unreachable_endpoint_records_the_error_and_claims_nothing():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = probe_auth_metadata(ENDPOINT, "http", client=client)

    assert result.error is not None
    assert result.prm_present is False
    assert result.dcr_offered is None

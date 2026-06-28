"""MCP client probe — connect to a target MCP server and inventory its surface.

This is the read side of CyberAI's offensive MCP tooling: given a target MCP
endpoint (stdio command, SSE URL, or streamable-HTTP URL), it opens a client
session and dumps the full advertised capability surface (tools, prompts,
resources) with pagination. The raw metadata is preserved verbatim — including
each tool's ``annotations`` and ``meta`` fields — because hidden instructions in
that metadata are exactly what later analysis stages inspect.

Connection failures never raise: the probe records the error on the result and
returns, so a scan over many endpoints degrades gracefully.
"""

from __future__ import annotations

import shlex
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamablehttp_client

Transport = Literal["stdio", "sse", "http"]


@dataclass
class MCPProbeResult:
    """Inventory of a single target MCP server's advertised surface."""

    endpoint: str
    transport: Transport
    connected: bool = False
    server_name: str | None = None
    server_version: str | None = None
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_transport(endpoint: str) -> Transport:
    """Infer the transport from an endpoint string.

    HTTP(S) URLs default to streamable-HTTP (the current transport); SSE must be
    requested explicitly via an ``sse://`` scheme or an explicit ``transport``
    argument. Anything else is treated as a stdio command line.
    """
    if endpoint.startswith("sse://"):
        return "sse"
    if endpoint.startswith(("http://", "https://")):
        return "http"
    return "stdio"


def _stdio_params(endpoint: str) -> StdioServerParameters:
    parts = shlex.split(endpoint)
    if not parts:
        raise ValueError("empty stdio command")
    return StdioServerParameters(command=parts[0], args=parts[1:])


@asynccontextmanager
async def _open_streams(endpoint: str, transport: Transport) -> AsyncIterator[tuple[Any, Any]]:
    """Yield (read, write) streams for the chosen transport.

    The transports unpack asymmetrically: ``streamablehttp_client`` yields a
    3-tuple (read, write, get_session_id) while ``stdio_client`` and
    ``sse_client`` yield a 2-tuple. This helper hides that difference so the
    probe body only ever sees (read, write).
    """
    if transport == "stdio":
        async with stdio_client(_stdio_params(endpoint)) as (read, write):
            yield read, write
    elif transport == "sse":
        url = endpoint.replace("sse://", "https://", 1)
        async with sse_client(url) as (read, write):
            yield read, write
    else:  # http
        async with streamablehttp_client(endpoint) as (read, write, _get_session_id):
            yield read, write


async def _dump(
    list_fn: Callable[..., Awaitable[Any]],
    attr: str,
) -> list[dict[str, Any]]:
    """Page through a list_* call and serialize every item to a JSON-safe dict.

    A server that does not implement a given capability raises rather than
    returning an empty list, so failures here are swallowed and yield ``[]``.
    """
    items: list[Any] = []
    cursor: str | None = None
    try:
        while True:
            result = await list_fn(cursor=cursor)
            items.extend(getattr(result, attr))
            cursor = result.nextCursor
            if not cursor:
                break
    except Exception:  # noqa: BLE001 — capability simply unsupported by target
        return []
    return [item.model_dump(mode="json", exclude_none=True) for item in items]


async def probe(endpoint: str, transport: Transport | None = None) -> MCPProbeResult:
    """Connect to a target MCP endpoint and inventory its capability surface."""
    transport = transport or detect_transport(endpoint)
    result = MCPProbeResult(endpoint=endpoint, transport=transport)
    try:
        async with _open_streams(endpoint, transport) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                result.connected = True
                result.server_name = init.serverInfo.name
                result.server_version = init.serverInfo.version
                result.tools = await _dump(session.list_tools, "tools")
                result.prompts = await _dump(session.list_prompts, "prompts")
                result.resources = await _dump(session.list_resources, "resources")
    except Exception as exc:  # noqa: BLE001 — surface connection errors on result
        result.error = f"{type(exc).__name__}: {exc}"
    return result

"""MCP client probe: inventory against an in-memory server, graceful on failure.

Uses the SDK's in-memory transport to connect the probe to CyberAI's own MCP
server (no subprocess, no network), then asserts the capability dump and the
graceful failure path on an unreachable endpoint.
"""

from __future__ import annotations

import asyncio
import json

from mcp.shared.memory import create_client_server_memory_streams

from cyberai.mcp.client_probe import inventory, probe
from cyberai.mcp.server import server as cyberai_mcp_server


def _inventory_against_server() -> dict:
    """Connect the probe to CyberAI's own MCP server over in-memory streams.

    mcp 2.0 removed create_connected_server_and_client_session, so the pairing
    is assembled by hand: the server runs in a background task while the
    client session initialises against the other end of the same stream pair.
    """

    async def _run() -> dict:
        import anyio
        from mcp import ClientSession

        async with create_client_server_memory_streams() as (client_streams, server_streams):
            client_read, client_write = client_streams
            server_read, server_write = server_streams

            async with anyio.create_task_group() as tg:

                async def _serve() -> None:
                    await cyberai_mcp_server.run(
                        server_read,
                        server_write,
                        cyberai_mcp_server.create_initialization_options(),
                        raise_exceptions=True,
                    )

                tg.start_soon(_serve)
                async with ClientSession(client_read, client_write) as session:
                    await session.initialize()
                    surface = await inventory(session)
                tg.cancel_scope.cancel()
                return surface

    return asyncio.run(_run())


def test_inventory_dumps_registered_tools():
    surface = _inventory_against_server()
    names = {t["name"] for t in surface["tools"]}
    assert names, "probe found no tools on the CyberAI MCP server"
    # the server advertises recon tooling
    assert any(("nmap" in n) or ("dns" in n) or ("whois" in n) for n in names)


def test_inventory_preserves_tool_metadata():
    surface = _inventory_against_server()
    tool = surface["tools"][0]
    # full per-tool metadata is preserved for later poisoning analysis
    assert "name" in tool
    assert "inputSchema" in tool
    assert isinstance(tool["inputSchema"], dict)


def test_probe_graceful_on_unreachable_endpoint():
    # a stdio command that cannot start: probe records the error, never raises
    result = asyncio.run(probe("cyberai_nonexistent_binary_xyz123", "stdio"))
    assert result.connected is False
    assert result.error is not None
    assert result.tools == []


def _call_tool_against_server(name: str, arguments: dict) -> object:
    """Drive one tool call through the SDK, exercising the server adapter."""

    async def _run() -> object:
        import anyio
        from mcp import ClientSession

        async with create_client_server_memory_streams() as (client_streams, server_streams):
            client_read, client_write = client_streams
            server_read, server_write = server_streams

            async with anyio.create_task_group() as tg:

                async def _serve() -> None:
                    await cyberai_mcp_server.run(
                        server_read,
                        server_write,
                        cyberai_mcp_server.create_initialization_options(),
                        raise_exceptions=True,
                    )

                tg.start_soon(_serve)
                async with ClientSession(client_read, client_write) as session:
                    await session.initialize()
                    result = await session.call_tool(name, arguments)
                tg.cancel_scope.cancel()
                return result

    return asyncio.run(_run())


def test_call_tool_reaches_the_handler_through_the_sdk():
    """The dispatch adapter is only exercised over a real session.

    list_tools alone leaves the call path untested, and a broken adapter
    fails the way everything else in this migration did: quietly, with an
    empty or error payload rather than an exception.
    """
    result = _call_tool_against_server("mcp_scan", {"endpoint": "http://unreachable.invalid/mcp"})
    payload = json.loads(result.content[0].text)
    assert isinstance(payload, dict)
    assert payload.get("connected") is False


def test_dumped_tools_use_protocol_field_names():
    """Consumers key off the wire spelling, so the dump must not drift to it.

    mcp 2.0 renamed the python attribute to input_schema while the protocol
    field stayed inputSchema. A dump without by_alias hands poisoning and
    overprivilege analysis an empty schema -- no error, no finding, no signal.
    """
    surface = _inventory_against_server()
    for tool in surface["tools"]:
        assert "inputSchema" in tool
        assert "input_schema" not in tool

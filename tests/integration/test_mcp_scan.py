"""MCP client probe: inventory against an in-memory server, graceful on failure.

Uses the SDK's in-memory transport to connect the probe to CyberAI's own MCP
server (no subprocess, no network), then asserts the capability dump and the
graceful failure path on an unreachable endpoint.
"""

from __future__ import annotations

import asyncio

from mcp.shared.memory import create_connected_server_and_client_session

from cyberai.mcp.client_probe import inventory, probe
from cyberai.mcp.server import server as cyberai_mcp_server


def _inventory_against_server() -> dict:
    async def _run() -> dict:
        async with create_connected_server_and_client_session(cyberai_mcp_server) as session:
            return await inventory(session)

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

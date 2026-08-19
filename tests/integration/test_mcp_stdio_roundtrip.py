"""The documented launch command must serve a live MCP surface over stdio.

``docs/mcp/integration.md`` and ``README.md`` tell users to run
``python -m cyberai.mcp.server``; every unit test so far imported
``list_tools``/``call_tool`` directly and never once started that process.
The SDK 1.x and 2.0 branches of ``_build_server`` had no coverage at all.

Both failure modes here are silent by construction: ``probe`` records
connection errors on the result instead of raising, and ``_dump`` swallows
exceptions into an empty list. A dead server therefore looks exactly like an
empty one -- so these tests assert ``error is None`` *and* a populated
surface, never merely that a result object came back.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client

from cyberai.mcp.client_probe import probe
from cyberai.mcp.tools import TOOL_REGISTRY

REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCH_ARGS = ["-m", "cyberai.mcp.server"]


def test_documented_launch_command_serves_the_whole_tool_surface(monkeypatch):
    """Start the server the way the docs say and inventory it with our probe."""
    monkeypatch.chdir(REPO_ROOT)
    result = asyncio.run(probe(f"{sys.executable} -m cyberai.mcp.server"))

    assert result.error is None, result.error
    assert result.connected is True
    assert result.server_name == "cyberai"
    names = {tool["name"] for tool in result.tools}
    assert names == set(TOOL_REGISTRY), names


def test_call_tool_reaches_our_dispatch_over_the_wire(monkeypatch):
    """An unknown tool name must come back as our structured error text.

    No registered handler is offline -- every one reaches the network -- so an
    unknown name is the only deterministic way to drive the full adapter path:
    transport, SDK handler, ``call_tool``, JSON serialization.
    """
    monkeypatch.chdir(REPO_ROOT)

    async def _call() -> str:
        params = StdioServerParameters(command=sys.executable, args=LAUNCH_ARGS)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                reply = await session.call_tool("does_not_exist", {})
                return reply.content[0].text

    payload = json.loads(asyncio.run(_call()))
    assert "does_not_exist" in payload["error"]

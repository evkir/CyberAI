"""CyberAI MCP server — exposes recon/intel capabilities as MCP tools.

Uses the official mcp Python SDK (low-level Server API). Tools are defined in
cyberai.mcp.tools as a registry of (Tool spec, sync handler) pairs; this module
wires them into the MCP list_tools / call_tool handlers and serves over stdio
so MCP clients (Claude Desktop, Cursor) can drive CyberAI.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from cyberai.mcp.tools import TOOL_REGISTRY

SERVER_NAME = "cyberai"
SERVER_VERSION = "0.4.0"

server: Server = Server(SERVER_NAME, version=SERVER_VERSION)


@server.list_tools()
async def list_tools() -> List[Tool]:
    """Advertise all registered CyberAI tools."""
    return [
        Tool(
            name=name,
            description=spec["description"],
            inputSchema=spec["inputSchema"],
        )
        for name, spec in TOOL_REGISTRY.items()
    ]


@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Dispatch a tool call to its registered sync handler.

    Handlers are plain CyberAI functions; results are JSON-serialized into a
    single TextContent block. Unknown tools and handler errors are reported as
    text rather than raised, so the client always gets a structured reply.
    """
    spec = TOOL_REGISTRY.get(name)
    if spec is None:
        return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]
    try:
        result = spec["handler"](**(arguments or {}))
    except Exception as exc:  # noqa: BLE001 — surface errors to the client
        return [
            TextContent(
                type="text",
                text=json.dumps({"error": f"{type(exc).__name__}: {exc}"}),
            )
        ]
    return [TextContent(type="text", text=json.dumps(result, default=str))]


async def run_stdio() -> None:
    """Serve the CyberAI MCP server over stdio."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    """Entry point: `python -m cyberai.mcp.server`."""
    import asyncio

    asyncio.run(run_stdio())


if __name__ == "__main__":
    main()

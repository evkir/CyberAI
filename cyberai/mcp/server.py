"""CyberAI MCP server — exposes recon/intel capabilities as MCP tools.

Uses the official mcp Python SDK. Tools are defined in cyberai.mcp.tools as a
registry of (Tool spec, sync handler) pairs; this module wires them into the
MCP list_tools / call_tool handlers and serves over stdio so MCP clients
(Claude Desktop, Cursor) can drive CyberAI.

SDK 2.0 dropped the @server.list_tools() decorators in favour of handlers
passed to the constructor, with a request context and a Result wrapper. The
plain list_tools() / call_tool() functions stay the shape they always were --
they are the tested unit -- and thin adapters bridge them to whichever
registration style the installed SDK expects.
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


def _build_server() -> Server:
    """Register the handlers the way the installed SDK accepts."""
    if hasattr(Server, "list_tools"):  # mcp 1.x: decorator registration
        srv: Server = Server(SERVER_NAME, version=SERVER_VERSION)
        srv.list_tools()(list_tools)
        srv.call_tool()(call_tool)
        return srv

    from mcp import types

    async def _on_list_tools(ctx: Any, params: Any) -> Any:
        return types.ListToolsResult(tools=await list_tools())

    async def _on_call_tool(ctx: Any, params: Any) -> Any:
        content = await call_tool(params.name, dict(params.arguments or {}))
        return types.CallToolResult(content=list(content))

    return Server(
        SERVER_NAME,
        version=SERVER_VERSION,
        on_list_tools=_on_list_tools,
        on_call_tool=_on_call_tool,
    )


server: Server = _build_server()


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

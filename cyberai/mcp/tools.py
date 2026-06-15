"""CyberAI MCP tool registry.

Each entry maps a tool name to its MCP spec (description + JSON Schema) and a
sync handler. Recon tools land in commit 2, intel tools in commit 3.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, TypedDict


class ToolSpec(TypedDict):
    description: str
    inputSchema: Dict[str, Any]
    handler: Callable[..., Any]


# Populated by register() calls below; recon/intel tools added in later commits.
TOOL_REGISTRY: Dict[str, ToolSpec] = {}


def register(
    name: str,
    description: str,
    input_schema: Dict[str, Any],
    handler: Callable[..., Any],
) -> None:
    """Register a tool in the global MCP registry."""
    TOOL_REGISTRY[name] = ToolSpec(
        description=description,
        inputSchema=input_schema,
        handler=handler,
    )

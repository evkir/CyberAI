"""MCP server: tool registry, list_tools, call_tool dispatch."""

from __future__ import annotations

import asyncio
import json

from cyberai.mcp.server import call_tool, list_tools
from cyberai.mcp.tools import TOOL_REGISTRY, register


# ── registry ──────────────────────────────────────────────────────────


def test_recon_tools_registered():
    assert {"nmap_scan", "dns_enum", "whois_lookup", "subdomain_enum"} <= set(TOOL_REGISTRY)


def test_intel_tools_registered():
    assert {"cve_search", "cve_detail", "epss_score"} <= set(TOOL_REGISTRY)


def test_all_schemas_are_objects_with_required():
    for name, spec in TOOL_REGISTRY.items():
        sch = spec["inputSchema"]
        assert sch["type"] == "object", name
        assert "properties" in sch, name
        assert isinstance(spec["description"], str) and spec["description"], name


# ── list_tools ────────────────────────────────────────────────────────


def test_list_tools_returns_mcp_tools():
    tools = asyncio.run(list_tools())
    names = {t.name for t in tools}
    assert "nmap_scan" in names and "cve_search" in names
    # every advertised tool carries a non-empty input schema
    assert all(t.inputSchema for t in tools)


# ── call_tool dispatch ────────────────────────────────────────────────


def test_call_tool_dispatches_to_handler():
    register(
        "echo_test",
        "echo",
        {"type": "object", "properties": {"x": {"type": "string"}}},
        lambda x="": {"echoed": x},
    )
    try:
        res = asyncio.run(call_tool("echo_test", {"x": "hi"}))
        assert json.loads(res[0].text) == {"echoed": "hi"}
    finally:
        TOOL_REGISTRY.pop("echo_test", None)


def test_call_tool_unknown_is_graceful():
    res = asyncio.run(call_tool("does_not_exist", {}))
    assert "unknown tool" in res[0].text


def test_call_tool_handler_error_is_graceful():
    register(
        "boom_test",
        "raises",
        {"type": "object", "properties": {}},
        lambda: 1 / 0,
    )
    try:
        res = asyncio.run(call_tool("boom_test", {}))
        assert "ZeroDivisionError" in res[0].text
    finally:
        TOOL_REGISTRY.pop("boom_test", None)


def test_call_tool_result_is_json_text():
    register(
        "list_test",
        "returns list",
        {"type": "object", "properties": {}},
        lambda: {"items": [1, 2, 3]},
    )
    try:
        res = asyncio.run(call_tool("list_test", {}))
        assert res[0].type == "text"
        assert json.loads(res[0].text) == {"items": [1, 2, 3]}
    finally:
        TOOL_REGISTRY.pop("list_test", None)

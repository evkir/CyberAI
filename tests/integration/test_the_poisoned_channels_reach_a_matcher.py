"""Every LLM-visible metadata channel reaches the poisoning matcher.

The stages have only ever met tool dicts built by hand. A dict written in a
test carries whatever spelling the test author chose; the SDK carries the
protocol spelling, and the two parted ways at ``_meta`` -- aliased with a
leading underscore on the wire, read without one by the stage, so a directive
carried there was collected by nobody and scored as clean.

This test drives the stages through the production serialisation instead:
the fixture server advertises one payload per channel, the probe dumps it the
way it dumps a real target, and the assertion is on which channels produced a
signal. A channel nothing collects cannot be scored, and that is the failure
this test exists to name.
"""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
from typing import Any

from mcp.shared.memory import create_client_server_memory_streams

from cyberai.agents.mcp_scan.poisoning import analyze_tools
from cyberai.mcp.client_probe import inventory

# tests/ is not a package, so the stand is loaded by path -- the same way
# test_mcp_stdio_roundtrip.py loads its own fixture server.
POISONED_SERVER = Path(__file__).resolve().parents[1] / "fixtures" / "mcp_poisoned_server.py"


def _load_server() -> Any:
    spec = importlib.util.spec_from_file_location("mcp_poisoned_server", POISONED_SERVER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.server


poisoned_server = _load_server()

# Each fixture tool carries its payload on exactly one channel, so a tool
# missing from the suspicious set names the channel that was never collected.
CHANNELS = {
    "read_notes": "description",
    "search_notes": "inputSchema",
    "export_notes": "outputSchema",
    "sync_notes": "annotations",
    "share_notes": "_meta",
    "render_notes": "icons",
}


def _probe_the_poisoned_stand() -> list[dict]:
    """Dump the fixture server's tool surface over in-memory streams."""

    async def _run() -> list[dict]:
        import anyio
        from mcp import ClientSession

        async with create_client_server_memory_streams() as (client_streams, server_streams):
            client_read, client_write = client_streams
            server_read, server_write = server_streams
            async with anyio.create_task_group() as tg:

                async def _serve() -> None:
                    await poisoned_server.run(
                        server_read,
                        server_write,
                        poisoned_server.create_initialization_options(),
                        raise_exceptions=True,
                    )

                tg.start_soon(_serve)
                async with ClientSession(client_read, client_write) as session:
                    await session.initialize()
                    surface = await inventory(session)
                tg.cancel_scope.cancel()
                return surface["tools"]

    return asyncio.run(_run())


def test_the_probe_delivers_every_poisoned_channel() -> None:
    """The dump carries each channel under its protocol spelling."""
    tools = {t["name"]: t for t in _probe_the_poisoned_stand()}
    assert set(tools) == set(CHANNELS), sorted(tools)
    for name, channel in CHANNELS.items():
        assert channel in tools[name], f"{name}: probe dropped {channel}"


def test_every_delivered_channel_is_collected_by_the_stage() -> None:
    """A channel the probe delivers is a channel the stage scans."""
    tools = _probe_the_poisoned_stand()
    scanned = {s.tool_name: set(s.scanned_fields) for s in analyze_tools(tools)}
    for name, channel in CHANNELS.items():
        assert channel in scanned[name], f"{name}: {channel} delivered but never collected"


def test_a_directive_on_any_channel_is_scored() -> None:
    """Six poisoned tools, six findings: no channel scores clean."""
    scans = analyze_tools(_probe_the_poisoned_stand())
    clean = sorted(s.tool_name for s in scans if not s.is_suspicious)
    assert clean == [], f"poisoned tools scored clean: {clean}"

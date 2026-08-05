"""_run_coro must work from both callers, with and without a live loop.

The agent is reached two ways: the CLI, where nothing is running, and the
MCP server's request handler, where a loop already is. asyncio.run raises in
the second case and the handler turns that exception into the scan result --
an error payload where a capability dump belongs. Both paths are pinned here
because the failure is silent from the client's side.
"""

import asyncio

from cyberai.agents.mcp_scan.agent import _run_coro


async def _answer() -> int:
    return 42


def test_runs_when_no_loop_is_active():
    assert _run_coro(_answer()) == 42


def test_runs_when_a_loop_is_already_turning():
    async def _outer() -> int:
        return _run_coro(_answer())

    assert asyncio.run(_outer()) == 42


def test_propagates_an_exception_from_inside_a_running_loop():
    """A failing probe must raise, not resolve to something falsy."""

    async def _boom() -> int:
        raise ValueError("probe failed")

    async def _outer() -> int:
        return _run_coro(_boom())

    try:
        asyncio.run(_outer())
    except ValueError as exc:
        assert "probe failed" in str(exc)
    else:
        raise AssertionError("exception was swallowed")

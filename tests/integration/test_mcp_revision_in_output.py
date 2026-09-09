"""The negotiated MCP revision must survive probe -> agent -> report -> terminal.

The probe learned the revision in commit 1, but a value nobody prints is a
producer without a consumer. These tests drive the real CLI against the real
server over a real stdio handshake -- the shape production uses -- and compare
what the terminal says with what a bare probe of the same command negotiated.
Asserting a hard-coded date would pin the SDK instead of the wiring.
"""

from __future__ import annotations

import asyncio
import io
import sys

from click.testing import CliRunner
from rich.console import Console

import cyberai.cli.mcp_scan as cli_module
from cyberai.agents.mcp_scan.report import _revision
from cyberai.cli.mcp_scan import mcp_scan
from cyberai.mcp.client_probe import probe

LAUNCH = f"{sys.executable} -m cyberai.mcp.server"


def _negotiated() -> str:
    result = asyncio.run(probe(LAUNCH))
    assert result.error is None, result.error
    assert result.protocol_version is not None
    return result.protocol_version


def test_the_terminal_names_the_revision_the_probe_negotiated():
    negotiated = _negotiated()
    invocation = CliRunner().invoke(mcp_scan, [LAUNCH])

    assert invocation.exit_code == 0, invocation.output
    # rich wraps long lines, so the assertion is on the value alone.
    assert negotiated in invocation.output
    assert "revision" in invocation.output


def test_the_revision_stays_one_token_when_the_terminal_has_colour(monkeypatch):
    """rich colourises digit runs, which would split the date into fragments.

    Whether colour is on depends on the environment, and the module console is
    built at import time, so setting an environment variable inside the test
    changes nothing. The console itself is replaced with one that has colour
    forced on: the printed revision must survive as a single greppable token.
    """
    buffer = io.StringIO()
    monkeypatch.setattr(
        cli_module,
        "console",
        Console(file=buffer, force_terminal=True, color_system="standard", width=200),
    )
    negotiated = _negotiated()
    invocation = CliRunner().invoke(mcp_scan, [LAUNCH])

    assert invocation.exit_code == 0, invocation.output
    printed = buffer.getvalue()
    assert "\x1b[" in printed, "colour was not forced; the test proves nothing"
    assert f"revision: {negotiated}" in printed


def test_the_report_names_the_revision_the_probe_negotiated():
    negotiated = _negotiated()
    invocation = CliRunner().invoke(mcp_scan, [LAUNCH, "--report"])

    assert invocation.exit_code == 0, invocation.output
    assert f"- protocol revision: {negotiated}" in invocation.output


def test_a_session_that_never_connected_negotiated_nothing():
    assert _revision({"connected": False, "protocol_version": None}) == "not negotiated"


def test_a_connected_session_without_a_revision_is_named_not_blended():
    """Losing the value in transit must not read like an honest absence."""
    assert _revision({"connected": True}) == "unreported"

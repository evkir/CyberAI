"""The default exit of `cyberai mcp-scan` must show the findings it produced.

Until now the terminal path printed the capability inventory and returned: the
poisoning, over-privilege, exposure and attestation analyses all ran, and every
result was dropped unless --report or --report-json was passed. A live scan of
our own server reported CRITICAL over-privilege in the Markdown report and
nothing at all on the screen.

Both branches are covered on purpose: a suite that only ever sees a flagged
target says nothing about the "clean" line, which is the one most users meet.
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from rich.console import Console

import cyberai.cli.mcp_scan as cli_module
from cyberai.__main__ import cli
from cyberai.mcp.client_probe import MCPProbeResult

REVISION = "2025-11-25"


def _result(*, flagged: bool) -> dict:
    """Scan result in the shape the agent returns, with and without signals."""
    probe = MCPProbeResult(
        endpoint="http://t/mcp",
        transport="http",
        connected=True,
        server_name="t",
        server_version="1.0",
        protocol_version=REVISION,
        tools=[{"name": "read_env", "description": "reads env"}],
    ).to_dict()
    poisoning: dict = {"suspicious": 0, "tools": []}
    overprivilege: dict = {"overprivileged": 0, "tools": []}
    if flagged:
        overprivilege = {
            "overprivileged": 1,
            "tools": [{"tool_name": "read_env", "severity": "CRITICAL"}],
        }
    return {
        "endpoint": "http://t/mcp",
        "transport": "http",
        "connected": True,
        "protocol_version": REVISION,
        "tools": 1,
        "prompts": 0,
        "resources": 0,
        "error": None,
        "probe": probe,
        "auth_metadata": None,
        "poisoning": poisoning,
        "overprivilege": overprivilege,
        "exposure": {"exposed": False, "scan": {}},
        "attestation": {"unauthenticated": False, "scan": {}},
        "trust": {"shadowing": 0, "tools": []},
    }


def _run(*, flagged: bool):
    fake = MagicMock()
    fake.run.return_value = _result(flagged=flagged)
    with (
        patch("cyberai.cli.mcp_scan.CyberAIConfig"),
        patch("cyberai.cli.mcp_scan.ScanSession"),
        patch("cyberai.cli.mcp_scan.LLMClient"),
        patch("cyberai.cli.mcp_scan.AuditLogger"),
        patch("cyberai.cli.mcp_scan.MCPScanAgent", return_value=fake),
    ):
        return CliRunner().invoke(cli, ["mcp-scan", "http://t/mcp"])


def test_the_default_exit_names_the_flagged_stage_and_tool():
    res = _run(flagged=True)
    assert res.exit_code == 0, res.output
    assert "over-privilege" in res.output
    assert "MCP02:2025" in res.output
    assert "read_env" in res.output


def test_the_default_exit_counts_the_severities():
    res = _run(flagged=True)
    assert res.exit_code == 0, res.output
    assert "CRITICAL 1" in res.output
    assert "HIGH 0" in res.output


def test_a_clean_target_says_so_instead_of_printing_nothing():
    res = _run(flagged=False)
    assert res.exit_code == 0, res.output
    assert "no stage raised a signal" in res.output
    assert "MCP02:2025" not in res.output


def test_the_counts_survive_colour(monkeypatch):
    """rich colourises digit runs; a split count is ungreppable (rule 103).

    The module console is built at import time, so an environment variable set
    inside the test changes nothing. The console object itself is replaced.
    """
    buffer = io.StringIO()
    monkeypatch.setattr(
        cli_module,
        "console",
        Console(file=buffer, force_terminal=True, color_system="standard", width=200),
    )
    res = _run(flagged=True)
    assert res.exit_code == 0, res.output
    printed = buffer.getvalue()
    assert "\x1b[" in printed, "colour was not forced; the test proves nothing"
    assert "CRITICAL 1" in printed

"""
End-to-end smoke tests for the cyberai CLI.

These tests verify that the entire pipeline runs without crashing,
even in dry-run mode where no real network calls are made.

These tests pass end-to-end:
the CLI, Orchestrator, and agents share a consistent API.
See docs/architecture/known-issues.md for the issues that were resolved.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from cyberai.__main__ import cli

pytestmark = pytest.mark.smoke


def test_cli_scan_dry_run_exits_cleanly():
    """
    `cyberai scan <target> --dry-run` should complete with exit code 0
    without making any real network calls.

    Currently fails because __main__.py calls Orchestrator(config) but
    Orchestrator.__init__ does not accept `config` as positional arg,
    and calls orchestrator.run_pipeline(session) which does not exist
    (the method is named `run(target)`).
    """
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "127.0.0.1", "--dry-run"])

    assert result.exit_code == 0, (
        f"CLI exited with code {result.exit_code}\n"
        f"Output:\n{result.output}\n"
        f"Exception:\n{result.exception!r}"
    )


def test_cli_scan_dry_run_produces_output():
    """The scan should produce some textual output, even in dry-run mode."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "example.com", "--dry-run"])

    assert result.output, "CLI produced no output at all"


def test_cli_help_works():
    """
    Sanity check: `cyberai --help` must always work.
    If this breaks, something is very wrong with imports.
    """
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "scan" in result.output.lower()


def test_cli_scan_dry_run_completes_all_phases():
    """Dry-run must reach all 4 phases and finish in `completed` state."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "example.com", "--dry-run"])
    assert result.exit_code == 0
    out = result.output.lower()
    assert "completed" in out
    for phase in ("recon", "intel", "exploit", "report"):
        assert phase in out, f"phase {phase} missing from dry-run output"

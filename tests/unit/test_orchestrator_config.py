"""
Tests for Orchestrator + CyberAIConfig integration — day 5 of STANDOFF.

Covers the KI-1 fix: orchestrator accepts config, builds llm lazily,
and the CLI wiring works in dry-run.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from cyberai.__main__ import cli
from cyberai.core.config import CyberAIConfig
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanState


# ── Orchestrator + config ─────────────────────────────────────────────


def test_orchestrator_accepts_config():
    orch = Orchestrator(config=CyberAIConfig(), dry_run=True)
    assert orch.config is not None


def test_orchestrator_defaults_config_when_omitted():
    """Orchestrator() with no config should still build a default one."""
    orch = Orchestrator(dry_run=True)
    assert isinstance(orch.config, CyberAIConfig)


def test_orchestrator_llm_is_none_in_dry_run():
    """Dry-run must never construct an LLM client (no API key needed)."""
    orch = Orchestrator(config=CyberAIConfig(), dry_run=True)
    assert orch.llm is None


def test_orchestrator_run_returns_completed_session():
    orch = Orchestrator(config=CyberAIConfig(), dry_run=True)
    session = orch.run("127.0.0.1")
    assert session.state == ScanState.COMPLETED
    assert len(session.phases) == 4


def test_orchestrator_run_accepts_scope():
    orch = Orchestrator(config=CyberAIConfig(), dry_run=True)
    session = orch.run("10.0.0.1", authorized_scope=["10.0.0.0/24"])
    assert "10.0.0.0/24" in session.authorized_scope


# ── CLI wiring ────────────────────────────────────────────────────────


def test_cli_scan_dry_run_exits_zero():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "127.0.0.1", "--dry-run"])
    assert result.exit_code == 0, result.output


def test_cli_scan_dry_run_with_scope():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "10.0.0.1", "--dry-run", "--scope", "10.0.0.0/24"])
    assert result.exit_code == 0, result.output


def test_cli_scan_reports_findings_count():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "127.0.0.1", "--dry-run"])
    assert "Findings:" in result.output


def test_cli_status_works():
    runner = CliRunner()
    result = runner.invoke(cli, ["status"])
    assert result.exit_code == 0
    assert "Provider" in result.output

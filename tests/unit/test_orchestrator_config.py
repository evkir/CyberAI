"""
Tests for Orchestrator + CyberAIConfig integration.

Covers the KI-1 fix: orchestrator accepts config, builds llm lazily,
and the CLI wiring works in dry-run.
"""

from __future__ import annotations

from click.testing import CliRunner

from cyberai.__main__ import cli
from cyberai.core.config import CyberAIConfig, LLMConfig
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


# ── Per-provider default model resolution ─────────────────────────────


def test_default_model_for_ollama():
    assert LLMConfig.default_model_for("ollama") == "qwen2.5:7b"


def test_default_model_for_openai():
    assert LLMConfig.default_model_for("openai") == "gpt-4o"


def test_default_model_for_anthropic():
    assert LLMConfig.default_model_for("anthropic") == "claude-opus-4-8"


def test_default_model_for_unknown_falls_back():
    assert LLMConfig.default_model_for("nope") == "gpt-4o"


def test_from_env_ollama_provider_defaults_model(monkeypatch):
    """provider=ollama with no CYBERAI_MODEL must not inherit gpt-4o."""
    monkeypatch.setenv("CYBERAI_LLM_PROVIDER", "ollama")
    monkeypatch.delenv("CYBERAI_MODEL", raising=False)
    cfg = CyberAIConfig.from_env()
    assert cfg.llm.provider == "ollama"
    assert cfg.llm.model == "qwen2.5:7b"


def test_from_env_explicit_model_overrides_default(monkeypatch):
    monkeypatch.setenv("CYBERAI_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("CYBERAI_MODEL", "llama3:8b")
    cfg = CyberAIConfig.from_env()
    assert cfg.llm.model == "llama3:8b"


def test_cli_provider_ollama_switches_model(monkeypatch):
    """--provider ollama must re-resolve model away from gpt-4o (bug #1)."""
    monkeypatch.delenv("CYBERAI_MODEL", raising=False)
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "127.0.0.1", "--dry-run", "--provider", "ollama"])
    assert result.exit_code == 0, result.output


def test_cli_model_flag_overrides(monkeypatch):
    """--model wins even when --provider would default otherwise."""
    monkeypatch.delenv("CYBERAI_MODEL", raising=False)
    runner = CliRunner()
    result = runner.invoke(
        cli, ["scan", "127.0.0.1", "--dry-run", "--provider", "ollama", "--model", "mistral"]
    )
    assert result.exit_code == 0, result.output

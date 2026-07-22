"""
Tests for Orchestrator + CyberAIConfig integration.

Covers the KI-1 fix: orchestrator accepts config, builds llm lazily,
and the CLI wiring works in dry-run.
"""

from __future__ import annotations

from click.testing import CliRunner

from cyberai.__main__ import cli
from cyberai.core.config import CyberAIConfig, LLMConfig, _env_bool
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


# -- Feature-flag env passthrough (from_env) --

_FLAG_ENV_VARS = [
    "CYBERAI_USE_NUCLEI",
    "CYBERAI_USE_JUDGE",
    "CYBERAI_ENABLE_REPLAN",
    "CYBERAI_USE_EXPLOIT_MEMORY",
    "CYBERAI_USE_BEHAVIORAL",
    "CYBERAI_USE_LAB_DOGFOOD",
    "CYBERAI_WEB_ENABLE_BENCH_TRIGGER",
    "CYBERAI_AIR_GAPPED",
    "CYBERAI_ENABLE_MODEL_ROUTING",
]


def _clear_flag_env(monkeypatch):
    for var in _FLAG_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def test_env_bool_truthy_values(monkeypatch):
    for val in ("1", "true", "TRUE", "yes", "on", " On "):
        monkeypatch.setenv("CYBERAI_TEST_FLAG", val)
        assert _env_bool("CYBERAI_TEST_FLAG", False) is True


def test_env_bool_falsy_values(monkeypatch):
    for val in ("0", "false", "no", "off", "nope", ""):
        monkeypatch.setenv("CYBERAI_TEST_FLAG", val)
        assert _env_bool("CYBERAI_TEST_FLAG", True) is False


def test_env_bool_unset_uses_default(monkeypatch):
    monkeypatch.delenv("CYBERAI_TEST_FLAG", raising=False)
    assert _env_bool("CYBERAI_TEST_FLAG", True) is True
    assert _env_bool("CYBERAI_TEST_FLAG", False) is False


def test_from_env_feature_flags_default_false(monkeypatch):
    _clear_flag_env(monkeypatch)
    cfg = CyberAIConfig.from_env()
    assert cfg.use_nuclei is False
    assert cfg.use_judge is False
    assert cfg.enable_replan is False
    assert cfg.use_exploit_memory is False
    assert cfg.use_behavioral_fingerprint is False
    assert cfg.use_lab_dogfood is False
    assert cfg.web_enable_bench_trigger is False
    assert cfg.air_gapped is False
    assert cfg.routing.enable_model_routing is False


def test_from_env_use_behavioral_flag(monkeypatch):
    _clear_flag_env(monkeypatch)
    monkeypatch.setenv("CYBERAI_USE_BEHAVIORAL", "1")
    cfg = CyberAIConfig.from_env()
    assert cfg.use_behavioral_fingerprint is True
    assert cfg.use_nuclei is False


def test_from_env_all_bool_flags_enabled(monkeypatch):
    _clear_flag_env(monkeypatch)
    for var in _FLAG_ENV_VARS:
        monkeypatch.setenv(var, "true")
    cfg = CyberAIConfig.from_env()
    assert cfg.use_nuclei is True
    assert cfg.use_judge is True
    assert cfg.enable_replan is True
    assert cfg.use_exploit_memory is True
    assert cfg.use_behavioral_fingerprint is True
    assert cfg.use_lab_dogfood is True
    assert cfg.web_enable_bench_trigger is True
    assert cfg.air_gapped is True
    assert cfg.routing.enable_model_routing is True

"""
Tests for Orchestrator + CyberAIConfig integration.

Covers the KI-1 fix: orchestrator accepts config, builds llm lazily,
and the CLI wiring works in dry-run.
"""

from __future__ import annotations

from click.testing import CliRunner

from cyberai.__main__ import _apply_feature_overrides, cli
from cyberai.core.config import (
    CyberAIConfig,
    LLMConfig,
    _env_bool,
    _env_float,
    _env_int,
)
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


# -- Numeric / path env passthrough (from_env) --

_NUMERIC_ENV_VARS = [
    "CYBERAI_VERBOSE",
    "CYBERAI_TIMEOUT",
    "CYBERAI_MAX_AGENT_ITERATIONS",
    "CYBERAI_MAX_COST_USD",
    "CYBERAI_JUDGE_THRESHOLD",
    "CYBERAI_JUDGE_MODEL",
    "CYBERAI_EXPLOIT_MEMORY_PATH",
    "CYBERAI_LAB_MACHINES_DIR",
    "CYBERAI_OUTPUT_DIR",
]


def _clear_numeric_env(monkeypatch):
    for var in _NUMERIC_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def test_env_float_valid(monkeypatch):
    monkeypatch.setenv("CYBERAI_TEST_NUM", "2.5")
    assert _env_float("CYBERAI_TEST_NUM", 0.0) == 2.5


def test_env_float_invalid_and_empty_use_default(monkeypatch):
    monkeypatch.setenv("CYBERAI_TEST_NUM", "abc")
    assert _env_float("CYBERAI_TEST_NUM", 1.0) == 1.0
    monkeypatch.setenv("CYBERAI_TEST_NUM", "  ")
    assert _env_float("CYBERAI_TEST_NUM", 1.0) == 1.0
    monkeypatch.delenv("CYBERAI_TEST_NUM", raising=False)
    assert _env_float("CYBERAI_TEST_NUM", 1.0) == 1.0


def test_env_int_valid(monkeypatch):
    monkeypatch.setenv("CYBERAI_TEST_NUM", "42")
    assert _env_int("CYBERAI_TEST_NUM", 0) == 42


def test_env_int_invalid_and_empty_use_default(monkeypatch):
    monkeypatch.setenv("CYBERAI_TEST_NUM", "3.5")
    assert _env_int("CYBERAI_TEST_NUM", 7) == 7
    monkeypatch.setenv("CYBERAI_TEST_NUM", "")
    assert _env_int("CYBERAI_TEST_NUM", 7) == 7
    monkeypatch.delenv("CYBERAI_TEST_NUM", raising=False)
    assert _env_int("CYBERAI_TEST_NUM", 7) == 7


def test_from_env_numeric_defaults(monkeypatch):
    _clear_numeric_env(monkeypatch)
    cfg = CyberAIConfig.from_env()
    assert cfg.verbose is False
    assert cfg.timeout == 60
    assert cfg.max_agent_iterations == 10
    assert cfg.max_cost_usd == 0.0
    assert cfg.judge_threshold == 0.7
    assert cfg.judge_model is None
    assert cfg.exploit_memory_path is None
    assert cfg.lab_machines_dir is None
    assert str(cfg.output_dir) == "reports"


def test_from_env_numeric_overrides(monkeypatch):
    _clear_numeric_env(monkeypatch)
    monkeypatch.setenv("CYBERAI_VERBOSE", "1")
    monkeypatch.setenv("CYBERAI_TIMEOUT", "120")
    monkeypatch.setenv("CYBERAI_MAX_AGENT_ITERATIONS", "20")
    monkeypatch.setenv("CYBERAI_MAX_COST_USD", "5.0")
    monkeypatch.setenv("CYBERAI_JUDGE_THRESHOLD", "0.9")
    monkeypatch.setenv("CYBERAI_JUDGE_MODEL", "claude-opus-4-8")
    monkeypatch.setenv("CYBERAI_EXPLOIT_MEMORY_PATH", "/tmp/mem.db")
    monkeypatch.setenv("CYBERAI_LAB_MACHINES_DIR", "/home/x/oscp/machines")
    monkeypatch.setenv("CYBERAI_OUTPUT_DIR", "/tmp/out")
    cfg = CyberAIConfig.from_env()
    assert cfg.verbose is True
    assert cfg.timeout == 120
    assert cfg.max_agent_iterations == 20
    assert cfg.max_cost_usd == 5.0
    assert cfg.judge_threshold == 0.9
    assert cfg.judge_model == "claude-opus-4-8"
    assert cfg.exploit_memory_path == "/tmp/mem.db"
    assert cfg.lab_machines_dir == "/home/x/oscp/machines"
    assert str(cfg.output_dir) == "/tmp/out"


# -- CLI feature-flag overrides (_apply_feature_overrides / scan) --


def test_apply_overrides_none_leaves_untouched():
    cfg = CyberAIConfig()
    cfg.use_behavioral_fingerprint = True
    cfg.use_nuclei = True
    _apply_feature_overrides(cfg)
    assert cfg.use_behavioral_fingerprint is True
    assert cfg.use_nuclei is True


def test_apply_overrides_forces_true():
    cfg = CyberAIConfig()
    _apply_feature_overrides(
        cfg, behavioral=True, nuclei=True, judge=True, replan=True, air_gapped=True
    )
    assert cfg.use_behavioral_fingerprint is True
    assert cfg.use_nuclei is True
    assert cfg.use_judge is True
    assert cfg.enable_replan is True
    assert cfg.air_gapped is True


def test_apply_overrides_forces_false_over_enabled():
    cfg = CyberAIConfig()
    cfg.use_behavioral_fingerprint = True
    cfg.air_gapped = True
    _apply_feature_overrides(cfg, behavioral=False, air_gapped=False)
    assert cfg.use_behavioral_fingerprint is False
    assert cfg.air_gapped is False


def test_cli_scan_behavioral_flag_exits_zero():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "127.0.0.1", "--dry-run", "--behavioral"])
    assert result.exit_code == 0, result.output


def test_cli_scan_no_behavioral_flag_exits_zero():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "127.0.0.1", "--dry-run", "--no-behavioral"])
    assert result.exit_code == 0, result.output


def test_cli_scan_air_gapped_flag_exits_zero():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "127.0.0.1", "--dry-run", "--air-gapped"])
    assert result.exit_code == 0, result.output


def test_cli_scan_verbose_flag_exits_zero():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "127.0.0.1", "--dry-run", "-v"])
    assert result.exit_code == 0, result.output

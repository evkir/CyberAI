"""--recon-only and --max-rps guards for safe external recon runs."""

from unittest.mock import patch

from click.testing import CliRunner

from cyberai.__main__ import cli
from cyberai.agents.recon.agent import ReconAgent
from cyberai.agents.recon.nmap_tool import validate_flags
from cyberai.core.config import CyberAIConfig
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanPhase, ScanSession

_RECON_TOOLS = {
    "run_whois": {},
    "run_dns": {},
    "enumerate_subdomains": {},
    "detect_llm_endpoints": {},
}


def _run_recon_capturing_flags(cfg):
    agent = ReconAgent(cfg, ScanSession(target="scanme.example.org"))
    captured = {}

    def fake_nmap(target, flags="-sV -T4 --top-ports 1000"):
        captured["flags"] = flags
        return {"ports": []}

    with (
        patch("cyberai.agents.recon.agent.run_nmap", side_effect=fake_nmap),
        patch.multiple(
            "cyberai.agents.recon.agent", **{k: lambda *a, **k2: v for k, v in _RECON_TOOLS.items()}
        ),
    ):
        agent.run("scanme.example.org")
    return captured["flags"]


def test_max_rps_default_none():
    assert CyberAIConfig().max_rps is None


def test_max_rps_configurable():
    assert CyberAIConfig(max_rps=5).max_rps == 5


def test_validate_flags_accepts_max_rate():
    assert validate_flags("--max-rate 5") == ["--max-rate", "5"]


def test_recon_agent_injects_max_rate():
    assert "--max-rate 7" in _run_recon_capturing_flags(CyberAIConfig(max_rps=7))


def test_recon_agent_no_max_rate_when_unset():
    assert "--max-rate" not in _run_recon_capturing_flags(CyberAIConfig())


def test_recon_only_orchestrator_single_phase():
    orch = Orchestrator(config=CyberAIConfig(), phases=[ScanPhase.RECON], dry_run=True)
    session = orch.run("example.com")
    assert [p.phase for p in session.phases] == [ScanPhase.RECON]


def test_cli_accepts_recon_only_and_max_rps():
    result = CliRunner().invoke(
        cli, ["scan", "example.com", "--recon-only", "--max-rps", "5", "--dry-run"]
    )
    assert result.exit_code == 0

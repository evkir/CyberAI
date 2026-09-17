"""An unauthorised run is refused before any probe leaves the machine.

The scope verdict used to live in the exploit phase alone, three phases
downstream of the first packet. A measured run against 10.10.10.10 with no
scope finished a full recon sweep -- nmap, whois, dns, subdomain enumeration,
51 seconds of traffic -- and only then declined to exploit. The refusal was
real and far too late: the target had already been touched by a run nobody
authorised.

These tests assert the absence of a call, not the presence of a verdict. A
session in the REFUSED state proves what the orchestrator recorded; only an
unentered ReconAgent.run proves what the network saw. The distinction has
bitten this repo before -- a green test can assert liveness while measuring
an early return.
"""

from unittest.mock import patch

from cyberai.core.config import CyberAIConfig
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanState


def _orch(**kw: object) -> Orchestrator:
    return Orchestrator(config=CyberAIConfig(), **kw)  # type: ignore[arg-type]


def test_an_unscoped_run_never_reaches_the_recon_agent() -> None:
    with patch("cyberai.agents.recon.agent.ReconAgent.run") as recon:
        session = _orch(dry_run=False).run("scanme.nmap.org")

    recon.assert_not_called()
    assert session.state == ScanState.REFUSED
    assert session.phases == []


def test_a_protected_range_is_refused_even_with_strict_scope_off() -> None:
    config = CyberAIConfig()
    config.strict_scope = False

    with patch("cyberai.agents.recon.agent.ReconAgent.run") as recon:
        session = Orchestrator(config=config).run("10.10.10.10")

    recon.assert_not_called()
    assert session.state == ScanState.REFUSED
    assert any("protected range" in e for e in session.errors)


def test_dry_run_shows_the_refusal_instead_of_a_finished_pipeline() -> None:
    session = _orch(dry_run=True).run("10.10.10.10")

    assert session.state == ScanState.REFUSED
    assert session.phases == []


def test_an_authorised_run_is_not_touched_by_the_preflight() -> None:
    orch = _orch(dry_run=True)
    session = orch.run("10.0.0.1", authorized_scope=["10.0.0.0/24"])

    assert session.state == ScanState.COMPLETED
    assert [p.phase for p in session.phases] == orch.phases
    assert session.errors == []


def test_a_refused_run_has_no_duration_rather_than_a_zero_one() -> None:
    session = _orch(dry_run=True).run("10.10.10.10")

    assert session.started_at is None
    assert session.summary()["duration_s"] is None


def test_a_refusal_reaches_the_exit_code() -> None:
    """CI reads `$?` and nothing else.

    A refused run has no phases at all, so the failed-phase list the CLI
    built its exit code from was empty and the process exited 0 -- the same
    signal a clean scan gives. The state is the only thing that tells them
    apart.
    """
    from click.testing import CliRunner

    from cyberai.__main__ import cli

    result = CliRunner().invoke(cli, ["scan", "10.10.10.10", "--dry-run"])

    assert result.exit_code == 1, result.output
    assert "Refused" in result.output


def test_an_authorised_run_still_exits_zero() -> None:
    from click.testing import CliRunner

    from cyberai.__main__ import cli

    result = CliRunner().invoke(cli, ["scan", "10.0.0.1", "--dry-run", "--scope", "10.0.0.0/24"])

    assert result.exit_code == 0, result.output
    assert "Refused" not in result.output


def test_the_async_pipeline_refuses_before_its_own_recon() -> None:
    """AsyncOrchestrator overrides run() whole, so it can lose the check.

    The preflight lives on the base class precisely because of this: the
    async body builds its own session, prints its own panel and drives its
    own recon agent, sharing nothing with the sync path but the method it
    calls. A mutant that removes the call from one body leaves the other
    green, which is why both are asserted here.
    """
    import asyncio

    from cyberai.core.orchestrator import AsyncOrchestrator

    orch = AsyncOrchestrator(config=CyberAIConfig(), dry_run=False)

    with patch("cyberai.agents.recon.async_agent.AsyncReconAgent") as recon:
        session = asyncio.run(orch.run("scanme.nmap.org"))

    recon.assert_not_called()
    assert session.state == ScanState.REFUSED
    assert session.phases == []


def test_the_async_pipeline_still_runs_what_it_was_authorised_to_run() -> None:
    import asyncio

    from cyberai.core.orchestrator import AsyncOrchestrator

    orch = AsyncOrchestrator(config=CyberAIConfig(), dry_run=True)
    session = asyncio.run(orch.run("10.0.0.1", authorized_scope=["10.0.0.0/24"]))

    assert session.state == ScanState.COMPLETED
    assert [p.phase for p in session.phases] == orch.phases

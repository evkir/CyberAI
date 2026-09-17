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

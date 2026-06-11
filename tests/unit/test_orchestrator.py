from unittest.mock import patch
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanPhase, ScanState


def test_dry_run_completes():
    orch = Orchestrator(dry_run=True)
    session = orch.run("10.0.0.1")
    assert session.state == ScanState.COMPLETED


def test_dry_run_all_phases_pass():
    orch = Orchestrator(dry_run=True)
    session = orch.run("10.0.0.1")
    assert all(p.success for p in session.phases)


def test_dry_run_phase_count():
    orch = Orchestrator(dry_run=True)
    session = orch.run("10.0.0.1")
    assert len(session.phases) == 4


def test_dry_run_custom_phases():
    orch = Orchestrator(
        phases=[ScanPhase.RECON, ScanPhase.INTEL],
        dry_run=True,
    )
    session = orch.run("10.0.0.1")
    assert len(session.phases) == 2
    phases = [p.phase for p in session.phases]
    assert ScanPhase.RECON in phases
    assert ScanPhase.INTEL in phases


def test_dry_run_session_target():
    orch = Orchestrator(dry_run=True)
    session = orch.run("192.168.1.100")
    assert session.target == "192.168.1.100"


def test_dry_run_session_has_id():
    orch = Orchestrator(dry_run=True)
    session = orch.run("10.0.0.1")
    assert session.session_id
    assert len(session.session_id) == 8


def test_dry_run_kb_has_dry_run_keys():
    orch = Orchestrator(dry_run=True)
    session = orch.run("10.0.0.1")
    # dry_run записывает данные в phases, не в KB напрямую
    for p in session.phases:
        assert p.data.get("dry_run") is True


def test_dry_run_authorized_scope():
    # authorized_scope moved from constructor to run() in day 5
    orch = Orchestrator(dry_run=True)
    session = orch.run("10.0.0.1", authorized_scope=["10.0.0.0/24"])
    assert "10.0.0.0/24" in session.authorized_scope


def test_phase_failure_continues_pipeline():
    orch = Orchestrator(
        phases=[ScanPhase.RECON, ScanPhase.INTEL],
        dry_run=False,
    )
    with patch.object(orch, "_dispatch") as mock_dispatch:
        mock_dispatch.side_effect = [
            Exception("recon failed"),
            {"cves": []},
        ]
        session = orch.run("10.0.0.1")
        # pipeline continues even after failure
        assert len(session.phases) == 2
        assert session.phases[0].success is False
        assert session.phases[1].success is True


def test_all_phases_fail_sets_failed_state():
    orch = Orchestrator(
        phases=[ScanPhase.RECON],
        dry_run=False,
    )
    with patch.object(orch, "_dispatch", side_effect=Exception("boom")):
        session = orch.run("10.0.0.1")
        assert session.state == ScanState.FAILED


def test_summary_contains_duration():
    orch = Orchestrator(dry_run=True)
    session = orch.run("10.0.0.1")
    summary = session.summary()
    assert summary["duration_s"] is not None

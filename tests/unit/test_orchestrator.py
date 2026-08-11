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
    # dry_run writes data into phases, not directly into the KB
    for p in session.phases:
        assert p.data.get("dry_run") is True


def test_dry_run_authorized_scope():
    # authorized_scope lives on run(), not the constructor
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


def test_check_phase_injection_ignores_nonascii_cve_text():
    """Non-ASCII phase content must not fabricate a unicode_escape finding.

    Regression: json.dumps with the default ensure_ascii=True re-encoded any
    non-ASCII char as a literal \\uXXXX escape, which matched the detector's
    unicode_escape pattern and raised a false MEDIUM finding on ordinary CVE
    descriptions. Serializing with ensure_ascii=False removes the artifact.
    """
    from cyberai.core.scan_session import ScanPhase, ScanSession, Severity

    orch = Orchestrator(dry_run=True)
    session = ScanSession(target="t")
    data = {"cves": [{"id": "CVE-2024-1", "desc": "overflow in café-server, RCE"}]}
    orch._check_phase_injection(session, ScanPhase.INTEL, data)
    assert not any(f.severity == Severity.MEDIUM for f in session.findings)


def test_check_phase_injection_still_flags_real_smuggling():
    """A genuine RTL-override payload in phase output must still be flagged."""
    from cyberai.core.scan_session import ScanPhase, ScanSession, Severity

    orch = Orchestrator(dry_run=True)
    session = ScanSession(target="t")
    data = {"banner": "OpenSSH \u202e evil \u202c payload"}
    orch._check_phase_injection(session, ScanPhase.INTEL, data)
    assert any(
        f.severity == Severity.MEDIUM and "Prompt-injection" in f.title for f in session.findings
    )


def test_a_single_phase_runs_without_standing_up_the_audit_logger(tmp_path):
    """One phase called on its own must not need the caller to patch in audit.

    run() assigns self.audit before it dispatches anything, so every phase
    handler reads an attribute that only exists on the full-pipeline path.
    Five test sites compensated by assigning it by hand. The report phase is
    the proof because it writes a file: if audit were still missing the call
    would raise AttributeError before any agent was built.
    """
    from pathlib import Path

    from cyberai.core.config import CyberAIConfig
    from cyberai.core.scan_session import ScanSession

    config = CyberAIConfig()
    config.output_dir = str(tmp_path)
    orch = Orchestrator(config)
    session = ScanSession(target="t.local")

    result = orch._run_report(session)

    # The phase produced its artefact, so the agent accepted audit=None and
    # built its own logger from the session -- the contract BaseAgent already
    # declared.
    assert Path(result["html_report"]).is_file()
    # And it did so without the orchestrator quietly building one: a logger
    # appearing here would mean the None path was never exercised.
    assert orch.audit is None

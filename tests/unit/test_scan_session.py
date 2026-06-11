from cyberai.core.scan_session import ScanSession, ScanState, ScanPhase, PhaseResult


def test_session_created_state():
    s = ScanSession(target="10.0.0.1")
    assert s.state == ScanState.CREATED
    assert s.target == "10.0.0.1"


def test_session_start():
    s = ScanSession(target="10.0.0.1")
    s.start()
    assert s.state == ScanState.RUNNING
    assert s.started_at is not None


def test_session_complete():
    s = ScanSession(target="10.0.0.1")
    s.start()
    s.complete()
    assert s.state == ScanState.COMPLETED
    assert s.ended_at is not None


def test_session_fail():
    s = ScanSession(target="10.0.0.1")
    s.start()
    s.fail("nmap crashed")
    assert s.state == ScanState.FAILED
    assert "nmap crashed" in s.errors


def test_session_cancel():
    s = ScanSession(target="10.0.0.1")
    s.start()
    s.cancel()
    assert s.state == ScanState.CANCELLED


def test_session_kb():
    s = ScanSession(target="10.0.0.1")
    s.kb_set("recon", {"ports": [80, 443]})
    assert s.kb_get("recon") == {"ports": [80, 443]}
    assert s.kb_get("missing", "default") == "default"


def test_record_phase():
    s = ScanSession(target="10.0.0.1")
    s.start()
    started = s.started_at
    result = s.record_phase(ScanPhase.RECON, success=True, started=started)
    assert isinstance(result, PhaseResult)
    assert result.success is True
    assert result.phase == ScanPhase.RECON
    assert len(s.phases) == 1


def test_record_phase_failure():
    s = ScanSession(target="10.0.0.1")
    s.start()
    result = s.record_phase(
        ScanPhase.INTEL, success=False, started=s.started_at, error="NVD API timeout"
    )
    assert result.success is False
    assert result.error == "NVD API timeout"


def test_session_summary_keys():
    s = ScanSession(target="10.0.0.1")
    s.start()
    s.complete()
    summary = s.summary()
    assert "session_id" in summary
    assert "target" in summary
    assert "state" in summary
    assert "phases" in summary
    assert "kb_keys" in summary


def test_session_id_unique():
    ids = {ScanSession(target="x").session_id for _ in range(10)}
    assert len(ids) == 10


def test_set_phase():
    s = ScanSession(target="10.0.0.1")
    s.set_phase(ScanPhase.EXPLOIT)
    assert s.state == ScanState.EXPLOIT


def test_authorized_scope():
    s = ScanSession(target="10.0.0.1", authorized_scope=["10.0.0.0/24"])
    assert "10.0.0.0/24" in s.authorized_scope

"""A lost phase leaves a non-zero exit code.

Measured on 2026-09-08: three separate runs ended with `state: failed` and
`errors: ["Failed phases: ['exploit']"]` while the shell saw 0. A script or
a CI step that gates on `$?` reads those runs as successes -- the same
"green over red" the suite is built to catch, one level up from the tests.

A partial run keeps 0. Every phase ran and reported what it could not check;
that is a result the caller can act on, not a failure of the pipeline.
"""

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from cyberai.__main__ import scan
from cyberai.core.scan_session import PhaseResult, ScanPhase, ScanSession


def _session(*, success: bool, data: dict | None = None) -> ScanSession:
    session = ScanSession(target="http://evil.example.com")
    session.phases.append(
        PhaseResult(
            phase=ScanPhase.EXPLOIT,
            success=success,
            started_at="2026-09-08T00:00:00Z",
            ended_at="2026-09-08T00:00:01Z",
            duration_s=0.0,
            data=data if data is not None else {},
            error=None if success else "RuntimeError: Scope check failed",
        )
    )
    return session


def _invoke(session):
    orchestrator = MagicMock()
    orchestrator.run.return_value = session
    with (
        patch("cyberai.__main__.Orchestrator", return_value=orchestrator),
        patch("cyberai.cli.replay.save_session", return_value="reports/session_x.json"),
    ):
        return CliRunner().invoke(scan, ["http://evil.example.com"])


def test_a_failed_phase_exits_non_zero():
    assert _invoke(_session(success=False)).exit_code == 1


def test_a_partial_run_still_exits_zero():
    result = _invoke(_session(success=True, data={"degraded": ["web_exploit_scope"]}))
    assert result.exit_code == 0
    assert "Partial" in result.output


def test_a_clean_run_exits_zero():
    result = _invoke(_session(success=True))
    assert result.exit_code == 0
    assert "Done." in result.output


def test_the_summary_is_printed_before_the_exit():
    """The code replaces neither the report nor the saved session.

    An exit raised above the summary would turn a diagnosable failure into a
    bare status code, which is worse than the zero it replaces.
    """
    result = _invoke(_session(success=False))
    assert result.exit_code == 1
    assert "Incomplete" in result.output
    assert "Session saved" in result.output
    assert "session_id" in result.output

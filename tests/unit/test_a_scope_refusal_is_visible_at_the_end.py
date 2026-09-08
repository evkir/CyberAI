"""A skipped web walk is reported as partial, not as a completed scan.

Measured on 2026-09-08: a run whose web exploitation was refused printed
`Done. Findings: 2` with the exploit phase marked successful and 0.005s
long. The refusal branch returns the same zeros a walk that found nothing
returns, and nothing downstream could tell them apart.

The status line already distinguishes three outcomes -- failed, degraded,
done -- and reads `degraded` off each phase result. The exploit phase never
put anything there, so the third branch was unreachable for this cause.
"""

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from cyberai.__main__ import scan
from cyberai.agents.exploit.agent import ExploitAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import PhaseResult, ScanPhase, ScanSession

_SURFACE = {
    "endpoints": [
        {
            "method": "GET",
            "url": "http://10.10.10.5:3000/search",
            "params": ["q"],
        }
    ]
}


def _agent(scope, target="http://evil.example.com"):
    session = ScanSession(target=target, authorized_scope=scope)
    config = CyberAIConfig()
    # Off by default: without this the walk is never reached and the marker
    # is absent for a reason that has nothing to do with the scope.
    config.use_web_exploit = True
    agent = ExploitAgent(config, session)
    agent.kb.set("recon.web_surface", _SURFACE)
    return agent


def test_the_refusal_carries_a_marker():
    result = _agent(["*.acme.com"])._run_web_exploit("http://evil.example.com")
    assert result["degraded"] == ["web_exploit_scope"]


def test_a_walk_that_ran_carries_no_marker():
    """The other side: an authorised target must not be reported as partial."""
    agent = _agent(["*.acme.com"], target="http://api.acme.com")
    report = MagicMock()
    report.findings = []
    report.oob_confirmed_params = []
    report.params_oob_confirmed = 0
    report.to_dict.return_value = {"confirmed": 0, "endpoints_tested": 1, "findings": []}

    with patch("cyberai.agents.exploit.agent.exploit_surface", return_value=report):
        result = agent._run_web_exploit("http://api.acme.com")

    assert result.get("degraded", []) == []


def test_the_phase_result_carries_the_marker_upward():
    """A marker left inside web_exploit never reaches the status line.

    The CLI reads `degraded` off the phase result, which is what run()
    returns; the web result is nested one level below it.
    """
    phase_result = _agent(["*.acme.com"]).run("http://evil.example.com")
    assert phase_result["degraded"] == ["web_exploit_scope"]


def test_the_marker_survives_the_cve_path_too():
    """run() has two exits and the CVE-driven one is the longer of the pair.

    A target with a ranked CVE leaves through the tail return, which builds a
    fresh dict; a marker lifted only in the early return would be dropped for
    exactly the runs that do the most work.
    """
    agent = _agent(["*.acme.com"])
    agent.kb.set("intel", {"ranked_cves": [{"cve_id": "CVE-2021-1", "severity": "HIGH"}]})

    phase_result = agent.run("http://evil.example.com")

    assert phase_result["degraded"] == ["web_exploit_scope"]
    assert "exploit_chain" in phase_result


def _session_with_exploit_data(data):
    session = ScanSession(target="http://evil.example.com")
    session.phases.append(
        PhaseResult(
            phase=ScanPhase.EXPLOIT,
            success=True,
            started_at="2026-09-08T00:00:00Z",
            ended_at="2026-09-08T00:00:01Z",
            duration_s=0.0,
            data=data,
        )
    )
    return session


def _run_scan_printing(session):
    orchestrator = MagicMock()
    orchestrator.run.return_value = session
    with (
        patch("cyberai.__main__.Orchestrator", return_value=orchestrator),
        patch("cyberai.cli.replay.save_session", return_value="reports/session_x.json"),
    ):
        return CliRunner().invoke(scan, ["http://evil.example.com"])


def test_the_status_line_reports_partial_for_a_refused_walk():
    result = _run_scan_printing(_session_with_exploit_data({"degraded": ["web_exploit_scope"]}))
    assert result.exit_code == 0
    assert "Partial" in result.output
    assert "exploit/web_exploit_scope" in result.output
    assert "Done." not in result.output


def test_the_status_line_still_reports_done_without_a_marker():
    result = _run_scan_printing(_session_with_exploit_data({"degraded": []}))
    assert "Done." in result.output
    assert "Partial" not in result.output


def test_a_marker_is_not_invented_for_a_phase_without_data():
    result = _run_scan_printing(_session_with_exploit_data(None))
    assert "Done." in result.output

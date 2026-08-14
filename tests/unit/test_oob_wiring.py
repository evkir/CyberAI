"""The seam between the web walk and the out-of-band collector.

The workflow and the walk are both covered directly. What is untested is
whether the product ever connects them: for a week the OOB library sat green
and unreachable, which is worse than dead code because the tests made it look
wired. These pin the seam -- the address the callback is sent to, what happens
when the collector is absent, and whether a confirmation reaches the session as
a finding a reader can act on.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cyberai.agents.exploit.agent import ExploitAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession, Severity

_SURFACE = {
    "base_url": "http://t.local",
    "reachable": True,
    "endpoints": [
        {"url": "http://t.local/fetch", "method": "GET", "params": ["url"], "source": "hint"},
    ],
}


def _agent(**flags):
    session = ScanSession(target="t.local")
    config = CyberAIConfig(**flags)
    agent = ExploitAgent(config, session, MagicMock(), MagicMock())
    agent.kb.set("recon.web_surface", _SURFACE, agent="recon")
    return agent, session


def _grid(available=True):
    grid = MagicMock()
    grid.available = available
    return grid


# ── the address the target is asked to call ───────────────────────────


def test_the_callback_address_is_the_gateway_not_the_configured_host():
    """A container cannot reach us on a loopback; it reaches its own.

    The port stays the operator's, the host does not: measured against the
    local blind-SSRF target, loopback confirms nothing and the gateway confirms
    on the first payload.
    """
    agent, _ = _agent(use_oob=True)
    agent.config.phantom.grid_url = "http://127.0.0.1:9090"

    with (
        patch("cyberai.agents.exploit.agent.bridge_gateway_host", return_value="172.17.0.1"),
        patch("cyberai.agents.exploit.agent.PhantomGridClient", return_value=_grid()) as client,
        patch("cyberai.agents.exploit.agent.PhantomGridPoller") as poller,
    ):
        assert agent._oob_confirmer("t.local") is not None

    assert client.call_args.kwargs["base_url"] == "http://172.17.0.1:9090"
    assert poller.call_args.kwargs["base_url"] == "http://172.17.0.1:9090"


def test_the_configured_port_survives_the_host_substitution():
    """Only the host is not negotiable; the operator still chooses the port."""
    agent, _ = _agent(use_oob=True)
    agent.config.phantom.grid_url = "http://grid.internal:7777"

    with (
        patch("cyberai.agents.exploit.agent.bridge_gateway_host", return_value="172.17.0.1"),
        patch("cyberai.agents.exploit.agent.PhantomGridClient", return_value=_grid()) as client,
        patch("cyberai.agents.exploit.agent.PhantomGridPoller"),
    ):
        agent._oob_confirmer("t.local")

    assert client.call_args.kwargs["base_url"] == "http://172.17.0.1:7777"


def test_an_absent_collector_leaves_the_walk_unchanged():
    """Skipped outright rather than run against nothing.

    Every parameter would otherwise pay the full wait to learn the same thing,
    and the report would carry a column of unverified entries that say more
    about our setup than about the target.
    """
    agent, _ = _agent(use_oob=True)

    with (
        patch("cyberai.agents.exploit.agent.bridge_gateway_host", return_value="172.17.0.1"),
        patch("cyberai.agents.exploit.agent.PhantomGridClient", return_value=_grid(False)),
    ):
        assert agent._oob_confirmer("t.local") is None


# ── the flag ──────────────────────────────────────────────────────────


def test_the_walk_gets_a_confirmer_only_when_the_flag_is_on():
    for flag, expected in ((True, True), (False, False)):
        agent, _ = _agent(use_oob=flag)
        with (
            patch("cyberai.agents.exploit.agent.bridge_gateway_host", return_value="172.17.0.1"),
            patch("cyberai.agents.exploit.agent.PhantomGridClient", return_value=_grid()),
            patch("cyberai.agents.exploit.agent.PhantomGridPoller"),
            patch(
                "cyberai.agents.exploit.agent.exploit_surface", return_value=MagicMock(findings=[])
            ) as walk,
        ):
            agent._run_web_exploit("t.local")
        passed = walk.call_args.kwargs["oob_confirm"]
        assert (passed is not None) is expected


# ── the verdict reaching the session ──────────────────────────────────


def _report_with_oob(entries):
    report = MagicMock()
    report.findings = []
    report.oob_confirmed_params = entries
    report.confirmed_count = 0
    report.to_dict.return_value = {"oob_confirmed_params": entries}
    return report


_ENTRY = {
    "url": "http://t.local/fetch",
    "parameter": "url",
    "method": "GET",
    "transport": "query",
    "source": "hint",
}


def test_a_callback_becomes_a_finding_a_reader_can_act_on():
    agent, session = _agent(use_oob=True)

    with patch(
        "cyberai.agents.exploit.agent.exploit_surface",
        return_value=_report_with_oob([dict(_ENTRY)]),
    ):
        agent._run_web_exploit("t.local")

    assert len(session.findings) == 1
    finding = session.findings[0]
    assert finding.severity is Severity.HIGH
    # A callback is execution observed elsewhere -- nothing weaker than certain.
    assert finding.confidence == 1.0
    # The address and the parameter, not just a count: a number is not a job.
    assert "url" in finding.title
    assert "http://t.local/fetch" in finding.description
    assert finding.data == _ENTRY


def test_the_confirmer_hands_the_delivery_function_to_the_workflow():
    """The adapter is not just built, it is called.

    Two contracts meet here: the walk passes a delivery function, the workflow
    expects one, and neither module imports the other. If the seam were wrong
    the walk would still run and the report would still say the parameter was
    never read -- the same silence a target that is not vulnerable produces.
    """
    agent, _ = _agent(use_oob=True)
    finding = MagicMock()
    finding.to_dict.return_value = {"confirmed": True, "error": ""}

    with (
        patch("cyberai.agents.exploit.agent.bridge_gateway_host", return_value="172.17.0.1"),
        patch("cyberai.agents.exploit.agent.PhantomGridClient", return_value=_grid()),
        patch("cyberai.agents.exploit.agent.PhantomGridPoller"),
        patch("cyberai.agents.exploit.agent.confirm_oob", return_value=finding) as workflow,
    ):
        confirm = agent._oob_confirmer("t.local")
        deliver = MagicMock()
        outcome = confirm(deliver)

    assert outcome == {"confirmed": True, "error": ""}
    # The delivery function reaches the workflow; without it the workflow mints
    # a token, sends nothing, and reports no callback.
    assert workflow.call_args.args[1] is deliver
    assert workflow.call_args.args[0] == "ssrf"
    assert workflow.call_args.kwargs["label"] == "cyberai-t.local"


def test_nothing_confirmed_records_nothing():
    agent, session = _agent(use_oob=True)

    with patch("cyberai.agents.exploit.agent.exploit_surface", return_value=_report_with_oob([])):
        agent._run_web_exploit("t.local")

    assert session.findings == []


def _report_counting(confirmed, oob):
    """A report whose two counters are numbers, not mocks.

    MagicMock returns a truthy mock for any attribute, so a summary line
    guarded by `if oob_count` would read as present no matter what the
    report says. Both counters are pinned to integers here.
    """
    report = MagicMock()
    report.findings = []
    report.oob_confirmed_params = []
    report.confirmed_count = confirmed
    report.params_oob_confirmed = oob
    report.to_dict.return_value = {}
    return report


def test_the_summary_line_reports_a_callback_the_in_band_count_cannot_see():
    """A blind confirmation never reaches confirmed_count.

    The count is in-band by definition, so a run whose only proof was a
    callback used to log `0 confirmed` -- the same narrow reading that once
    scored the blind target unsolvable. The line now carries both numbers.
    """
    agent, _ = _agent(use_oob=True)
    with (
        patch("cyberai.agents.exploit.agent.exploit_surface", return_value=_report_counting(0, 1)),
        patch.object(agent, "_log") as log,
    ):
        agent._run_web_exploit("t.local")
    summary = log.call_args.args[0]
    assert "0 confirmed" in summary
    assert "1 out-of-band" in summary


def test_the_summary_line_stays_quiet_when_no_callback_landed():
    """The addition is conditional, so ordinary runs are not padded.

    Without this the line would end in `, 0 out-of-band` on every run that
    never used the path, which is noise on the majority of runs and hides
    the case worth noticing.
    """
    agent, _ = _agent(use_oob=True)
    with (
        patch("cyberai.agents.exploit.agent.exploit_surface", return_value=_report_counting(2, 0)),
        patch.object(agent, "_log") as log,
    ):
        agent._run_web_exploit("t.local")
    summary = log.call_args.args[0]
    assert "2 confirmed" in summary
    assert "out-of-band" not in summary

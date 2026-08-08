"""The Markdown report names the LLM channels the run fuzzed, or says nothing."""

from cyberai.agents.report.markdown_renderer import render_markdown
from cyberai.core.scan_session import ScanSession

# Shape taken from a live run (session 29f9d66e): one channel on Juice Shop,
# three payloads never delivered because no capture host answered.
REPORT = {
    "channel_id": "http://127.0.0.1:3000/rest/chat",
    "oob_used": False,
    "confirmed_count": 0,
    "flagged_count": 2,
    "skipped_count": 3,
    "results": [],
}


def _session(exploit=None):
    s = ScanSession(target="t.local")
    if exploit is not None:
        s.kb.set("exploit", exploit, agent="exploit")
    return s


def _redteam(**over):
    rt = {"channels": 1, "confirmed": 0, "flagged": 2, "reports": [dict(REPORT)]}
    rt.update(over)
    return _session({"redteam": rt})


def test_channel_reaches_the_markdown_report():
    md = render_markdown(_redteam())

    assert "## LLM Channel Red-Team" in md
    # The heading alone passes with an empty body; require the address.
    assert "http://127.0.0.1:3000/rest/chat" in md
    assert "Channels fuzzed: 1 | Confirmed: 0 | Flagged: 2" in md


def test_undelivered_payloads_are_named_not_swallowed():
    """Three payloads never left. Reporting only "0 confirmed" would read as a
    channel that took every payload and stayed clean."""
    md = render_markdown(_redteam())

    assert "not delivered 3" in md
    assert "no OOB channel" in md


def test_a_live_oob_channel_is_distinguished():
    md = render_markdown(_redteam(reports=[{**REPORT, "oob_used": True}]))

    assert "OOB channel used" in md
    assert "no OOB channel" not in md


def test_counts_come_from_the_report_not_the_heading():
    md = render_markdown(_redteam(reports=[{**REPORT, "flagged_count": 7}]))

    assert "flagged 7" in md


def test_no_section_when_no_channel_was_fuzzed():
    """A run that found no channel is the common case; a heading over it would
    assert a walk of the LLM surface that never happened."""
    assert "## LLM Channel Red-Team" not in render_markdown(
        _session({"redteam": {"channels": 0, "confirmed": 0, "flagged": 0, "reports": []}})
    )


def test_no_section_without_a_redteam_run():
    assert "## LLM Channel Red-Team" not in render_markdown(_session({"ai_analysis": "x"}))


def test_no_section_when_no_exploit_phase_ran():
    assert "## LLM Channel Red-Team" not in render_markdown(_session())


def test_malformed_shapes_do_not_render_a_heading():
    assert "## LLM Channel Red-Team" not in render_markdown(_session({"redteam": "yes"}))
    assert "## LLM Channel Red-Team" not in render_markdown(
        _session({"redteam": {"reports": "one"}})
    )

"""The Markdown report carries the model's analysis, or says nothing at all."""

from cyberai.agents.report.markdown_renderer import render_markdown
from cyberai.core.scan_session import ScanSession


def _session(exploit=None):
    s = ScanSession(target="t.local")
    if exploit is not None:
        s.kb.set("exploit", exploit, agent="exploit")
    return s


def test_analysis_reaches_the_markdown_report():
    s = _session({"ai_analysis": "SQLi confirmed in parameter q via SQLITE_ERROR."})

    md = render_markdown(s)

    assert "## AI Analysis" in md
    # The heading alone would pass with an empty body; require the reading.
    assert "SQLi confirmed in parameter q via SQLITE_ERROR." in md


def test_no_section_when_no_exploit_phase_ran():
    md = render_markdown(_session())

    assert "## AI Analysis" not in md


def test_no_section_when_the_model_was_never_asked():
    """A heading over "analysis skipped" promises a reading nobody made."""
    s = _session({"ai_analysis": "AI analysis skipped — no LLM client configured."})

    md = render_markdown(s)

    assert "## AI Analysis" not in md


def test_no_section_for_an_empty_or_non_string_analysis():
    assert "## AI Analysis" not in render_markdown(_session({"ai_analysis": "   "}))
    assert "## AI Analysis" not in render_markdown(_session({"ai_analysis": {"x": 1}}))

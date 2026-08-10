"""The out-of-band verdicts have to reach the documents a person opens.

Both renderers name their keys by hand, so a field added to the walk's report
reaches the JSON export -- which passes the dict through whole -- and stops
there. Six fields in one week were produced and never read; these pin the two
readers that cannot be checked by adding a key alone.

The unverified list matters most. It is our instrument saying it did not
measure, and a page that drops it silently turns a broken collector into a
target that looks clean.
"""

from pathlib import Path

from cyberai.agents.report.agent import ReportAgent
from cyberai.agents.report.html_renderer import render_html_report
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession

_CONFIRMED = {
    "url": "http://127.0.0.1:8804/fetch",
    "parameter": "url",
    "method": "GET",
    "transport": "query",
}
_UNVERIFIED = {
    "url": "http://127.0.0.1:8804/probe",
    "parameter": "next",
    "method": "GET",
    "transport": "query",
}

OOB_REPORT = {
    "confirmed": 0,
    "endpoints_tested": 1,
    "requests_sent": 10,
    "params_inert": 2,
    "inert_params": [dict(_CONFIRMED), dict(_UNVERIFIED)],
    "params_oob_confirmed": 1,
    "oob_confirmed_params": [dict(_CONFIRMED)],
    "params_oob_unverified": 1,
    "oob_unverified_params": [dict(_UNVERIFIED)],
}

# Nothing confirmed, nothing unverified, and no endpoint tested either: the
# control for every assertion below, so none of them can pass on a block the
# renderer prints unconditionally.
QUIET_REPORT = {
    "confirmed": 0,
    "endpoints_tested": 1,
    "requests_sent": 4,
    "params_inert": 1,
    "inert_params": [dict(_CONFIRMED)],
}


def _agent(tmp_path: Path, web_report: object) -> ReportAgent:
    config = CyberAIConfig()
    config.output_dir = tmp_path
    session = ScanSession(target="http://127.0.0.1:8804")
    session.kb.set("exploit.web", web_report, agent="exploit")
    return ReportAgent(config, session, llm=None)


def _markdown(tmp_path: Path, report: object) -> str:
    result = _agent(tmp_path, report).run("http://127.0.0.1:8804")
    return Path(result["markdown"]).read_text()


def _live_kb(web_report):
    session = ScanSession(target="http://127.0.0.1:8804")
    session.kb.set("exploit.web", web_report, agent="exploit")
    return session.kb


def _html(tmp_path: Path, report: object, name: str) -> str:
    output = str(tmp_path / name)
    session = ScanSession(target="http://127.0.0.1:8804")
    render_html_report(session.summary(), _live_kb(report), output_path=output)
    return Path(output).read_text()


# ── markdown ──────────────────────────────────────────────────────────


def test_the_document_names_the_parameter_a_callback_confirmed(tmp_path):
    md = _markdown(tmp_path, OOB_REPORT)
    assert "### Confirmed out of band (1)" in md
    assert "`GET http://127.0.0.1:8804/fetch` -- parameter `url` (query)" in md


def test_the_document_names_what_the_check_could_not_answer_for(tmp_path):
    """An unverified parameter is not a clean one, and the file must say so."""
    md = _markdown(tmp_path, OOB_REPORT)
    assert "### Left unverified (1)" in md
    assert "`GET http://127.0.0.1:8804/probe` -- parameter `next` (query)" in md


def test_a_run_without_a_collector_writes_neither_block(tmp_path):
    """Control: without it the assertions above pass on a hardcoded block."""
    md = _markdown(tmp_path, QUIET_REPORT)
    assert "Confirmed out of band" not in md
    assert "Left unverified" not in md
    # The rest of the section is unaffected.
    assert "### Value not read (1)" in md


def test_a_confirmation_is_reported_before_the_open_questions(tmp_path):
    """A proven finding read after two lists of things nobody checked is a
    finding the reader reaches last."""
    md = _markdown(tmp_path, OOB_REPORT)
    assert md.index("Confirmed out of band") < md.index("Value not read")
    assert md.index("Value not read") < md.index("Left unverified")


# ── html ──────────────────────────────────────────────────────────────


def test_the_page_names_the_parameter_a_callback_confirmed(tmp_path):
    content = _html(tmp_path, OOB_REPORT, "oob.html")
    assert "Confirmed out of band (1)" in content
    assert "8804/fetch" in content


def test_the_page_names_what_the_check_could_not_answer_for(tmp_path):
    content = _html(tmp_path, OOB_REPORT, "unverified.html")
    assert "Left unverified -- the check could not run (1)" in content
    assert "8804/probe" in content


def test_a_page_from_a_run_without_a_collector_writes_neither_block(tmp_path):
    content = _html(tmp_path, QUIET_REPORT, "quiet.html")
    assert "Confirmed out of band" not in content
    assert "Left unverified" not in content
    assert "Value not read (1)" in content

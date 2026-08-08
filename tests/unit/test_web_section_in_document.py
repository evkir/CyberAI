"""The web section has to reach the file, not just the renderer.

The counts already reached the KB and stopped there; a test on the rendering
helper alone would pass throughout the whole time the written document was
missing them. These run the real agent against a real path on disk.
"""

from pathlib import Path

from cyberai.agents.report.agent import ReportAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession

WEB_REPORT = {
    "confirmed": 1,
    "endpoints_tested": 13,
    "requests_sent": 236,
    "params_unauthorized": 1,
    "unauthorized_params": [
        {
            "url": "http://127.0.0.1:3000/rest/user/security-question",
            "parameter": "email",
            "method": "GET",
            "transport": "query",
        }
    ],
    "params_inert": 1,
    "inert_params": [
        {
            "url": "http://127.0.0.1:3000/reviews",
            "parameter": "id",
            "method": "GET",
            "transport": "query",
        }
    ],
}


def _agent(tmp_path: Path, web_report: object) -> ReportAgent:
    config = CyberAIConfig()
    config.output_dir = tmp_path
    session = ScanSession(target="http://127.0.0.1:3000")
    if web_report is not None:
        session.kb.set("exploit.web", web_report, agent="exploit")
    return ReportAgent(config, session, llm=None)


def _written_markdown(result: dict) -> str:
    return Path(result["markdown"]).read_text()


def test_the_web_section_reaches_the_written_document(tmp_path):
    """The operator opens the file, not the return value."""
    md = _written_markdown(_agent(tmp_path, WEB_REPORT).run("http://127.0.0.1:3000"))
    assert "## Web Exploitation" in md
    assert "Endpoints tested: 13" in md


def test_the_written_document_names_the_untested_parameter(tmp_path):
    """An address someone can act on, not a count of ten."""
    md = _written_markdown(_agent(tmp_path, WEB_REPORT).run("http://127.0.0.1:3000"))
    assert (
        "`GET http://127.0.0.1:3000/rest/user/security-question` -- parameter `email` (query)" in md
    )


def test_the_written_document_names_the_parameter_that_ignored_its_value(tmp_path):
    """The inert list is the out-of-band re-check queue."""
    md = _written_markdown(_agent(tmp_path, WEB_REPORT).run("http://127.0.0.1:3000"))
    assert "`GET http://127.0.0.1:3000/reviews` -- parameter `id` (query)" in md


_ENUM_REPORT = {
    "confirmed": 0,
    "endpoints_tested": 5,
    "requests_sent": 104,
    "params_enumerable": 1,
    "enumerable_params": [
        {
            "url": "http://127.0.0.1:5001/users/v1/{username}",
            "parameter": "username",
            "method": "GET",
            "transport": "path",
            "source": "openapi",
        }
    ],
}


def test_the_written_document_names_the_enumerable_identifier(tmp_path):
    """A count says nothing about which route hands out other people's records."""
    md = _written_markdown(_agent(tmp_path, _ENUM_REPORT).run("http://127.0.0.1:5001"))
    assert "### Enumerable identifiers (1)" in md
    assert (
        "`GET http://127.0.0.1:5001/users/v1/{username}` -- parameter `username` "
        "(path, openapi)" in md
    )


def test_a_run_that_found_no_enumerable_identifier_writes_no_heading(tmp_path):
    """An empty list is not a section; Juice Shop earns none of them."""
    md = _written_markdown(_agent(tmp_path, WEB_REPORT).run("http://127.0.0.1:3000"))
    assert "Enumerable identifiers" not in md


def test_a_string_where_the_list_belongs_is_not_counted_as_its_length(tmp_path):
    """`len("abc")` would announce three findings this run never made."""
    report = dict(WEB_REPORT, enumerable_params="abc")
    md = _written_markdown(_agent(tmp_path, report).run("http://127.0.0.1:3000"))
    assert "Enumerable identifiers" not in md


def test_a_network_only_run_writes_no_web_section(tmp_path):
    """No web phase, no heading claiming one ran."""
    md = _written_markdown(_agent(tmp_path, None).run("http://127.0.0.1:3000"))
    assert "## Web Exploitation" not in md


def test_the_source_of_a_parameter_reaches_the_document(tmp_path: Path):
    """A name from a bundle and a name from a spec earn different confidence."""
    report = {
        "confirmed": 0,
        "endpoints_tested": 2,
        "requests_sent": 4,
        "inert_params": [
            {
                "url": "http://t/engine.io",
                "parameter": "agent",
                "method": "GET",
                "transport": "query",
                "source": "js-route",
            }
        ],
        "unauthorized_params": [
            {
                "url": "http://t/v1/books",
                "parameter": "id",
                "method": "GET",
                "transport": "query",
                "source": "openapi",
            }
        ],
    }
    text = _written_markdown(_agent(tmp_path, report).run("http://t"))
    assert "(query, js-route)" in text
    assert "(query, openapi)" in text


def test_a_parameter_without_a_source_prints_no_dangling_comma(tmp_path: Path):
    report = {
        "confirmed": 0,
        "endpoints_tested": 1,
        "requests_sent": 2,
        "inert_params": [
            {
                "url": "http://t/reviews",
                "parameter": "id",
                "method": "GET",
                "transport": "query",
            }
        ],
    }
    text = _written_markdown(_agent(tmp_path, report).run("http://t"))
    assert "(query)" in text
    assert "(query, )" not in text


PHANTOM_REPORT = {
    "confirmed": 0,
    "endpoints_tested": 0,
    "requests_sent": 4,
    "endpoints_phantom": 1,
    "phantom_endpoints": [{"url": "http://127.0.0.1:3000/reviews", "method": "GET"}],
}


def test_the_written_document_names_the_route_that_does_not_exist(tmp_path: Path):
    """An unrouted endpoint is not a clean one, and the file has to say so."""
    md = _written_markdown(_agent(tmp_path, PHANTOM_REPORT).run("http://127.0.0.1:3000"))
    assert "### Not routed (1)" in md
    assert "`GET http://127.0.0.1:3000/reviews`" in md


def test_a_phantom_only_run_still_writes_the_section(tmp_path: Path):
    """Nothing tested is a result; a missing section would read as no web phase."""
    md = _written_markdown(_agent(tmp_path, PHANTOM_REPORT).run("http://127.0.0.1:3000"))
    assert "## Web Exploitation" in md


def test_a_run_without_phantoms_writes_no_such_block(tmp_path: Path):
    md = _written_markdown(_agent(tmp_path, WEB_REPORT).run("http://127.0.0.1:3000"))
    assert "Not routed" not in md


_BOLA_REPORT = {
    "confirmed": 0,
    "endpoints_tested": 0,
    "requests_sent": 5,
    "params_bola": 1,
    "bola_params": [
        {
            "url": "http://127.0.0.1:3000/rest/basket/{bid}",
            "parameter": "bid",
            "method": "GET",
            "transport": "path",
            "source": "js-route",
        }
    ],
}


def test_the_written_document_names_the_route_that_stopped_checking_ownership(tmp_path: Path):
    """A count is not an address, and this one has to be verified by hand."""
    md = _written_markdown(_agent(tmp_path, _BOLA_REPORT).run("http://127.0.0.1:3000"))
    assert "### Object authorization not enforced (1)" in md
    assert "`GET http://127.0.0.1:3000/rest/basket/{bid}` -- parameter `bid` (path, js-route)" in md


def test_a_run_that_tested_nothing_but_found_this_still_writes_the_section(tmp_path: Path):
    """The verdict costs no endpoint test, so the section gate has to count it.

    Every list the section can hold belongs in that gate: a report whose only
    content is one of them would otherwise be dropped whole, and a missing
    section reads as a web phase that never ran.
    """
    md = _written_markdown(_agent(tmp_path, _BOLA_REPORT).run("http://127.0.0.1:3000"))
    assert "## Web Exploitation" in md


def test_a_run_without_a_broken_object_check_writes_no_such_block(tmp_path: Path):
    md = _written_markdown(_agent(tmp_path, WEB_REPORT).run("http://127.0.0.1:3000"))
    assert "Object authorization" not in md

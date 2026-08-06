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


def test_a_network_only_run_writes_no_web_section(tmp_path):
    """No web phase, no heading claiming one ran."""
    md = _written_markdown(_agent(tmp_path, None).run("http://127.0.0.1:3000"))
    assert "## Web Exploitation" not in md

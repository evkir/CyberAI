"""The LLM executive section has to reach the file, not just the KB.

`run()` wrote the section into the knowledge base and stopped there, so a
paid-for call produced nothing the operator could read. These exercise the
real agent against a real path on disk: a test on the rendering helper alone
would have passed throughout the whole time the document was missing it.
"""

from pathlib import Path
from unittest.mock import MagicMock

from cyberai.agents.report.agent import ReportAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession, Severity

SECTION = {
    "title": "One confirmed injection",
    "severity": "HIGH",
    "findings": ["SQL injection in parameter q"],
    "recommendations": ["Parameterise the query"],
    "impact": "Database contents are readable by any visitor.",
}


def _agent(tmp_path: Path, *, use_llm_summary: bool) -> ReportAgent:
    config = CyberAIConfig()
    config.output_dir = tmp_path
    config.use_llm_summary = use_llm_summary
    session = ScanSession(target="http://127.0.0.1:3000")
    session.add_finding(
        severity=Severity.HIGH,
        title="SQL injection confirmed in parameter 'q'",
        description="SQLITE_ERROR in the response body",
        agent="exploit",
    )
    llm = MagicMock()
    llm.structured_call.return_value = dict(SECTION)
    return ReportAgent(config, session, llm=llm)


def _written_markdown(result: dict) -> str:
    return Path(result["markdown"]).read_text()


def test_the_section_reaches_the_written_document(tmp_path):
    agent = _agent(tmp_path, use_llm_summary=True)
    md = _written_markdown(agent.run("http://127.0.0.1:3000"))

    assert "Executive Section (LLM)" in md
    assert SECTION["impact"] in md
    assert SECTION["findings"][0] in md
    assert SECTION["recommendations"][0] in md


def test_the_section_is_absent_without_the_flag(tmp_path):
    agent = _agent(tmp_path, use_llm_summary=False)
    md = _written_markdown(agent.run("http://127.0.0.1:3000"))

    assert "Executive Section (LLM)" not in md
    agent.llm.structured_call.assert_not_called()


def test_a_failed_call_leaves_the_deterministic_report_intact(tmp_path):
    agent = _agent(tmp_path, use_llm_summary=True)
    agent.llm.structured_call.side_effect = RuntimeError("model down")
    result = agent.run("http://127.0.0.1:3000")
    md = _written_markdown(result)

    assert "Executive Section (LLM)" not in md
    # The report itself still exists and still carries the finding.
    assert "SQL injection confirmed" in md

"""Findings have to travel from the session to the file on their own.

Both renderer-level tests hand the findings in as an argument, so they would
stay green for as long as the orchestrator forgot to pass them — which is the
state this branch started from, and the same shape of gap as the executive
section that reached the KB and no further. This one runs the real report
phase against a real path on disk.
"""

from pathlib import Path

from cyberai.core.config import CyberAIConfig
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanSession, Severity


def _session(tmp_path: Path) -> ScanSession:
    session = ScanSession(target="http://127.0.0.1:3000")
    session.add_finding(
        severity=Severity.HIGH,
        title="SQL injection confirmed in parameter 'q'",
        description="A single quote reached the query.",
        agent="exploit",
        target="http://127.0.0.1:3000/rest/products/search",
        evidence=[{"proof": "SQLITE_ERROR surfaced", "parameter": "q"}],
    )
    return session


def test_a_session_finding_reaches_the_html_file(tmp_path, monkeypatch):
    config = CyberAIConfig()
    config.output_dir = tmp_path
    orch = Orchestrator(config)
    session = _session(tmp_path)

    monkeypatch.chdir(tmp_path)
    result = orch._run_report(session)

    html = Path(result["html_report"])
    # All three artefacts of one run belong together: a bare filename here
    # lands in the working directory while the markdown sits in output_dir.
    assert html.parent == tmp_path
    content = html.read_text(encoding="utf-8")
    assert "SQL injection confirmed in parameter &#x27;q&#x27;" in content or (
        "SQL injection confirmed in parameter 'q'" in content
    )
    assert "SQLITE_ERROR surfaced" in content
    assert "No findings recorded." not in content

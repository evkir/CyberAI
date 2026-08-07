"""The JSON report carries the analysis, and carries the key either way."""

import json
from pathlib import Path

from cyberai.agents.report.json_exporter import export_json
from cyberai.core.scan_session import ScanSession


def _export(tmp_path: Path, exploit=None) -> dict:
    s = ScanSession(target="t.local")
    if exploit is not None:
        s.kb.set("exploit", exploit, agent="exploit")
    return json.loads(Path(export_json(s, output_dir=str(tmp_path))).read_text())


def test_analysis_reaches_the_json_report(tmp_path):
    d = _export(tmp_path, {"ai_analysis": "SQLi confirmed in q via SQLITE_ERROR."})

    assert d["ai_analysis"] == "SQLi confirmed in q via SQLITE_ERROR."


def test_the_key_is_present_when_no_exploit_phase_ran(tmp_path):
    """A machine consumer should read an empty answer, not hit a KeyError."""
    d = _export(tmp_path)

    assert d["ai_analysis"] == ""


def test_the_key_is_present_when_the_model_was_never_asked(tmp_path):
    """Unlike Markdown, JSON keeps the skip notice: it is data, not a heading."""
    d = _export(tmp_path, {"ai_analysis": "AI analysis skipped — no LLM client configured."})

    assert "skipped" in d["ai_analysis"]

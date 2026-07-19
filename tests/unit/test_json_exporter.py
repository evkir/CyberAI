"""Regression: json_exporter must use real ScanSession attrs (session_id, not id)."""

import json
from pathlib import Path

from cyberai.core.scan_session import ScanSession
from cyberai.agents.report.json_exporter import export_json


def test_export_json_uses_session_id(tmp_path: Path) -> None:
    # Real ScanSession has `session_id`, NOT `id` — guards the refactor regression.
    session = ScanSession(target="scanme.nmap.org")
    out = export_json(session, str(tmp_path))
    data = json.loads(Path(out).read_text())
    assert data["session"]["id"] == session.session_id
    assert data["session"]["target"] == "scanme.nmap.org"


def test_export_json_no_findings_ok(tmp_path: Path) -> None:
    # Empty session must export cleanly (live scanme.nmap.org case).
    session = ScanSession(target="example.com")
    out = export_json(session, str(tmp_path))
    assert Path(out).exists()

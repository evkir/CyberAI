from pathlib import Path

from cyberai.agents.report.json_exporter import export_json
from cyberai.core.scan_session import ScanSession


def test_json_written_into_dir_not_repo_root(tmp_path):
    session = ScanSession(target="scanme.nmap.org")
    out = export_json(session, output_dir=str(tmp_path) + "/")
    p = Path(out)
    assert p.parent == tmp_path  # NOT collapsed to reports_report_... in cwd
    assert p.name.startswith("report_scanme.nmap.org_")
    assert p.exists()


def test_json_sanitizes_unsafe_target_but_keeps_separator(tmp_path):
    session = ScanSession(target="http://a.b/c:8080")
    out = export_json(session, output_dir=str(tmp_path) + "/")
    p = Path(out)
    assert p.parent == tmp_path  # directory separator survives
    assert ":" not in p.name and "/" not in p.name  # target chars sanitized in stem only

import pytest
from pathlib import Path
from cyberai.agents.report.html_renderer import (
    render_html_report,
    _render_phases,
    _render_attack_paths,
    _render_chain,
    _escape,
)

SESSION = {
    "session_id": "abc123",
    "target": "10.0.0.1",
    "state": "completed",
    "duration_s": 42.5,
    "phases": [
        {"phase": "recon", "success": True, "duration_s": 5.1, "error": None},
        {"phase": "intel", "success": True, "duration_s": 8.3, "error": None},
        {"phase": "exploit", "success": False, "duration_s": 2.0, "error": "timeout"},
    ],
}

KB = {
    "exploit": {
        "attack_paths": [
            {
                "cve_id": "CVE-2024-1234",
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "technique": "Remote code execution",
                "success_probability": 0.95,
                "severity_tier": "CRITICAL",
                "remediation": "Patch immediately.",
                "tags": ["remote", "no-auth"],
                "requires_auth": False,
                "requires_interaction": False,
                "notes": "CVSS 9.8 | PoC: Yes",
            }
        ],
        "exploit_chain": {
            "summary": "Initial Access → Execution",
            "steps": [
                {
                    "phase": "Initial Access",
                    "cve_id": "CVE-2024-1234",
                    "technique": "T1190",
                    "service": "http",
                    "cvss": 9.8,
                    "description": "RCE via Apache",
                }
            ],
        },
        "ai_analysis": "High risk target. Patch CVE-2024-1234 immediately.",
    }
}


def test_escape_html():
    assert _escape("<script>") == "&lt;script&gt;"
    assert _escape('"hello"') == "&quot;hello&quot;"
    assert _escape("a & b") == "a &amp; b"


def test_render_phases_success():
    html = _render_phases(SESSION["phases"])
    assert "RECON" in html
    assert "✓" in html
    assert "✗" in html
    assert "timeout" in html


def test_render_phases_empty():
    html = _render_phases([])
    assert "No phases" in html


def test_render_attack_paths():
    html = _render_attack_paths(KB["exploit"]["attack_paths"])
    assert "CVE-2024-1234" in html
    assert "CRITICAL" in html
    assert "95%" in html


def test_render_attack_paths_empty():
    html = _render_attack_paths([])
    assert "No attack paths" in html


def test_render_chain():
    html = _render_chain(KB["exploit"]["exploit_chain"])
    assert "Initial Access" in html
    assert "CVE-2024-1234" in html


def test_render_chain_empty():
    html = _render_chain({})
    assert "No exploit chain" in html


def test_render_html_report_creates_file(tmp_path):
    output = str(tmp_path / "report.html")
    result = render_html_report(SESSION, KB, output_path=output)
    assert result == output
    content = Path(output).read_text()
    assert "CyberAI" in content
    assert "10.0.0.1" in content
    assert "CVE-2024-1234" in content
    assert "abc123" in content


def test_render_html_report_escapes_xss(tmp_path):
    session = SESSION.copy()
    session["target"] = "<script>alert(1)</script>"
    output = str(tmp_path / "report_xss.html")
    render_html_report(session, KB, output_path=output)
    content = Path(output).read_text()
    assert "<script>" not in content

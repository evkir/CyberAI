import pytest
from pathlib import Path
from cyberai.agents.report.html_renderer import (
    render_html_report,
    _render_phases,
    _render_attack_paths,
    _render_chain,
    _escape,
    _detail_rows,
    _DETAIL_LIMIT,
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


def test_render_html_report_creates_its_own_directory(tmp_path):
    """Dropping the mkdir leaves every existing test green.

    In the pipeline the ReportAgent creates output_dir one line earlier, so
    the renderer works by accident there. A caller that writes HTML without
    that neighbour -- or a first run against a fresh output_dir -- gets a
    FileNotFoundError instead of a report.
    """
    output = str(tmp_path / "fresh" / "nested" / "report.html")

    render_html_report(SESSION, KB, output_path=output)

    assert Path(output).exists()
    assert "<html" in Path(output).read_text(encoding="utf-8").lower()


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


def _finding(**over):
    from cyberai.core.scan_session import Finding, Severity

    base = dict(
        id=1,
        severity=Severity.HIGH,
        title="SQL injection in q",
        description="A single quote breaks the query.",
        timestamp="2026-08-06T00:00:00Z",
        agent="exploit",
        target="http://127.0.0.1:3000/rest/products/search",
    )
    base.update(over)
    return Finding(**base)


def test_findings_reach_the_html_file(tmp_path):
    output = str(tmp_path / "findings.html")
    render_html_report(SESSION, KB, output_path=output, findings=[_finding()])
    content = Path(output).read_text()
    assert "SQL injection in q" in content
    assert "A single quote breaks the query." in content
    assert "rest/products/search" in content


def test_findings_placeholder_never_survives(tmp_path):
    output = str(tmp_path / "empty.html")
    render_html_report(SESSION, KB, output_path=output)
    content = Path(output).read_text()
    assert "{findings_html}" not in content
    assert "No findings recorded." in content


def test_finding_severity_drives_the_class(tmp_path):
    from cyberai.core.scan_session import Severity

    output = str(tmp_path / "sev.html")
    render_html_report(
        SESSION, KB, output_path=output, findings=[_finding(severity=Severity.CRITICAL)]
    )
    content = Path(output).read_text()
    # The attack-paths table also emits class='critical', so matching the class
    # alone stays green with the findings block gone. Brackets are the finding.
    assert "[CRITICAL]" in content


def test_finding_text_is_escaped(tmp_path):
    output = str(tmp_path / "xss_finding.html")
    render_html_report(
        SESSION, KB, output_path=output, findings=[_finding(title="<script>alert(1)</script>")]
    )
    content = Path(output).read_text()
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content


WEB_EVIDENCE = {
    "vuln_class": "sqli",
    "url": "http://127.0.0.1:3000/rest/products/search",
    "method": "GET",
    "parameter": "q",
    "payload": "apple'",
    "proof": "SQLITE_ERROR surfaced",
    "evidence": "SQLITE_ERROR: unrecognized token",
}


def test_evidence_reaches_the_html_file(tmp_path):
    output = str(tmp_path / "ev.html")
    render_html_report(
        SESSION, KB, output_path=output, findings=[_finding(evidence=[WEB_EVIDENCE])]
    )
    content = Path(output).read_text()
    assert "SQLITE_ERROR: unrecognized token" in content
    assert "apple&#x27;" in content or "apple'" in content


def test_evidence_is_rendered_as_fields_not_as_a_repr(tmp_path):
    output = str(tmp_path / "ev_fields.html")
    render_html_report(
        SESSION, KB, output_path=output, findings=[_finding(evidence=[WEB_EVIDENCE])]
    )
    content = Path(output).read_text()
    # The repr of the dict would carry both the brace and the quoted key.
    assert "{&#x27;url&#x27;" not in content
    assert "{'url'" not in content
    assert "<td>Vuln class</td>" in content


def test_data_wins_over_evidence_so_the_proof_prints_once(tmp_path):
    output = str(tmp_path / "once.html")
    render_html_report(
        SESSION,
        KB,
        output_path=output,
        findings=[_finding(data=WEB_EVIDENCE, evidence=[WEB_EVIDENCE])],
    )
    content = Path(output).read_text()
    assert content.count("SQLITE_ERROR: unrecognized token") == 1


@pytest.mark.parametrize("empty", [None, [], {}, ""])
def test_finding_without_details_renders_no_table(tmp_path, empty):
    """add_finding stores `evidence or []`, so a finding with no structured
    data is the common case and must not print an empty table."""
    output = str(tmp_path / f"bare_{type(empty).__name__}.html")
    render_html_report(
        SESSION, KB, output_path=output, findings=[_finding(data=empty, evidence=empty or [])]
    )
    content = Path(output).read_text()
    assert "<td>Vuln class</td>" not in content
    assert "<table class='cve-table'></table>" not in content
    assert "SQL injection in q" in content


@pytest.mark.parametrize("empty", ["", {}, [], None])
def test_detail_rows_emits_nothing_for_empty_payloads(empty):
    """The renderer's `data or evidence` collapses every empty form to a list
    before this is called, so the guard is unreachable from the report path
    and has to be pinned here. Without it an empty string renders <pre></pre>.
    """
    assert _detail_rows(empty) == ""


def test_detail_rows_drops_blanks_before_the_cap_not_after():
    """The filter runs before the slice, so blanks cannot consume the budget.

    Dropping it looks harmless on an all-blank list, because each entry
    recurses into the empty guard and yields nothing either way. It stops
    being harmless once blanks outnumber the cap: the real entry is then
    sliced away and the proof leaves the report.
    """
    payload = [{} for _ in range(_DETAIL_LIMIT)] + [{"proof": "SQLITE_ERROR"}]
    assert "SQLITE_ERROR" in _detail_rows(payload)


def test_detail_rows_skips_a_list_of_empty_entries():
    assert _detail_rows([{}, "", None, []]) == ""


def test_detail_rows_skips_blank_values_inside_a_dict():
    payload = {"url": "http://t/x", "payload": "", "proof": None, "transport": []}
    rows = _detail_rows(payload)
    assert "<td>Url</td>" in rows
    assert "<td>Payload</td>" not in rows
    assert "<td>Proof</td>" not in rows
    assert "<td>Transport</td>" not in rows


def test_detail_rows_skips_a_dict_of_blank_values():
    assert _detail_rows({"payload": "", "proof": None}) == ""


def test_detail_rows_renders_a_scalar_as_a_block():
    """Recon findings store a plain string, not a mapping."""
    assert _detail_rows("22/tcp open ssh") == "<pre>22/tcp open ssh</pre>"


def test_finding_cve_and_low_confidence_reach_the_page(tmp_path):
    output = str(tmp_path / "meta.html")
    finding = _finding(cve="CVE-2021-44228")
    finding.confidence = 0.4
    render_html_report(SESSION, KB, output_path=output, findings=[finding])
    content = Path(output).read_text()
    assert "CVE-2021-44228" in content
    assert "40%" in content


def test_finding_without_cve_or_doubt_says_neither(tmp_path):
    output = str(tmp_path / "meta_bare.html")
    render_html_report(SESSION, KB, output_path=output, findings=[_finding()])
    content = Path(output).read_text()
    assert "<strong>CVE:</strong>" not in content
    assert "<strong>Confidence:</strong>" not in content

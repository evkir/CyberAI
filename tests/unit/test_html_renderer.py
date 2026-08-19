from pathlib import Path

import pytest

from cyberai.agents.report.html_renderer import (
    _DETAIL_LIMIT,
    _detail_rows,
    _escape,
    _render_attack_paths,
    _render_chain,
    _render_phases,
    render_html_report,
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


def _live_kb(web_report):
    """A real KnowledgeBase, not the nested dict the constants above use.

    The section reads a flat dotted key; a test on a plain dict would pass
    on a shape the product never builds. The constants above are that
    shape: they nest everything under one `exploit` dict, which the agent
    does write, but the web report never lands there.
    """
    from cyberai.core.scan_session import ScanSession

    session = ScanSession(target="http://127.0.0.1:3000")
    if web_report is not None:
        session.kb.set("exploit.web", web_report, agent="exploit")
    return session.kb


_WEB_REPORT = {
    "endpoints_tested": 11,
    "requests_sent": 187,
    "confirmed": 1,
    "unauthorized_params": [
        {
            "url": "http://127.0.0.1:3000/rest/user/security-question",
            "parameter": "email",
            "method": "GET",
        }
    ],
    "destructive_endpoints": [{"url": "http://127.0.0.1:3000/api/Users/1", "method": "DELETE"}],
}


def test_the_web_section_reaches_the_html_file(tmp_path):
    output = str(tmp_path / "web.html")
    render_html_report(SESSION, _live_kb(_WEB_REPORT), output_path=output)
    content = Path(output).read_text()
    assert "Web Exploitation" in content
    assert "rest/user/security-question" in content
    assert "api/Users/1" in content


def test_a_reachable_collector_is_stated_on_the_page(tmp_path):
    """The page has to carry what the markdown file carries. The markdown
    section grew this line first and the page did not, which is the exact
    split that left twelve web contract tests green while the page was
    missing the section entirely."""
    output = str(tmp_path / "oob_live.html")
    render_html_report(
        SESSION, _live_kb({**_WEB_REPORT, "oob_channel": "live"}), output_path=output
    )
    assert "Out-of-band collector: reachable" in Path(output).read_text()


def test_an_unreachable_collector_is_stated_on_the_page(tmp_path):
    """Zero confirmations read as a clean target unless the page says the
    collector was never there. Measured on Juice Shop: a foreign app holding
    the grid port produced findings byte-identical to the live-grid run."""
    output = str(tmp_path / "oob_dead.html")
    render_html_report(
        SESSION, _live_kb({**_WEB_REPORT, "oob_channel": "unavailable"}), output_path=output
    )
    content = Path(output).read_text()
    assert "requested and not reachable" in content
    assert "reachable for this run" not in content


def test_a_page_for_a_run_without_a_collector_says_nothing(tmp_path):
    """_WEB_REPORT has no oob_channel key at all -- the shape of every run
    without a collector, and of every report written before the field
    existed. A line on the common path is how a real line stops being read."""
    output = str(tmp_path / "oob_off.html")
    render_html_report(SESSION, _live_kb(_WEB_REPORT), output_path=output)
    assert "Out-of-band collector" not in Path(output).read_text()


def test_the_web_section_names_the_counts(tmp_path):
    output = str(tmp_path / "counts.html")
    render_html_report(SESSION, _live_kb(_WEB_REPORT), output_path=output)
    content = Path(output).read_text()
    assert "187" in content


def test_the_web_section_is_not_filed_under_the_attack_paths_heading(tmp_path):
    """The heading has to sit over the table it names.

    The template used to open with the Attack Paths heading and only then
    substitute the web section, so a confirmed SQL injection printed under a
    heading for CVE-driven machinery that produced nothing on that run.

    Both blocks are asserted present first. That is for the failure message,
    not for the check: `index` raises on a missing block and a ValueError
    does not say which one went missing. The comparison catches the order
    either way.
    """
    from cyberai.core.scan_session import ScanSession

    session = ScanSession(target="http://127.0.0.1:3000")
    session.kb.set("exploit.web", _WEB_REPORT, agent="exploit")
    session.kb.set("exploit", {"attack_paths": KB["exploit"]["attack_paths"]}, agent="exploit")

    output = str(tmp_path / "order.html")
    render_html_report(SESSION, session.kb, output_path=output)
    content = Path(output).read_text()

    for block in ("Web Exploitation", "Attack Paths", "CVE-2024-1234"):
        assert block in content, f"{block} is missing, so its position proves nothing"
    assert content.index("Web Exploitation") < content.index("Attack Paths")
    assert content.index("Attack Paths") < content.index("CVE-2024-1234")


def test_a_run_without_a_web_phase_writes_no_web_section(tmp_path):
    """Control: without this the assertions above pass on a hardcoded block."""
    output = str(tmp_path / "noweb.html")
    render_html_report(SESSION, _live_kb(None), output_path=output)
    content = Path(output).read_text()
    assert "Web Exploitation" not in content
    assert "{web_exploitation_html}" not in content


def test_a_web_phase_that_found_nothing_writes_no_section(tmp_path):
    """The key is present and the phase ran, but it walked nothing.

    Distinct from the absent key above: this report is a dict and passes
    the type guard, so without the count check the page would print a
    heading over an empty body and claim a walk that found no surface.
    """
    output = str(tmp_path / "emptyweb.html")
    render_html_report(SESSION, _live_kb({"endpoints_tested": 0}), output_path=output)
    content = Path(output).read_text()
    assert "Web Exploitation" not in content
    assert "{web_exploitation_html}" not in content


_BOLA_ONLY_REPORT = {
    "endpoints_tested": 0,
    "requests_sent": 5,
    "confirmed": 0,
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


def test_the_page_names_the_route_that_stopped_checking_ownership(tmp_path):
    """The heading alone is a count; the reader has to be given the address."""
    output = str(tmp_path / "bola.html")
    render_html_report(SESSION, _live_kb(_BOLA_ONLY_REPORT), output_path=output)
    content = Path(output).read_text()
    assert "Object authorization not enforced (1)" in content
    assert "rest/basket/{bid}" in content
    assert "bid" in content


def test_a_web_phase_that_only_found_this_still_writes_the_section(tmp_path):
    """No endpoint was tested, so the count check alone would drop the page.

    The verdict costs the walk nothing it counts as a test, which is what
    separates this from the empty report above: there is something to say
    and no tested endpoint to say it under.
    """
    output = str(tmp_path / "bolaonly.html")
    render_html_report(SESSION, _live_kb(_BOLA_ONLY_REPORT), output_path=output)
    content = Path(output).read_text()
    assert "Web Exploitation" in content
    assert "{web_exploitation_html}" not in content


def test_a_run_without_a_broken_object_check_writes_no_such_heading(tmp_path):
    """Control: without it the assertions above pass on a hardcoded block."""
    output = str(tmp_path / "nobola.html")
    render_html_report(SESSION, _live_kb(_WEB_REPORT), output_path=output)
    content = Path(output).read_text()
    assert "Object authorization" not in content


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


def _redteam_kb(redteam):
    """A real KnowledgeBase, and the key the orchestrator actually writes.

    The counters live nested under `exploit`, not under a flat dotted key the
    way the web report does: the orchestrator merges the fuzzer result into
    the exploit phase dict before storing it. A fixture built the other way
    would pass on a shape the product never produces.
    """
    from cyberai.core.scan_session import ScanSession

    session = ScanSession(target="http://127.0.0.1:3000")
    if redteam is not None:
        session.kb.set("exploit", {"redteam": redteam}, agent="exploit")
    return session.kb


_CHANNEL = {
    "channel_id": "http://127.0.0.1:3000/rest/chat",
    "oob_used": False,
    "confirmed_count": 0,
    "flagged_count": 2,
    "skipped_count": 3,
}
_REDTEAM = {"channels": 1, "confirmed": 0, "flagged": 2, "reports": [_CHANNEL]}


def test_the_channel_section_reaches_the_html_file(tmp_path):
    output = str(tmp_path / "rt.html")
    render_html_report(SESSION, _redteam_kb(_REDTEAM), output_path=output)
    content = Path(output).read_text()

    assert "LLM Channel Red-Team" in content
    # The heading alone would pass with an empty list; require the address.
    assert "http://127.0.0.1:3000/rest/chat" in content
    assert "Channels fuzzed: 1 | Confirmed: 0 | Flagged: 2" in content


def test_undelivered_payloads_reach_the_page(tmp_path):
    """Three payloads never left. A page showing only "0 confirmed" reads as a
    channel that took every payload and stayed clean."""
    output = str(tmp_path / "rt_skipped.html")
    render_html_report(SESSION, _redteam_kb(_REDTEAM), output_path=output)
    content = Path(output).read_text()

    assert "not delivered 3" in content
    assert "no OOB channel" in content


def test_a_live_oob_channel_is_distinguished_on_the_page(tmp_path):
    output = str(tmp_path / "rt_oob.html")
    kb = _redteam_kb({**_REDTEAM, "reports": [{**_CHANNEL, "oob_used": True}]})
    render_html_report(SESSION, kb, output_path=output)
    content = Path(output).read_text()

    assert "OOB channel used" in content
    assert "no OOB channel" not in content


def test_the_channel_row_carries_its_own_counters(tmp_path):
    output = str(tmp_path / "rt_counts.html")
    kb = _redteam_kb({**_REDTEAM, "reports": [{**_CHANNEL, "flagged_count": 7}]})
    render_html_report(SESSION, kb, output_path=output)

    assert "flagged 7" in Path(output).read_text()


def test_a_channel_id_is_escaped(tmp_path):
    """The address comes off the wire. Rendered raw it would run."""
    output = str(tmp_path / "rt_xss.html")
    kb = _redteam_kb({**_REDTEAM, "reports": [{**_CHANNEL, "channel_id": "<script>x</script>"}]})
    render_html_report(SESSION, kb, output_path=output)
    content = Path(output).read_text()

    assert "<script>x</script>" not in content
    assert "&lt;script&gt;" in content


def test_no_section_when_no_channel_was_fuzzed(tmp_path):
    output = str(tmp_path / "rt_none.html")
    kb = _redteam_kb({"channels": 0, "confirmed": 0, "flagged": 0, "reports": []})
    render_html_report(SESSION, kb, output_path=output)
    content = Path(output).read_text()

    assert "LLM Channel Red-Team" not in content
    # An unsubstituted placeholder is worse than an absent section: it prints
    # the template's own syntax onto the page a reader opens.
    assert "{redteam_html}" not in content


def test_no_section_without_a_redteam_run(tmp_path):
    output = str(tmp_path / "rt_absent.html")
    render_html_report(SESSION, _redteam_kb(None), output_path=output)
    content = Path(output).read_text()

    assert "LLM Channel Red-Team" not in content
    assert "{redteam_html}" not in content


def test_malformed_shapes_do_not_render_a_heading(tmp_path):
    from cyberai.core.scan_session import ScanSession

    session = ScanSession(target="t.local")
    session.kb.set("exploit", {"redteam": "yes"}, agent="exploit")
    output = str(tmp_path / "rt_bad.html")
    render_html_report(SESSION, session.kb, output_path=output)

    assert "LLM Channel Red-Team" not in Path(output).read_text()

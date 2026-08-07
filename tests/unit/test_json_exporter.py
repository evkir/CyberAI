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


WEB_REPORT = {
    "confirmed": 1,
    "endpoints_tested": 13,
    "requests_sent": 236,
    "params_unauthorized": 1,
    "unauthorized_params": [
        {
            "url": "http://127.0.0.1:3000/rest/2fa/setup",
            "parameter": "password",
            "method": "POST",
            "transport": "query",
        }
    ],
    "params_inert": 1,
    "inert_params": [
        {
            "url": "http://127.0.0.1:3000/engine.io",
            "parameter": "agent",
            "method": "GET",
            "transport": "query",
        }
    ],
    "destructive_endpoints": [
        {"url": "http://127.0.0.1:3000/rest/basket/{e}/coupon/{i}", "method": "PUT"}
    ],
}


def test_web_exploitation_reaches_the_json_file(tmp_path: Path) -> None:
    """The Markdown names every address; this file named none of them."""
    session = ScanSession(target="http://127.0.0.1:3000")
    session.kb.set("exploit.web", dict(WEB_REPORT), agent="exploit")
    out = export_json(session, str(tmp_path))
    data = json.loads(Path(out).read_text())

    web = data["web_exploitation"]
    assert [p["url"] for p in web["inert_params"]] == ["http://127.0.0.1:3000/engine.io"]
    assert [p["parameter"] for p in web["unauthorized_params"]] == ["password"]
    assert web["destructive_endpoints"][0]["method"] == "PUT"
    assert web["requests_sent"] == 236


def test_web_exploitation_key_is_present_without_a_web_phase(tmp_path: Path) -> None:
    """A network-only run has no exploit.web; the key still has to exist, or a
    consumer cannot tell a missing key from a target that was never walked."""
    session = ScanSession(target="scanme.nmap.org")
    out = export_json(session, str(tmp_path))
    data = json.loads(Path(out).read_text())
    assert data["web_exploitation"] == {}


def test_phantom_endpoints_reach_the_json_export(tmp_path: Path) -> None:
    """The machine-readable path carries the unrouted verdict without a per-key edit.

    The exporter passes `exploit.web` through whole, so a new field arrives on
    its own. That is a property worth pinning: the previous shape read one key
    at a time, and every field added to the web phase went missing until
    someone noticed.
    """
    session = ScanSession(target="http://127.0.0.1:3000")
    session.kb.set(
        "exploit.web",
        {
            "confirmed": 0,
            "endpoints_tested": 0,
            "endpoints_phantom": 1,
            "phantom_endpoints": [{"url": "http://127.0.0.1:3000/reviews", "method": "GET"}],
        },
        agent="exploit",
    )
    data = json.loads(Path(export_json(session, str(tmp_path))).read_text())
    web = data["web_exploitation"]
    assert web["endpoints_phantom"] == 1
    assert web["phantom_endpoints"] == [{"url": "http://127.0.0.1:3000/reviews", "method": "GET"}]

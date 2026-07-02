"""Nuclei engine + searchsploit: parsing, subprocess mock, OOB wiring."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from cyberai.agents.exploit.nuclei_engine import (
    NucleiEngine,
    NucleiFinding,
    find_nuclei,
    parse_jsonl,
)
from cyberai.agents.exploit.searchsploit import (
    ExploitRecord,
    SearchSploit,
    parse_output,
)


# ── nuclei JSONL parser ───────────────────────────────────────────────

# Real v3.8.0 line shapes captured from a live run.
_WAF_LINE = json.dumps(
    {
        "template-id": "waf-detect",
        "info": {
            "name": "WAF Detection",
            "severity": "info",
            "classification": {"cve-id": None, "cwe-id": ["cwe-200"]},
        },
        "type": "http",
        "host": "scanme.nmap.org",
        "matched-at": "http://scanme.nmap.org",
    }
)
_CVE_LINE = json.dumps(
    {
        "template-id": "CVE-2021-44228",
        "info": {
            "name": "Log4Shell",
            "severity": "critical",
            "classification": {"cve-id": ["CVE-2021-44228"]},
        },
        "type": "http",
        "host": "victim.local",
        "matched-at": "http://victim.local/api",
    }
)


def test_parse_single_line():
    fs = parse_jsonl(_WAF_LINE)
    assert len(fs) == 1
    f = fs[0]
    assert f.template_id == "waf-detect"
    assert f.severity == "info"
    assert f.cve_id is None  # null handled


def test_parse_cve_id_list_takes_first():
    f = parse_jsonl(_CVE_LINE)[0]
    assert f.cve_id == "CVE-2021-44228"
    assert f.severity == "critical"


def test_parse_multiline_and_garbage():
    blob = _WAF_LINE + "\n\ngarbage{\n" + _CVE_LINE
    fs = parse_jsonl(blob)
    assert len(fs) == 2  # garbage line skipped


def test_parse_empty():
    assert parse_jsonl("") == []


# ── NucleiEngine.run (subprocess mocked) ──────────────────────────────


@patch("cyberai.agents.exploit.nuclei_engine.os.path.exists", return_value=True)
@patch("cyberai.agents.exploit.nuclei_engine.subprocess.run")
def test_run_parses_stdout(mock_run, _exists):
    mock_run.return_value = MagicMock(stdout=_CVE_LINE, returncode=0)
    eng = NucleiEngine(nuclei_path="/fake/nuclei")
    findings = eng.run("victim.local", cve_id="CVE-2021-44228")
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2021-44228"
    # command carries -id and the jsonl/omit-raw flags
    cmd = mock_run.call_args.args[0]
    assert "-id" in cmd and "CVE-2021-44228" in cmd
    assert "-jsonl" in cmd and "-omit-raw" in cmd


@patch("cyberai.agents.exploit.nuclei_engine.os.path.exists", return_value=True)
@patch("cyberai.agents.exploit.nuclei_engine.subprocess.run")
def test_run_tags(mock_run, _exists):
    mock_run.return_value = MagicMock(stdout="", returncode=0)
    eng = NucleiEngine(nuclei_path="/fake/nuclei")
    eng.run("victim.local", tags=["cve", "rce"])
    cmd = mock_run.call_args.args[0]
    assert "-tags" in cmd
    assert "cve,rce" in cmd


@patch("cyberai.agents.exploit.nuclei_engine.os.path.exists", return_value=True)
@patch("cyberai.agents.exploit.nuclei_engine.subprocess.run")
def test_run_injects_oob_var(mock_run, _exists):
    mock_run.return_value = MagicMock(stdout="", returncode=0)
    eng = NucleiEngine(nuclei_path="/fake/nuclei")
    eng.extra_vars = {"oob": "http://grid.local/c/tok1"}
    eng.run("victim.local", cve_id="CVE-2021-44228")
    cmd = mock_run.call_args.args[0]
    assert "-var" in cmd
    assert "oob=http://grid.local/c/tok1" in cmd


@patch("cyberai.agents.exploit.nuclei_engine.os.path.exists", return_value=True)
@patch("cyberai.agents.exploit.nuclei_engine.subprocess.run")
def test_run_timeout_returns_empty(mock_run, _exists):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=1)
    eng = NucleiEngine(nuclei_path="/fake/nuclei")
    assert eng.run("victim.local", cve_id="CVE-X") == []


@patch("cyberai.agents.exploit.nuclei_engine.find_nuclei", return_value=None)
def test_run_unavailable_returns_empty(_find):
    eng = NucleiEngine()
    assert eng.available is False
    assert eng.run("victim.local", cve_id="CVE-X") == []


def test_find_nuclei_env(monkeypatch, tmp_path):
    fake = tmp_path / "nuclei"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("NUCLEI_PATH", str(fake))
    assert find_nuclei() == str(fake)


# ── searchsploit parser + graceful ────────────────────────────────────

_SS_JSON = json.dumps(
    {
        "SEARCH": "CVE-2021-44228",
        "RESULTS_EXPLOIT": [
            {
                "Title": "Apache Log4j 2 - RCE (Log4Shell)",
                "EDB-ID": "50592",
                "Path": "/opt/exploitdb/exploits/java/remote/50592.py",
                "Type": "remote",
                "Platform": "java",
                "Date_Published": "2021-12-14",
            }
        ],
        "RESULTS_SHELLCODE": [],
    }
)


def test_searchsploit_parse():
    recs = parse_output(_SS_JSON)
    assert len(recs) == 1
    assert recs[0].edb_id == "50592"
    assert recs[0].path.endswith("50592.py")
    assert recs[0].platform == "java"


def test_searchsploit_parse_empty_and_garbage():
    assert parse_output("") == []
    assert parse_output("not json") == []
    assert parse_output('{"SEARCH":"x","RESULTS_EXPLOIT":[]}') == []


@patch("cyberai.agents.exploit.searchsploit.os.path.exists", return_value=True)
@patch("cyberai.agents.exploit.searchsploit.subprocess.run")
def test_searchsploit_search(mock_run, _exists):
    mock_run.return_value = MagicMock(stdout=_SS_JSON, returncode=0)
    ss = SearchSploit(searchsploit_path="/fake/searchsploit")
    recs = ss.search_cve("CVE-2021-44228")
    assert len(recs) == 1
    assert isinstance(recs[0], ExploitRecord)
    cmd = mock_run.call_args.args[0]
    assert "-j" in cmd and "CVE-2021-44228" in cmd


@patch("cyberai.agents.exploit.searchsploit.find_searchsploit", return_value=None)
def test_searchsploit_unavailable(_find):
    ss = SearchSploit()
    assert ss.available is False
    assert ss.search("anything") == []


# ── ExploitAgent OOB heuristic + _run_nuclei wiring ───────────────────


def _agent():
    from cyberai.agents.exploit.agent import ExploitAgent

    agent = ExploitAgent.__new__(ExploitAgent)
    agent.AGENT_NAME = "exploit"
    agent._log = MagicMock()
    agent._iterations = 0
    agent.config = MagicMock()
    agent.config.max_agent_iterations = 10
    return agent


def test_cve_needs_oob_jndi():
    agent = _agent()
    # Log4Shell is in the internal poc_mapper with JNDI technique.
    assert agent._cve_needs_oob("CVE-2021-44228") is True


def test_run_nuclei_unavailable_engine(monkeypatch):
    import cyberai.agents.exploit.agent as ag

    monkeypatch.setattr(ag, "NucleiEngine", lambda *a, **k: MagicMock(available=False))
    agent = _agent()
    assert agent._run_nuclei("victim.local", [{"cve_id": "CVE-2021-44228"}]) == []


def test_run_nuclei_collects_findings(monkeypatch):
    import cyberai.agents.exploit.agent as ag

    fake_engine = MagicMock()
    fake_engine.available = True
    fake_engine.extra_vars = {}
    fake_engine.run.return_value = [
        NucleiFinding(
            template_id="CVE-2021-44228",
            name="Log4Shell",
            severity="critical",
            host="victim.local",
            matched_at="http://victim.local",
            cve_id="CVE-2021-44228",
        )
    ]
    monkeypatch.setattr(ag, "NucleiEngine", lambda *a, **k: fake_engine)
    # grid unavailable -> no oob host, but findings still collected
    monkeypatch.setattr(ag, "PhantomGridClient", lambda *a, **k: MagicMock(available=False))
    agent = _agent()
    res = agent._run_nuclei("victim.local", [{"cve_id": "CVE-2021-44228"}])
    assert len(res) == 1
    assert res[0]["cve_id"] == "CVE-2021-44228"

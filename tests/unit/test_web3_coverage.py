"""Coverage for aderyn execution paths and web3 agent tool/address branches."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import cyberai.agents.web3.agent as ag
from cyberai.agents.web3 import aderyn_tool as at
from cyberai.agents.web3.aderyn_tool import AderynTool, find_aderyn, parse_aderyn_json
from cyberai.agents.web3.agent import SmartContractAgent
from cyberai.core.scan_session import ScanSession


def _tool(tmp_path):
    fake = tmp_path / "aderyn"
    fake.write_text("#!/bin/sh\n")
    return AderynTool(aderyn_path=str(fake))


class _Proc:
    returncode = 0
    stdout = ""
    stderr = ""


_PAYLOAD = {
    "high_issues": {
        "issues": [
            {
                "title": "t",
                "description": "d",
                "detector_name": "selfdestruct",
                "instances": [{}],
            }
        ]
    }
}


def _sol(tmp_path):
    """A real .sol path — the argument shape production sends (rule 90)."""
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    sol = contracts / "Vault.sol"
    sol.write_text("contract Vault {}\n")
    return sol


def test_analyze_runs_and_parses(tmp_path):
    tool = _tool(tmp_path)
    sol = _sol(tmp_path)

    def _write(cmd, **kwargs):
        out = cmd[cmd.index("-o") + 1]
        Path(out).write_text(json.dumps(_PAYLOAD))
        return _Proc()

    with patch("cyberai.agents.web3.aderyn_tool.subprocess.run", side_effect=_write) as run:
        findings = tool.analyze(str(sol))

    run.assert_called_once()
    cmd = run.call_args.args[0]
    assert cmd[1] == str(sol.parent)
    assert "--skip-update-check" in cmd
    assert [f.detector_name for f in findings] == ["selfdestruct"]


def test_analyze_sol_file_passes_directory_and_bare_include(tmp_path):
    """aderyn 0.1.9 panics on a .sol ROOT; the include must be a bare name."""
    tool = _tool(tmp_path)
    sol = _sol(tmp_path)

    def _write(cmd, **kwargs):
        Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(_PAYLOAD))
        return _Proc()

    with patch("cyberai.agents.web3.aderyn_tool.subprocess.run", side_effect=_write) as run:
        tool.analyze(str(sol))

    cmd = run.call_args.args[0]
    assert str(sol) not in cmd
    assert cmd[cmd.index("--path-includes") + 1] == "Vault.sol"


def test_analyze_project_root_passes_no_include(tmp_path):
    """A directory target is already the shape aderyn wants — no filtering."""
    tool = _tool(tmp_path)
    root = tmp_path / "project"
    root.mkdir()

    def _write(cmd, **kwargs):
        Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(_PAYLOAD))
        return _Proc()

    with patch("cyberai.agents.web3.aderyn_tool.subprocess.run", side_effect=_write) as run:
        tool.analyze(str(root))

    cmd = run.call_args.args[0]
    assert cmd[1] == str(root)
    assert "--path-includes" not in cmd


def test_analyze_logs_nonzero_returncode(tmp_path, caplog):
    """rc=101 was invisible for three releases: available=True, findings=[]."""
    tool = _tool(tmp_path)

    class _Panic:
        returncode = 101
        stdout = ""
        stderr = "Os { code: 20, kind: NotADirectory }"

    with patch(
        "cyberai.agents.web3.aderyn_tool.subprocess.run", side_effect=lambda *a, **k: _Panic()
    ):
        with caplog.at_level("WARNING", logger="cyberai.web3.aderyn"):
            assert tool.analyze(str(_sol(tmp_path))) == []

    assert "101" in caplog.text
    assert "NotADirectory" in caplog.text


def test_analyze_timeout_graceful(tmp_path):
    tool = _tool(tmp_path)
    with patch(
        "cyberai.agents.web3.aderyn_tool.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="aderyn", timeout=1),
    ):
        assert tool.analyze("V.sol") == []


def test_analyze_exception_graceful(tmp_path):
    tool = _tool(tmp_path)
    with patch("cyberai.agents.web3.aderyn_tool.subprocess.run", side_effect=OSError("boom")):
        assert tool.analyze("V.sol") == []


def test_analyze_missing_report_returns_empty(tmp_path):
    tool = _tool(tmp_path)
    with patch(
        "cyberai.agents.web3.aderyn_tool.subprocess.run", side_effect=lambda *a, **k: _Proc()
    ):
        assert tool.analyze("V.sol") == []  # no report file written


def test_find_aderyn_fallback_path(monkeypatch):
    monkeypatch.delenv("ADERYN_PATH", raising=False)
    target = at._FALLBACK_PATHS[0]
    with patch.object(at.shutil, "which", return_value=None):
        with patch.object(at.os.path, "exists", side_effect=lambda p: p == target):
            assert find_aderyn() == target


def _agent():
    agent = SmartContractAgent.__new__(SmartContractAgent)
    agent.AGENT_NAME = "web3"
    agent._log = MagicMock()
    agent.kb = MagicMock()
    agent.session = ScanSession(target="x")
    return agent


def test_aderyn_scan_tool_method(monkeypatch):
    fake = MagicMock()
    fake.available = True
    fake.analyze.return_value = parse_aderyn_json(
        '{"low_issues":{"issues":[{"title":"t","description":"d",'
        '"detector_name":"ecrecover","instances":[{}]}]}}'
    )
    monkeypatch.setattr(ag, "AderynTool", lambda *a, **k: fake)
    out = _agent()._aderyn_scan("V.sol")
    assert out["available"] is True
    assert out["count"] == 1
    assert out["findings"][0]["check"] == "ecrecover"


def test_fetch_source_verified(monkeypatch):
    src = MagicMock()
    src.address = "0xabc"
    src.name = "Tok"
    src.verified = True
    src.compiler_version = "0.8.20"
    src.source_code = "contract {}"
    client = MagicMock()
    client.get_source.return_value = src
    monkeypatch.setattr(ag, "EtherscanClient", lambda *a, **k: client)
    out = _agent()._fetch_source("0xabc")
    assert out["verified"] is True
    assert out["name"] == "Tok"


def test_fetch_source_missing(monkeypatch):
    client = MagicMock()
    client.get_source.return_value = None
    monkeypatch.setattr(ag, "EtherscanClient", lambda *a, **k: client)
    assert _agent()._fetch_source("0xabc") == {"verified": False, "source_code": ""}


def test_run_address_mode_uses_fetch_source():
    agent = _agent()
    agent.call_tool = MagicMock(return_value={"verified": True})
    res = agent.run("0xABCDEF1234")
    assert res["mode"] == "address"
    assert res["source_meta"] == {"verified": True}
    agent.call_tool.assert_called_once_with("fetch_source", address="0xABCDEF1234")


def test_find_aderyn_via_which(monkeypatch):
    monkeypatch.delenv("ADERYN_PATH", raising=False)
    with patch.object(at.shutil, "which", return_value="/usr/bin/aderyn"):
        assert find_aderyn() == "/usr/bin/aderyn"


def test_analyze_unreadable_report(tmp_path):
    tool = _tool(tmp_path)

    def _write(cmd, **kwargs):
        out = cmd[cmd.index("-o") + 1]
        Path(out).write_text('{"low_issues":{"issues":[]}}')
        return _Proc()

    with patch("cyberai.agents.web3.aderyn_tool.subprocess.run", side_effect=_write):
        with patch.object(at.Path, "read_text", side_effect=OSError("perm")):
            assert tool.analyze("V.sol") == []


def test_slither_scan_tool_method(monkeypatch):
    from cyberai.agents.web3.slither_tool import parse_slither_json

    fake = MagicMock()
    fake.available = True
    fake.analyze.return_value = parse_slither_json(
        '{"results":{"detectors":[{"check":"reentrancy-eth","impact":"High",'
        '"confidence":"Medium","description":"d","id":"1"}]}}'
    )
    monkeypatch.setattr(ag, "SlitherTool", lambda *a, **k: fake)
    out = _agent()._slither_scan("V.sol")
    assert out["available"] is True
    assert out["highest_severity"] == "Critical"
    assert out["count"] == 1

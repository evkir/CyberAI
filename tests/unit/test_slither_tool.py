"""SlitherTool: binary discovery, output parsing and sealed execution.

analyze() was previously exercised only by a live test gated on slither being
installed, so every branch below was unreachable on a machine without it —
including the sealed-exec call site.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from cyberai.agents.web3 import slither_tool as st
from cyberai.agents.web3.slither_tool import SlitherTool, find_slither, parse_slither_json

_REPORT = json.dumps(
    {
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "Reentrancy in withdraw()",
                }
            ]
        }
    }
)


# -- find_slither ------------------------------------------------------


def test_find_slither_env_override(tmp_path, monkeypatch):
    fake = tmp_path / "slither"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("SLITHER_PATH", str(fake))
    assert find_slither() == str(fake)


def test_find_slither_via_which(monkeypatch):
    monkeypatch.delenv("SLITHER_PATH", raising=False)
    with patch.object(st.shutil, "which", return_value="/usr/bin/slither"):
        assert find_slither() == "/usr/bin/slither"


def test_find_slither_falls_back_to_known_paths(monkeypatch):
    monkeypatch.delenv("SLITHER_PATH", raising=False)
    target = st._FALLBACK_PATHS[0]
    with (
        patch.object(st.shutil, "which", return_value=None),
        patch.object(st.os.path, "exists", side_effect=lambda p: p == target),
    ):
        assert find_slither() == target


def test_find_slither_returns_none_when_absent(monkeypatch):
    monkeypatch.delenv("SLITHER_PATH", raising=False)
    with (
        patch.object(st.shutil, "which", return_value=None),
        patch.object(st.os.path, "exists", return_value=False),
    ):
        assert find_slither() is None


# -- parse_slither_json ------------------------------------------------


def test_parse_empty_output():
    assert parse_slither_json("") == []
    assert parse_slither_json("   ") == []


def test_parse_garbage_output():
    assert parse_slither_json("not json at all") == []


def test_parse_report_yields_findings():
    findings = parse_slither_json(_REPORT)
    assert len(findings) == 1
    assert findings[0].check == "reentrancy-eth"


# -- analyze -----------------------------------------------------------


def test_analyze_unavailable_returns_empty():
    with patch.object(st, "find_slither", return_value=None):
        tool = SlitherTool()
    assert tool.available is False
    with patch.object(st, "run_sealed") as run:
        assert tool.analyze("x.sol") == []
        run.assert_not_called()


@patch("cyberai.agents.web3.slither_tool.os.path.exists", return_value=True)
@patch("cyberai.agents.web3.slither_tool.run_sealed")
def test_analyze_parses_stdout(mock_run, _exists):
    mock_run.return_value = MagicMock(stdout=_REPORT, returncode=255)
    tool = SlitherTool(slither_path="/fake/slither")
    findings = tool.analyze("dao.sol")
    assert [f.check for f in findings] == ["reentrancy-eth"]
    argv = mock_run.call_args.args[0]
    assert argv[:1] == ["/fake/slither"]
    assert "--json" in argv


@patch("cyberai.agents.web3.slither_tool.os.path.exists", return_value=True)
@patch("cyberai.agents.web3.slither_tool.run_sealed")
def test_analyze_uses_sealed_exec(mock_run, _exists):
    """The child must not inherit the operator environment."""
    mock_run.return_value = MagicMock(stdout="", returncode=0)
    SlitherTool(slither_path="/fake/slither").analyze("dao.sol")
    kwargs = mock_run.call_args.kwargs
    assert kwargs["home"] == Path.home()  # slither reads ~/.solc-select
    assert "capture_output" not in kwargs  # run_sealed applies it itself


@patch("cyberai.agents.web3.slither_tool.os.path.exists", return_value=True)
@patch("cyberai.agents.web3.slither_tool.run_sealed")
def test_analyze_timeout_returns_empty(mock_run, _exists):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="slither", timeout=1)
    assert SlitherTool(slither_path="/fake/slither").analyze("dao.sol") == []


@patch("cyberai.agents.web3.slither_tool.os.path.exists", return_value=True)
@patch("cyberai.agents.web3.slither_tool.run_sealed")
def test_analyze_execution_failure_returns_empty(mock_run, _exists):
    mock_run.side_effect = OSError("cannot execute")
    assert SlitherTool(slither_path="/fake/slither").analyze("dao.sol") == []

"""Coverage for halmos_tool execution paths and property_synth edge cases."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

from cyberai.agents.web3 import halmos_tool as ht
from cyberai.agents.web3.halmos_tool import HalmosTool, find_halmos, parse_halmos_json
from cyberai.agents.web3.property_synth import (
    PropertySynthesizer,
    _parse_llm_candidates,
    synthesize_properties,
)


def test_find_halmos_on_path(monkeypatch):
    monkeypatch.delenv("HALMOS_PATH", raising=False)
    with patch.object(ht.shutil, "which", return_value="/usr/bin/halmos"):
        assert find_halmos() == "/usr/bin/halmos"


def test_find_halmos_fallback(monkeypatch):
    monkeypatch.delenv("HALMOS_PATH", raising=False)
    with patch.object(ht.shutil, "which", return_value=None):
        with patch.object(ht.os.path, "exists", lambda p: p == ht._FALLBACK_PATHS[0]):
            assert find_halmos() == ht._FALLBACK_PATHS[0]


def test_parse_non_dict_results():
    assert parse_halmos_json('{"test_results": 123}') == []


def _write_report(cmd, payload):
    out = cmd[cmd.index("--json-output") + 1]
    with open(out, "w") as fh:
        fh.write(payload)


def test_analyze_happy_path(tmp_path):
    fake = tmp_path / "halmos"
    fake.write_text("#!/bin/sh\n")
    tool = HalmosTool(halmos_path=str(fake))
    assert tool.available is True
    report = json.dumps(
        {"test_results": {"A:A": [{"name": "check_x()", "exitcode": 1, "num_models": 1}]}}
    )
    with patch.object(
        ht.subprocess, "run", side_effect=lambda cmd, **k: _write_report(cmd, report)
    ):
        findings = tool.analyze("/proj", contract="A", loop=3)
    assert len(findings) == 1
    assert findings[0].test_name == "check_x()"


def test_analyze_timeout(tmp_path):
    fake = tmp_path / "halmos"
    fake.write_text("x")
    tool = HalmosTool(halmos_path=str(fake))
    with patch.object(ht.subprocess, "run", side_effect=ht.subprocess.TimeoutExpired("halmos", 1)):
        assert tool.analyze("/proj") == []


def test_analyze_generic_exception(tmp_path):
    fake = tmp_path / "halmos"
    fake.write_text("x")
    tool = HalmosTool(halmos_path=str(fake))
    with patch.object(ht.subprocess, "run", side_effect=RuntimeError("boom")):
        assert tool.analyze("/proj") == []


def test_analyze_report_missing(tmp_path):
    fake = tmp_path / "halmos"
    fake.write_text("x")
    tool = HalmosTool(halmos_path=str(fake))
    with patch.object(ht.subprocess, "run", return_value=MagicMock()):
        assert tool.analyze("/proj") == []


def test_analyze_report_read_error(tmp_path):
    fake = tmp_path / "halmos"
    fake.write_text("x")
    tool = HalmosTool(halmos_path=str(fake))

    def make_dir(cmd, **k):
        out = cmd[cmd.index("--json-output") + 1]
        os.mkdir(out)  # report path is a directory -> read_text raises OSError

    with patch.object(ht.subprocess, "run", side_effect=make_dir):
        assert tool.analyze("/proj") == []


def test_classify_generic_and_unnamed():
    abi = [
        {"type": "function", "name": "pause", "inputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "", "inputs": [], "stateMutability": "nonpayable"},
    ]
    cands = synthesize_properties(abi)
    # Unnamed function skipped; pause has no hint -> generic.
    assert len(cands) == 1
    assert cands[0].kind == "generic"


def test_synthesizer_render_method():
    abi = [{"type": "function", "name": "withdraw", "inputs": [], "stateMutability": "nonpayable"}]
    src = PropertySynthesizer().render(abi, "V")
    assert "check_reentrancy_withdraw" in src


def test_parse_llm_candidates_edge_cases():
    assert _parse_llm_candidates("") == []
    assert _parse_llm_candidates("   ") == []
    assert _parse_llm_candidates('{"not": "a list"}') == []
    # A list item missing "name" is skipped.
    assert _parse_llm_candidates('[{"kind": "x"}]') == []

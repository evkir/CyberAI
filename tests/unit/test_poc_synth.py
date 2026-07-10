"""Tests for the Foundry exploit-script synthesizer."""

from __future__ import annotations

from unittest.mock import MagicMock

from cyberai.agents.web3.poc_synth import (
    ExploitSynthesizer,
    plan_exploit,
    render_exploit,
)


def test_kind_inferred_from_check():
    assert plan_exploit({"check": "reentrancy-eth"}).kind == "reentrancy"
    assert plan_exploit({"check": "arbitrary-send-eth"}).kind == "fund-extraction"
    assert plan_exploit({"check": "unprotected-initializer"}).kind == "access-control"
    assert plan_exploit({"check": "solc-version"}).kind == "generic"


def test_plan_carries_target_fn():
    plan = plan_exploit({"check": "reentrancy-eth", "target_fn": "withdraw"})
    assert plan.target_fn == "withdraw"
    assert plan.name == "testExploit"


def test_render_has_exploit_entrypoint_and_profit_assert():
    plan = plan_exploit({"check": "reentrancy-eth", "target_fn": "withdraw"})
    src = render_exploit("Vault", plan)
    assert "contract VaultExploit is Test" in src
    assert "function testExploit() public" in src
    assert 'emit log_named_uint("profit_wei", profit);' in src
    assert "assertGt(attacker.balance, balBefore" in src
    assert "withdraw" in src


def test_synthesizer_deterministic_baseline():
    s = ExploitSynthesizer()  # no LLM
    out = s.synthesize({"check": "reentrancy-eth", "target_fn": "withdraw"}, "Vault")
    assert "function testExploit() public" in out


def test_llm_path_used_when_gated():
    llm = MagicMock()
    llm.call.return_value = "// custom exploit\ncontract X {}"
    s = ExploitSynthesizer(llm=llm, use_llm_synthesis=True)
    out = s.synthesize({"check": "reentrancy-eth"}, "Vault")
    assert out == "// custom exploit\ncontract X {}"
    llm.call.assert_called_once()


def test_llm_failure_falls_back_to_scaffold():
    llm = MagicMock()
    llm.call.side_effect = RuntimeError("model down")
    s = ExploitSynthesizer(llm=llm, use_llm_synthesis=True)
    out = s.synthesize({"check": "reentrancy-eth"}, "Vault")
    assert "function testExploit() public" in out  # scaffold preserved


def test_llm_empty_falls_back_to_scaffold():
    llm = MagicMock()
    llm.call.return_value = "   "
    s = ExploitSynthesizer(llm=llm, use_llm_synthesis=True)
    out = s.synthesize({"check": "reentrancy-eth"}, "Vault")
    assert "function testExploit() public" in out


def test_plan_to_dict():
    d = plan_exploit({"check": "reentrancy-eth", "target_fn": "withdraw"}).to_dict()
    assert d["name"] == "testExploit"
    assert d["kind"] == "reentrancy"
    assert d["target_fn"] == "withdraw"
    assert d["rationale"]

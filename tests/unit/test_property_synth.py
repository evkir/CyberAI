"""Tests for the halmos property-test synthesizer."""

from __future__ import annotations

import json

from cyberai.agents.web3.property_synth import (
    PropertyCandidate,
    PropertySynthesizer,
    render_harness,
    synthesize_properties,
)

_ABI = [
    {"type": "function", "name": "withdraw", "inputs": [], "stateMutability": "nonpayable"},
    {
        "type": "function",
        "name": "mint",
        "inputs": [{"name": "amount", "type": "uint256"}],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "transferOwnership",
        "inputs": [{"name": "newOwner", "type": "address"}],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "balanceOf",
        "inputs": [{"name": "a", "type": "address"}],
        "stateMutability": "view",
    },
    {"type": "constructor", "inputs": []},
]


def test_deterministic_classification():
    cands = synthesize_properties(_ABI, "Vault")
    kinds = {c.target_fn: c.kind for c in cands}
    assert kinds["withdraw"] == "reentrancy"
    assert kinds["mint"] == "overflow"
    # transferOwnership matches the access hint before the reentrancy "transfer".
    assert kinds["transferOwnership"] == "access-control"
    # view functions and non-function entries are skipped.
    assert "balanceOf" not in kinds
    assert len(cands) == 3


def test_payable_is_reentrancy():
    abi = [{"type": "function", "name": "buy", "inputs": [], "stateMutability": "payable"}]
    (c,) = synthesize_properties(abi)
    assert c.kind == "reentrancy"  # payable overrides the overflow "buy" hint


def test_check_names_and_rationale():
    cands = synthesize_properties(_ABI)
    names = {c.name for c in cands}
    assert "check_reentrancy_withdraw" in names
    assert "check_access_control_transferOwnership" in names
    assert all(c.rationale for c in cands)


def test_render_harness_structure():
    cands = synthesize_properties(_ABI, "Vault")
    src = render_harness("Vault", cands)
    assert "contract VaultSymTest is SymTest, Test {" in src
    assert "SPDX-License-Identifier" in src
    for c in cands:
        assert f"function {c.name}(" in src


def test_synthesizer_deterministic_default():
    synth = PropertySynthesizer()  # use_llm_synthesis defaults to False
    assert synth.use_llm_synthesis is False
    assert [c.to_dict() for c in synth.synthesize(_ABI)] == [
        c.to_dict() for c in synthesize_properties(_ABI)
    ]


def test_synthesizer_llm_augments_when_enabled():
    class FakeLLM:
        def call(self, prompt: str) -> str:
            return json.dumps(
                [{"name": "check_custom_invariant", "kind": "generic", "target_fn": "x"}]
            )

    synth = PropertySynthesizer(llm=FakeLLM(), use_llm_synthesis=True)
    cands = synth.synthesize(_ABI)
    names = {c.name for c in cands}
    assert "check_custom_invariant" in names  # LLM candidate appended
    assert "check_reentrancy_withdraw" in names  # baseline preserved


def test_synthesizer_llm_failure_falls_back():
    class BrokenLLM:
        def call(self, prompt: str) -> str:
            raise RuntimeError("model unavailable")

    synth = PropertySynthesizer(llm=BrokenLLM(), use_llm_synthesis=True)
    cands = synth.synthesize(_ABI)
    # Deterministic baseline survives an LLM failure.
    assert [c.to_dict() for c in cands] == [c.to_dict() for c in synthesize_properties(_ABI)]


def test_llm_garbage_output_ignored():
    class GarbageLLM:
        def call(self, prompt: str) -> str:
            return "not json at all"

    synth = PropertySynthesizer(llm=GarbageLLM(), use_llm_synthesis=True)
    cands = synth.synthesize(_ABI)
    assert [c.to_dict() for c in cands] == [c.to_dict() for c in synthesize_properties(_ABI)]

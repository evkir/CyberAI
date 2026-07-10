"""Exploit-script synthesizer: build a Foundry `testExploit` PoC from a finding.

Given a triaged finding, derive the exploit kind (reentrancy / access-control /
fund-extraction / generic) and render a Foundry test contract whose
`testExploit()` runs the attack and asserts profit. The profit assertion is the
confirmation signal consumed by the runner: a passing test means the exploit
paid off on the fork. A deterministic template is the always-on baseline; an
optional LLM path (gated, default off) can flesh out the attack body and always
falls back to the deterministic scaffold.

No blockchain tooling is imported: the output is Solidity source text handed to
`forge test`. The deterministic path is fully offline.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger("cyberai.web3.poc_synth")

# Finding-check substrings -> exploit kind (deterministic heuristics).
_REENTRANCY_HINTS = ("reentrancy",)
_ACCESS_HINTS = (
    "initializer",
    "unprotected-upgrade",
    "unprotected-initializer",
    "owner",
    "access",
    "suicidal",
    "selfdestruct",
    "delegatecall",
)
_EXTRACTION_HINTS = (
    "arbitrary-send",
    "arbitrary-transfer",
    "arbitrary-transfer-from",
    "eth-send",
    "unchecked-transfer",
)

_ATTACK_HINT = {
    "reentrancy": "re-enter the vulnerable function during its external call",
    "access-control": "invoke the privileged function from an unauthorized caller",
    "fund-extraction": "drive the contract to send funds to the attacker",
    "generic": "drive the target into a profitable unexpected state",
}


def _kind_for_check(check: str) -> str:
    """Map a finding's detector check to an exploit kind."""
    low = (check or "").lower()
    if any(h in low for h in _REENTRANCY_HINTS):
        return "reentrancy"
    if any(h in low for h in _EXTRACTION_HINTS):
        return "fund-extraction"
    if any(h in low for h in _ACCESS_HINTS):
        return "access-control"
    return "generic"


@dataclass
class ExploitPlan:
    """The intent of a synthesized on-chain PoC."""

    name: str  # test function name (matched by the runner, default testExploit)
    kind: str  # reentrancy | access-control | fund-extraction | generic
    target_fn: str  # the function the exploit exercises
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "target_fn": self.target_fn,
            "rationale": self.rationale,
        }


def plan_exploit(finding: Dict[str, Any], contract_name: str = "Target") -> ExploitPlan:
    """Derive an ExploitPlan from a triaged finding (deterministic)."""
    check = str(finding.get("check", "")) if isinstance(finding, dict) else ""
    kind = _kind_for_check(check)
    target_fn = ""
    if isinstance(finding, dict):
        target_fn = str(finding.get("target_fn") or finding.get("function") or "")
    return ExploitPlan(
        name="testExploit",
        kind=kind,
        target_fn=target_fn,
        rationale=_ATTACK_HINT[kind],
    )


_HEADER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
"""


def render_exploit(contract_name: str, plan: ExploitPlan) -> str:
    """Render a Foundry exploit PoC scaffold from an ExploitPlan.

    The scaffold sets up the attacker, leaves the attack body as a marked TODO,
    logs `profit_wei`, and asserts profit — the shape the runner confirms.
    """
    fn = plan.target_fn or "the vulnerable function"
    lines = [
        _HEADER,
        f"// Synthesized on-chain PoC for a {plan.kind} finding on {fn}.",
        "// Fill the attack body; the profit assertion confirms a real exploit.",
        f"contract {contract_name}Exploit is Test {{",
        "    address internal attacker = address(this);",
        "",
        "    function testExploit() public {",
        "        uint256 balBefore = attacker.balance;",
        f"        // {plan.rationale}",
        f"        // TODO: exploit {fn}",
        "        uint256 profit = attacker.balance - balBefore;",
        '        emit log_named_uint("profit_wei", profit);',
        '        assertGt(attacker.balance, balBefore, "no profit -> not confirmed");',
        "    }",
        "}",
    ]
    return "\n".join(lines)


class ExploitSynthesizer:
    """Synthesizes a Foundry exploit PoC from a finding.

    The deterministic scaffold is always available. When `use_llm_synthesis` is
    True and an LLM client is provided, the model may flesh out the attack body;
    the deterministic scaffold is always preserved as fallback.
    """

    def __init__(self, llm: Any = None, use_llm_synthesis: bool = False):
        self.llm = llm
        self.use_llm_synthesis = use_llm_synthesis

    def synthesize(self, finding: Dict[str, Any], contract_name: str = "Target") -> str:
        plan = plan_exploit(finding, contract_name)
        scaffold = render_exploit(contract_name, plan)
        if self.use_llm_synthesis and self.llm is not None:
            try:
                body = self._llm_script(finding, contract_name, plan)
                if body:
                    return body
            except Exception as exc:  # noqa: BLE001 — never hard-fail; keep scaffold
                logger.warning("LLM PoC synthesis failed; using scaffold: %s", exc)
        return scaffold

    def _llm_script(
        self, finding: Dict[str, Any], contract_name: str, plan: ExploitPlan
    ) -> Optional[str]:
        """Ask the model for a complete exploit contract (Solidity). Gated path."""
        prompt = (
            "Write a Foundry test contract with a `testExploit()` function that "
            "exploits the finding below and asserts attacker profit "
            '(emit log_named_uint("profit_wei", profit); assertGt on balance). '
            "Only output Solidity source.\n"
            f"Contract: {contract_name}\nKind: {plan.kind}\n"
            f"Finding: {json.dumps(finding)}"
        )
        raw = self.llm.call(prompt)
        raw = (raw or "").strip()
        return raw or None

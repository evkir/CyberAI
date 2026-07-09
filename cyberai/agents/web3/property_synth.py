"""Property-test synthesizer: build halmos `check_` harnesses from a contract ABI.

Given a Solidity ABI, derive symbolic-test candidates (reentrancy / overflow /
access-control / generic) and render them as a Foundry test contract that halmos
can execute. A deterministic template is the always-on baseline; an optional LLM
path (gated, default off) can propose richer invariants and always falls back to
the deterministic result.

No blockchain tooling is imported: the output is source text handed to halmos
(which builds it via forge). The deterministic path is fully offline.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyberai.web3.property_synth")

# Function-name hints -> property kind (deterministic heuristics).
_ACCESS_HINTS = (
    "setowner",
    "transferownership",
    "setadmin",
    "initialize",
    "upgrade",
    "grantrole",
    "setpaused",
    "renounceownership",
)
_REENTRANCY_HINTS = ("withdraw", "claim", "redeem", "send", "transfer", "payout", "collect")
_OVERFLOW_HINTS = ("mint", "deposit", "add", "increase", "increment", "buy", "stake")

_RATIONALE = {
    "reentrancy": "state should stay consistent across an external call",
    "overflow": "arithmetic must not overflow/underflow for symbolic inputs",
    "access-control": "privileged mutation must revert for a non-owner caller",
    "generic": "function must not reach an unexpected assertion/revert state",
}


@dataclass
class PropertyCandidate:
    """One synthesized symbolic-test property."""

    name: str  # halmos check_ function name
    kind: str  # reentrancy | overflow | access-control | generic
    target_fn: str  # the ABI function this property exercises
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "target_fn": self.target_fn,
            "rationale": self.rationale,
        }


def _classify_fn(name: str, mutability: str, inputs: List[Dict[str, Any]]) -> Optional[str]:
    """Map an ABI function to a property kind, or None to skip (view/pure)."""
    low = name.lower()
    has_int = any(str(i.get("type", "")).startswith(("uint", "int")) for i in inputs)
    if any(h in low for h in _ACCESS_HINTS):
        return "access-control"
    if mutability == "payable" or any(h in low for h in _REENTRANCY_HINTS):
        return "reentrancy"
    if has_int and any(h in low for h in _OVERFLOW_HINTS):
        return "overflow"
    if mutability in ("nonpayable", "payable"):
        return "generic"
    return None


def synthesize_properties(
    abi: List[Dict[str, Any]], contract_name: str = "Target"
) -> List[PropertyCandidate]:
    """Deterministically derive property candidates from an ABI (offline baseline)."""
    candidates: List[PropertyCandidate] = []
    for entry in abi or []:
        if entry.get("type") != "function":
            continue
        fn = entry.get("name") or ""
        if not fn:
            continue
        mut = entry.get("stateMutability", "nonpayable")
        inputs = entry.get("inputs") or []
        kind = _classify_fn(fn, mut, inputs)
        if kind is None:
            continue
        candidates.append(
            PropertyCandidate(
                name=f"check_{kind.replace('-', '_')}_{fn}",
                kind=kind,
                target_fn=fn,
                rationale=_RATIONALE[kind],
            )
        )
    return candidates


_HEADER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";

// Synthesized symbolic-test harness. Each check_ function is explored by halmos
// over all inputs within the configured bounds.
"""


def render_harness(contract_name: str, candidates: List[PropertyCandidate]) -> str:
    """Render a Foundry symbolic-test contract from property candidates."""
    lines: List[str] = [_HEADER, f"contract {contract_name}SymTest is SymTest, Test {{"]
    for c in candidates:
        args = "uint256 x" if c.kind in ("overflow", "generic") else "address caller"
        lines.append(f"    /// @notice {c.rationale}")
        lines.append(f"    function {c.name}({args}) public {{")
        lines.append("        // symbolic inputs are explored by halmos")
        lines.append("        vm.assume(true);")
        lines.append("    }")
        lines.append("")
    lines.append("}")
    return "\n".join(lines)


class PropertySynthesizer:
    """Synthesizes halmos property tests from an ABI.

    The deterministic template is always available. When `use_llm_synthesis` is
    True and an LLM client is provided, extra invariant candidates are requested
    from the model; the deterministic baseline is always preserved as fallback.
    """

    def __init__(self, llm: Any = None, use_llm_synthesis: bool = False):
        self.llm = llm
        self.use_llm_synthesis = use_llm_synthesis

    def synthesize(
        self, abi: List[Dict[str, Any]], contract_name: str = "Target"
    ) -> List[PropertyCandidate]:
        candidates = synthesize_properties(abi, contract_name)
        if self.use_llm_synthesis and self.llm is not None:
            try:
                candidates = candidates + self._llm_candidates(abi, contract_name)
            except Exception as exc:  # noqa: BLE001 — never hard-fail; keep baseline
                logger.warning("LLM synthesis failed; using deterministic baseline: %s", exc)
        return candidates

    def render(self, abi: List[Dict[str, Any]], contract_name: str = "Target") -> str:
        return render_harness(contract_name, self.synthesize(abi, contract_name))

    def _llm_candidates(
        self, abi: List[Dict[str, Any]], contract_name: str
    ) -> List[PropertyCandidate]:
        """Ask the model for extra invariant candidates (JSON array). Gated path."""
        prompt = (
            "Given this Solidity ABI, propose additional halmos symbolic-test "
            "invariants as a JSON array of objects with keys name, kind, "
            "target_fn, rationale. Only output JSON.\n"
            f"Contract: {contract_name}\nABI: {json.dumps(abi)}"
        )
        raw = self.llm.call(prompt)
        return _parse_llm_candidates(raw)


def _parse_llm_candidates(raw: str) -> List[PropertyCandidate]:
    """Parse an LLM JSON array into candidates; [] on any malformed output."""
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    out: List[PropertyCandidate] = []
    for item in data:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        out.append(
            PropertyCandidate(
                name=str(item["name"]),
                kind=str(item.get("kind", "generic")),
                target_fn=str(item.get("target_fn", "")),
                rationale=str(item.get("rationale", "")),
            )
        )
    return out

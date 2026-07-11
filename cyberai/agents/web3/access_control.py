"""Heuristic access-control detectors over the Solidity source model.

Flags three high-signal authorization weaknesses without any external tooling:

  * missing-auth            — an externally callable state mutation of privileged
                              (owner/admin/role) state with no access guard.
  * unprotected-initializer — an initializer reachable more than once / by anyone
                              (no `initializer` modifier, no owner check).
  * controlled-delegatecall — a delegatecall whose target is caller-influenced.

Findings are heuristic (regex over stripped source) and expose the same
`check` / `impact` / `confidence` surface as slither/aderyn findings so they flow
through `immunefi_severity.classify`. They are meant to corroborate, not replace,
the static analyzers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .access_graph import ContractModel, FunctionInfo, parse_contracts

# A modifier guards access if its name reads like an authorization check.
_AUTH_MODIFIER_RE = re.compile(r"^(only|auth|restricted|requires?auth|authorized)", re.IGNORECASE)
# Inline guards: require(msg.sender == owner), _checkOwner(), hasRole(...), etc.
_INLINE_GUARD_RE = re.compile(
    r"msg\.sender\s*==\s*(?:owner|_owner|admin|_admin|governance|governor)"
    r"|(?:owner|_owner|admin|_admin|governance|governor)\s*==\s*msg\.sender"
    r"|_check(?:owner|role)\b"
    r"|hasrole\s*\(",
    re.IGNORECASE,
)

# Function-name patterns for takeover-grade privileged operations -> Critical.
_OWNERSHIP_NAMES = (
    "setowner",
    "transferownership",
    "renounceownership",
    "setadmin",
    "addadmin",
    "setgovernance",
    "grantrole",
    "revokerole",
    "setrole",
    "upgradeto",
    "upgradetoandcall",
    "setimplementation",
)
# Lesser privileged operations -> High (griefing / config, no direct takeover).
_PRIVILEGED_NAMES = (
    "mint",
    "setfee",
    "setprice",
    "pause",
    "unpause",
    "setpaused",
    "sweep",
    "rescue",
    "withdrawall",
    "setbaseuri",
    "settreasury",
)
# Direct writes to authority state -> Critical regardless of function name.
_OWNER_WRITE_RE = re.compile(
    r"\b(?:owner|_owner|admin|_admin|governance|governor)\s*=(?!=)", re.IGNORECASE
)
_INIT_NAMES = ("initialize", "init", "__init", "setup", "reinitialize")
_DELEGATECALL_RE = re.compile(r"\.delegatecall\s*\(", re.IGNORECASE)


@dataclass
class AccessFinding:
    """An access-control weakness, shaped like a slither/aderyn finding."""

    check: str
    impact: str
    confidence: str
    description: str
    contract: str
    function: str
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "impact": self.impact,
            "confidence": self.confidence,
            "description": self.description,
            "contract": self.contract,
            "function": self.function,
            "source": "access-control",
        }


def _is_guarded(fn: FunctionInfo) -> bool:
    if any(_AUTH_MODIFIER_RE.match(mod) for mod in fn.modifiers):
        return True
    return bool(_INLINE_GUARD_RE.search(fn.body))


def _mutates(fn: FunctionInfo) -> bool:
    return fn.mutability not in ("view", "pure")


def _name_matches(name: str, patterns) -> bool:
    low = name.lower()
    return any(p in low for p in patterns)


def detect_missing_auth(model: ContractModel) -> List[AccessFinding]:
    findings: List[AccessFinding] = []
    for fn in model.functions:
        if not fn.is_externally_callable or not _mutates(fn):
            continue
        if _name_matches(fn.name, _INIT_NAMES):
            continue  # handled by the initializer detector
        if _is_guarded(fn):
            continue
        writes_owner = bool(_OWNER_WRITE_RE.search(fn.body))
        if writes_owner or _name_matches(fn.name, _OWNERSHIP_NAMES):
            impact, confidence = "High", "High"  # -> Critical
            why = "changes ownership/authority state"
        elif _name_matches(fn.name, _PRIVILEGED_NAMES):
            impact, confidence = "Medium", "High"  # -> High
            why = "privileged operation"
        else:
            continue
        findings.append(
            AccessFinding(
                check="missing-auth",
                impact=impact,
                confidence=confidence,
                description=(
                    f"{model.name}.{fn.name} is externally callable and {why} "
                    "without an access-control guard"
                ),
                contract=model.name,
                function=fn.name,
            )
        )
    return findings


def detect_unprotected_initializer(model: ContractModel) -> List[AccessFinding]:
    findings: List[AccessFinding] = []
    for fn in model.functions:
        if not fn.is_externally_callable or not _name_matches(fn.name, _INIT_NAMES):
            continue
        has_initializer_mod = any(
            m.lower() in ("initializer", "reinitializer") for m in fn.modifiers
        )
        if has_initializer_mod or _is_guarded(fn):
            continue
        findings.append(
            AccessFinding(
                check="unprotected-initializer",
                impact="High",
                confidence="High",
                description=(
                    f"{model.name}.{fn.name} initializes state without an "
                    "`initializer` guard or owner check and can be front-run/re-run"
                ),
                contract=model.name,
                function=fn.name,
            )
        )
    return findings


def detect_controlled_delegatecall(model: ContractModel) -> List[AccessFinding]:
    findings: List[AccessFinding] = []
    for fn in model.functions:
        if not _DELEGATECALL_RE.search(fn.body):
            continue
        findings.append(
            AccessFinding(
                check="controlled-delegatecall",
                impact="High",
                confidence="High",
                description=(
                    f"{model.name}.{fn.name} performs a delegatecall whose target "
                    "may be caller-influenced (code execution in this contract's context)"
                ),
                contract=model.name,
                function=fn.name,
            )
        )
    return findings


def analyze_source(source: str) -> List[AccessFinding]:
    """Run all access-control detectors over Solidity source."""
    findings: List[AccessFinding] = []
    for model in parse_contracts(source):
        findings.extend(detect_missing_auth(model))
        findings.extend(detect_unprotected_initializer(model))
        findings.extend(detect_controlled_delegatecall(model))
    return findings

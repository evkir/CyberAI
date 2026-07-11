"""Lightweight Solidity source model for access-control analysis.

A heuristic, dependency-free parser that extracts just enough structure to
reason about authorization: contracts, their functions (visibility, modifiers,
mutability, body), declared modifiers, and owner/role state variables. It is not
a full Solidity parser — it strips comments and scans with brace matching, which
is sufficient to flag unprotected privileged operations while staying offline
and CI-friendly. Findings from this layer are heuristic and meant to be
cross-checked against slither/aderyn, never treated as ground truth alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

# Visibility / mutability keywords that are NOT modifiers.
_NON_MODIFIER_KW = {
    "public",
    "external",
    "internal",
    "private",
    "view",
    "pure",
    "payable",
    "nonpayable",
    "virtual",
    "override",
    "returns",
}

# State-variable names that denote privileged authority.
_OWNER_VARS = ("owner", "_owner", "admin", "_admin", "governance", "governor")
_ROLE_HINTS = ("role", "roles", "hasrole", "_roles", "authorized", "operators")

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_CONTRACT_RE = re.compile(r"\b(?:contract|library|interface)\s+(\w+)")
_FUNCTION_RE = re.compile(r"\bfunction\s+(\w+)\s*\(")
_MODIFIER_DEF_RE = re.compile(r"\bmodifier\s+(\w+)")


def _strip_comments(src: str) -> str:
    return _COMMENT_RE.sub(" ", src)


def _match_paren(src: str, open_idx: int) -> int:
    """Index of the ')' matching the '(' at open_idx (or -1)."""
    depth = 0
    for i in range(open_idx, len(src)):
        c = src[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _match_brace(src: str, open_idx: int) -> int:
    """Index of the '}' matching the '{' at open_idx (or -1). Balanced nesting
    (e.g. `call{value: x}`) is handled by counting."""
    depth = 0
    for i in range(open_idx, len(src)):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


@dataclass
class FunctionInfo:
    name: str
    visibility: str
    modifiers: List[str] = field(default_factory=list)
    mutability: str = "nonpayable"
    body: str = ""

    @property
    def is_externally_callable(self) -> bool:
        return self.visibility in ("public", "external")


@dataclass
class ContractModel:
    name: str
    functions: List[FunctionInfo] = field(default_factory=list)
    modifiers_defined: List[str] = field(default_factory=list)
    owner_vars: List[str] = field(default_factory=list)
    has_role_state: bool = False


def _parse_signature(sig: str) -> tuple[str, str, List[str]]:
    """From the text between ')' and '{', extract visibility, mutability, modifiers."""
    visibility = "public"  # Solidity default for free functions; refined below
    mutability = "nonpayable"
    modifiers: List[str] = []
    # Drop the returns clause, then modifier/parenthesized args (e.g.
    # onlyRole(ADMIN)) so only the bare modifier name survives.
    sig = re.sub(r"\breturns\s*\([^)]*\)", " ", sig)
    sig = re.sub(r"\([^)]*\)", " ", sig)
    for tok in re.findall(r"\b(\w+)\b", sig):
        low = tok.lower()
        if low in ("public", "external", "internal", "private"):
            visibility = low
        elif low in ("view", "pure"):
            mutability = low
        elif low == "payable":
            mutability = "payable"
        elif low in _NON_MODIFIER_KW:
            continue
        else:
            modifiers.append(tok)
    return visibility, mutability, modifiers


def _parse_functions(body: str) -> List[FunctionInfo]:
    fns: List[FunctionInfo] = []
    for m in _FUNCTION_RE.finditer(body):
        paren = body.index("(", m.end() - 1)
        close = _match_paren(body, paren)
        if close < 0:
            continue
        brace = body.find("{", close)
        semi = body.find(";", close)
        # Abstract/interface function (declaration only) — no body.
        if brace < 0 or (0 <= semi < brace):
            sig = body[close + 1 : semi if semi >= 0 else close + 1]
            vis, mut, mods = _parse_signature(sig)
            fns.append(FunctionInfo(m.group(1), vis, mods, mut, ""))
            continue
        sig = body[close + 1 : brace]
        end = _match_brace(body, brace)
        fn_body = body[brace + 1 : end] if end > brace else ""
        vis, mut, mods = _parse_signature(sig)
        fns.append(FunctionInfo(m.group(1), vis, mods, mut, fn_body))
    return fns


def _extract_owner_vars(body: str) -> tuple[List[str], bool]:
    """Find owner-like state variables and whether role state is present."""
    owners: List[str] = []
    low = body.lower()
    for name in _OWNER_VARS:
        # `address ... owner` declaration or assignment.
        if re.search(rf"\baddress\b[^;{{]*\b{name}\b", low) or re.search(rf"\b{name}\s*=", low):
            owners.append(name)
    has_role = any(h in low for h in _ROLE_HINTS)
    return sorted(set(owners)), has_role


def parse_contracts(source: str) -> List[ContractModel]:
    """Parse Solidity source into a list of ContractModel (heuristic)."""
    src = _strip_comments(source)
    models: List[ContractModel] = []
    for m in _CONTRACT_RE.finditer(src):
        brace = src.find("{", m.end())
        if brace < 0:
            continue
        end = _match_brace(src, brace)
        body = src[brace + 1 : end] if end > brace else src[brace + 1 :]
        owners, has_role = _extract_owner_vars(body)
        models.append(
            ContractModel(
                name=m.group(1),
                functions=_parse_functions(body),
                modifiers_defined=_MODIFIER_DEF_RE.findall(body),
                owner_vars=owners,
                has_role_state=has_role,
            )
        )
    return models

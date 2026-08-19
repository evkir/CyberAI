"""
--scope flag handler with IP range validation.
Parses CIDR ranges and domain lists, builds ScopeConfig.
"""

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List
from urllib.parse import urlparse

from cyberai.core.safety import ScopeConfig

# Asset types from HackerOne/Bugcrowd that map to network-scannable targets.
# Non-network types (mobile app IDs, source repos, hardware, "other") are
# skipped — the pipeline can't scan an App Store ID.
SCANNABLE_ASSET_TYPES = {
    "URL",
    "WILDCARD",
    "CIDR",
    "IP_ADDRESS",
    "DOMAIN",
    "API",
    "WEBSITE",
}

# Bugcrowd target categories that map to network-scannable targets.
SCANNABLE_BC_CATEGORIES = {
    "website",
    "api",
    "url",
    "ip",
    "cidr",
    "wildcard",
}


def parse_scope(scope_str: str) -> ScopeConfig:
    """
    Parse --scope value into ScopeConfig.

    Accepts:
      - Single IP:      10.10.10.1
      - CIDR range:     10.10.10.0/24
      - Domain:         target.htb
      - Comma-separated mix: 10.10.10.1,target.htb,192.168.1.0/24
    """
    if not scope_str:
        return ScopeConfig(authorized=False)

    entries = [e.strip() for e in scope_str.split(",") if e.strip()]
    ips: List[str] = []
    domains: List[str] = []

    for entry in entries:
        if _is_ip_or_cidr(entry):
            ips.append(entry)
        elif _is_domain(entry):
            domains.append(entry)
        else:
            raise ValueError(f"Invalid scope entry: '{entry}'")

    return ScopeConfig(
        allowed_ips=ips,
        allowed_domains=domains,
        authorized=True,
    )


def validate_scope_entry(entry: str) -> bool:
    """Returns True if entry is a valid IP, CIDR, or domain."""
    return _is_ip_or_cidr(entry) or _is_domain(entry)


def _is_ip_or_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_domain(value: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


@dataclass
class ScopeImport:
    """Result of importing a bug-bounty program scope file."""

    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{len(self.in_scope)} in-scope, "
            f"{len(self.out_of_scope)} out-of-scope, "
            f"{len(self.skipped)} skipped (non-network)"
        )


def _normalize_asset(identifier: str, asset_type: str) -> str:
    """Reduce an asset identifier to a host/wildcard/CIDR token.

    URL assets become bare hosts (`https://api.x.com/v1` -> `api.x.com`).
    WILDCARD/CIDR/IP pass through unchanged. Ports and paths are stripped.
    """
    ident = identifier.strip()
    atype = asset_type.upper()
    if atype in {"WILDCARD", "CIDR", "IP_ADDRESS"}:
        return ident
    # URL/DOMAIN/API/WEBSITE -> strip scheme, path, port.
    if "://" in ident:
        ident = urlparse(ident).netloc or urlparse(ident).path
    ident = ident.split("/")[0].split(":")[0]
    return ident.strip().lower()


def import_h1_scope(path: str) -> ScopeImport:
    """Parse a HackerOne structured-scopes JSON export into a ScopeImport.

    Accepts either the raw JSON:API envelope ({"data": [...]}) or a bare
    list of structured-scope objects. Each item carries an `attributes`
    block with `asset_identifier`, `asset_type`, `eligible_for_submission`.
    Only eligible, network-scannable assets land in `in_scope`; ineligible
    ones go to `out_of_scope`; non-network types are `skipped`.
    """
    raw = json.loads(Path(path).read_text())
    items: List[Any] = raw["data"] if isinstance(raw, dict) and "data" in raw else raw
    result = ScopeImport()
    for item in items:
        attrs = item.get("attributes", item) if isinstance(item, dict) else {}
        ident = attrs.get("asset_identifier", "")
        atype = (attrs.get("asset_type") or "").upper()
        if not ident:
            continue
        if atype not in SCANNABLE_ASSET_TYPES:
            result.skipped.append(f"{ident} ({atype or 'UNKNOWN'})")
            continue
        token = _normalize_asset(ident, atype)
        if not token:
            result.skipped.append(f"{ident} ({atype})")
            continue
        if attrs.get("eligible_for_submission", True):
            result.in_scope.append(token)
        else:
            result.out_of_scope.append(token)
    return result


def _bc_iter_targets(raw: Any) -> List[dict]:
    """Yield flat target dicts from any of the common Bugcrowd JSON shapes.

    Handles three real-world shapes:
      1. API export: {"data":[{"attributes":{"target_groups":[{"targets":[...]}]}}]}
         or {"target_groups":[{"targets":[...], "in_scope":bool}]}
      2. bounty-targets-data flat list: [{"name"/"target", "type", "in_scope"}]
      3. rescope/bbscope: {"in_scope":[...], "out_of_scope":[...]}
    """
    targets: List[dict] = []

    # Shape 3: explicit in/out lists of strings.
    if isinstance(raw, dict) and ("in_scope" in raw or "out_of_scope" in raw):
        for name in raw.get("in_scope", []):
            targets.append({"name": name, "in_scope": True, "category": "website"})
        for name in raw.get("out_of_scope", []):
            targets.append({"name": name, "in_scope": False, "category": "website"})
        return targets

    # Shape 1: target_groups (possibly under data[].attributes).
    groups = None
    if isinstance(raw, dict):
        if "target_groups" in raw:
            groups = raw["target_groups"]
        elif "data" in raw and isinstance(raw["data"], list):
            groups = []
            for prog in raw["data"]:
                attrs = prog.get("attributes", prog) if isinstance(prog, dict) else {}
                groups.extend(attrs.get("target_groups", []))
    if groups:
        for grp in groups:
            grp_in = grp.get("in_scope", True)
            for t in grp.get("targets", []):
                t = dict(t)
                t.setdefault("in_scope", grp_in)
                targets.append(t)
        return targets

    # Shape 2: flat list.
    if isinstance(raw, list):
        return [t for t in raw if isinstance(t, dict)]
    return targets


def import_bugcrowd_scope(path: str) -> ScopeImport:
    """Parse a Bugcrowd scope export into a ScopeImport.

    Tolerant of several JSON shapes (see `_bc_iter_targets`). A target's
    `category` decides scannability; `in_scope` (default True) splits the
    eligible targets from explicitly out-of-scope ones.
    """
    raw = json.loads(Path(path).read_text())
    result = ScopeImport()
    for t in _bc_iter_targets(raw):
        name = (t.get("name") or t.get("target") or t.get("uri") or "").strip()
        if not name:
            continue
        category = (t.get("category") or t.get("type") or "website").lower()
        if category not in SCANNABLE_BC_CATEGORIES:
            result.skipped.append(f"{name} ({category})")
            continue
        atype = "WILDCARD" if name.startswith("*") else "URL"
        token = _normalize_asset(name, atype)
        if not token:
            result.skipped.append(f"{name} ({category})")
            continue
        if t.get("in_scope", True):
            result.in_scope.append(token)
        else:
            result.out_of_scope.append(token)
    return result

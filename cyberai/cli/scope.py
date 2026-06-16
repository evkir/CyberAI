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


def format_scope(scope: ScopeConfig) -> str:
    """Human-readable scope summary for CLI output."""
    parts = scope.allowed_ips + scope.allowed_domains
    if not parts:
        return "no scope defined"
    return ", ".join(parts)


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

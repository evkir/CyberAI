"""
--scope flag handler with IP range validation.
Parses CIDR ranges and domain lists, builds ScopeConfig.
"""
import ipaddress
import re
from typing import List
from cyberai.core.safety import ScopeConfig


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

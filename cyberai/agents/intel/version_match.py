"""Version-range matching of NVD CPE constraints against detected services.

Given the concrete product/version nmap -sV captured and the CPE rules parsed
from a CVE's NVD ``configurations``, decide whether the CVE actually applies to
the running version — instead of matching on product keyword alone, which
surfaces decades-old CVEs against modern builds (e.g. CVE-2000-0525 pinned to
OpenSSH 2.1 showing up for OpenSSH 9.6).

Dependency-free to preserve the air-gapped invariant: no packaging/semver
libraries, just a tolerant leading-numeric parse and tuple comparison.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

_NUM_RE = re.compile(r"(\d+(?:\.\d+)*)")


def _vtuple(value: Optional[str]) -> Optional[tuple]:
    """Leading dotted-numeric of a version string as an int tuple.

    Tolerates nmap's noisy strings ("9.6p1 Ubuntu 3ubuntu13.16" -> (9, 6)) and
    treats wildcards / empties / non-numeric as "no usable version" (None).
    """
    if not value:
        return None
    m = _NUM_RE.match(value.strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _product_matches(rule: Dict, tokens: set) -> bool:
    """True if the rule's CPE vendor or product shares a token (>=3 chars) with
    what was detected, so openssh CVEs are checked only against openssh and
    apache CVEs (CPE product ``http_server``, vendor ``apache``) against apache.
    """
    for field in (rule.get("vendor", ""), rule.get("product", "")):
        for sub in re.split(r"[^a-z0-9]+", field.lower()):
            if len(sub) >= 3 and sub in tokens:
                return True
    return False


def _rule_applies(detected: tuple, rule: Dict) -> bool:
    """Whether a detected version satisfies one CPE rule's version constraint."""
    vsi = _vtuple(rule.get("version_start_including"))
    vse = _vtuple(rule.get("version_start_excluding"))
    vei = _vtuple(rule.get("version_end_including"))
    vee = _vtuple(rule.get("version_end_excluding"))
    if any(b is not None for b in (vsi, vse, vei, vee)):
        if vsi is not None and detected < vsi:
            return False
        if vse is not None and detected <= vse:
            return False
        if vei is not None and detected > vei:
            return False
        if vee is not None and detected >= vee:
            return False
        return True
    # No range fields: exact pin, or wildcard meaning the whole product is
    # vulnerable. A pin matches when it is a prefix of the detected version
    # (CPE 2.4 covers a detected 2.4.7).
    pin = _vtuple(rule.get("version"))
    if pin is None:  # version == "*" with no bounds -> all versions vulnerable
        return True
    return detected[: len(pin)] == pin


def version_applies(detected_version: str, cpe_rules: List[Dict], tokens: set) -> Optional[bool]:
    """Tri-state applicability of a CVE to a detected service version.

    Returns:
        True  - a product-matching CPE rule covers the detected version
        False - product-matching rule(s) exist but none cover the version
        None  - no usable detected version, or the CVE constrains only other
                products (cannot be version-confirmed; the caller falls back to
                conservative handling rather than asserting the CVE applies)
    """
    detected = _vtuple(detected_version)
    if detected is None:
        return None
    relevant = [r for r in cpe_rules if _product_matches(r, tokens)]
    if not relevant:
        return None
    return any(_rule_applies(detected, r) for r in relevant)

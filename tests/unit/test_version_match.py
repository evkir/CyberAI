"""Version-range CVE applicability against detected service versions."""

from __future__ import annotations

import pytest

from cyberai.agents.intel.nvd_client import _parse_cves
from cyberai.agents.intel.version_match import _vtuple, version_applies

# -- _vtuple: tolerant leading-numeric parse --


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("9.6p1 Ubuntu 3ubuntu13.16", (9, 6)),
        ("2.4.7", (2, 4, 7)),
        ("0.7.62", (0, 7, 62)),
        ("2.1", (2, 1)),
        ("*", None),
        ("", None),
        (None, None),
        ("Nping echo", None),
    ],
)
def test_vtuple_parses_noisy_versions(raw, expected):
    assert _vtuple(raw) == expected


# -- exact pins (no range fields) --


def _pin(product, version, vendor=""):
    return {
        "vendor": vendor,
        "product": product,
        "version": version,
        "version_start_including": None,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": None,
    }


def _range(product, vsi=None, vse=None, vei=None, vee=None, vendor=""):
    return {
        "vendor": vendor,
        "product": product,
        "version": "*",
        "version_start_including": vsi,
        "version_start_excluding": vse,
        "version_end_including": vei,
        "version_end_excluding": vee,
    }


def test_out_of_range_exact_pins_dropped():
    """OpenSSH 9.6 must NOT match a CVE pinned to 1.2 / 2.1 (the real FP)."""
    rules = [_pin("openssh", "1.2"), _pin("openssh", "2.1")]
    assert version_applies("9.6p1 Ubuntu 3ubuntu13.16", rules, {"openssh"}) is False


def test_exact_pin_prefix_match_applies():
    """A pin of 2.4 covers a detected 2.4.7 (prefix semantics)."""
    rules = [_pin("http_server", "2.4", vendor="apache")]
    assert version_applies("2.4.7", rules, {"apache", "httpd"}) is True


def test_exact_pin_equal_applies():
    rules = [_pin("openssh", "9.6")]
    assert version_applies("9.6p1 Ubuntu", rules, {"openssh"}) is True


# -- version ranges --


def test_in_range_applies():
    rules = [_range("nginx", vsi="0.7.0", vee="0.7.62")]
    assert version_applies("0.7.30", rules, {"nginx"}) is True


def test_out_of_range_above_dropped():
    """Modern nginx is not in the < 0.8.15 vulnerable range."""
    rules = [_range("nginx", vsi="0.7.0", vee="0.7.62")]
    assert version_applies("1.25.3", rules, {"nginx"}) is False


def test_end_excluding_boundary_is_exclusive():
    rules = [_range("nginx", vee="0.7.62")]
    assert version_applies("0.7.62", rules, {"nginx"}) is False
    assert version_applies("0.7.61", rules, {"nginx"}) is True


def test_start_including_boundary_is_inclusive():
    rules = [_range("nginx", vsi="1.0.0")]
    assert version_applies("1.0.0", rules, {"nginx"}) is True
    assert version_applies("0.9.9", rules, {"nginx"}) is False


def test_start_excluding_boundary_is_exclusive():
    rules = [_range("nginx", vse="1.0.0")]
    assert version_applies("1.0.0", rules, {"nginx"}) is False
    assert version_applies("1.0.1", rules, {"nginx"}) is True


def test_end_including_boundary_is_inclusive():
    rules = [_range("nginx", vei="1.2.0")]
    assert version_applies("1.2.0", rules, {"nginx"}) is True
    assert version_applies("1.2.1", rules, {"nginx"}) is False


# -- wildcard: whole product vulnerable --


def test_wildcard_no_bounds_applies_any_version():
    rules = [_pin("nginx", "*")]
    assert version_applies("1.25.3", rules, {"nginx"}) is True


# -- product filtering / tri-state None --


def test_no_product_matching_rule_returns_none():
    """A CVE whose only rules constrain other products cannot be version-judged
    for our service -> None (caller decides conservatively)."""
    rules = [_pin("debian_linux", "5.0", vendor="debian")]
    assert version_applies("9.6p1", rules, {"openssh"}) is None


def test_unparseable_detected_version_returns_none():
    rules = [_range("nginx", vee="0.8.15")]
    assert version_applies("Nping echo", rules, {"nginx"}) is None


def test_product_match_via_vendor_token():
    """Apache's CPE product is 'http_server'; the match comes off the vendor
    'apache' token, not the product string."""
    rules = [_range("http_server", vee="2.4.50", vendor="apache")]
    assert version_applies("2.4.7", rules, {"apache", "httpd"}) is True


def test_empty_rules_returns_none():
    assert version_applies("2.4.7", [], {"apache"}) is None


# -- end-to-end from parsed NVD shape --


def test_parsed_openssh_pins_reject_modern_version():
    """Full path: parse real NVD pin shape, then reject OpenSSH 9.6."""
    vuln = {
        "cve": {
            "id": "CVE-2000-0525",
            "descriptions": [{"lang": "en", "value": "OpenSSH before 2.1"}],
            "metrics": {},
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:openbsd:openssh:2.1:*:*:*:*:*:*:*",
                                }
                            ]
                        }
                    ]
                }
            ],
        }
    }
    rules = _parse_cves([vuln])[0]["cpe"]
    assert rules[0]["vendor"] == "openbsd"
    assert version_applies("9.6p1 Ubuntu", rules, {"openssh"}) is False


# -- classify_cve: per-port verdict against detected versions --

from cyberai.agents.intel.version_match import classify_cve  # noqa: E402


def _cve(rules):
    return {"id": "CVE-X", "cpe": rules}


def test_classify_confirmed_when_version_in_range():
    ports = [{"port": 80, "service": "http", "product": "nginx", "version": "1.24.0"}]
    cve = _cve([_range("nginx", vsi="1.20.0", vee="1.26.0")])
    assert classify_cve(cve, ports) == "confirmed"


def test_classify_out_of_range_when_version_excluded():
    ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1"}]
    cve = _cve([_pin("openssh", "2.1")])
    assert classify_cve(cve, ports) == "out_of_range"


def test_classify_unconfirmed_when_no_cpe_rules():
    ports = [{"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.7"}]
    assert classify_cve(_cve([]), ports) == "unconfirmed"


def test_classify_unconfirmed_when_product_has_empty_version():
    """The nginx empty-version hole: product detected but -sV captured no
    version -> cannot version-confirm -> unconfirmed (surfaces as INFO)."""
    ports = [{"port": 443, "service": "http", "product": "nginx", "version": ""}]
    cve = _cve([_range("nginx", vee="0.8.15")])
    assert classify_cve(cve, ports) == "unconfirmed"


def test_classify_skips_ports_without_product():
    """A port with no product (degraded) is skipped; if nothing else confirms,
    the CVE is unconfirmed rather than crashing."""
    ports = [{"port": 80, "service": "http"}]
    cve = _cve([_range("nginx", vee="0.8.15")])
    assert classify_cve(cve, ports) == "unconfirmed"


def test_classify_confirmed_takes_priority_over_out_of_range():
    """One in-range service confirms even if another service is out of range."""
    ports = [
        {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1"},
        {"port": 80, "service": "http", "product": "nginx", "version": "1.24.0"},
    ]
    cve = _cve([_pin("openssh", "2.1"), _range("nginx", vsi="1.20.0", vee="1.26.0")])
    assert classify_cve(cve, ports) == "confirmed"

"""Scope import + wildcard/exclusion matching edge cases."""

import json

from cyberai.agents.exploit.safety_validator import (
    _matches_entry,
    _split_scope,
    _target_in_scope,
)
from cyberai.cli.scope import import_bugcrowd_scope, import_h1_scope


# ── _matches_entry ─────────────────────────────────────────────────────
def test_matches_exact():
    assert _matches_entry("api.acme.com", "api.acme.com")
    assert not _matches_entry("api.acme.com", "web.acme.com")


def test_matches_wildcard_subdomain():
    assert _matches_entry("api.acme.com", "*.acme.com")
    assert _matches_entry("deep.nested.acme.com", "*.acme.com")


def test_wildcard_does_not_match_apex():
    assert not _matches_entry("acme.com", "*.acme.com")


def test_matches_cidr():
    assert _matches_entry("10.0.0.5", "10.0.0.0/24")
    assert not _matches_entry("10.0.1.5", "10.0.0.0/24")


def test_matches_entry_hostname_vs_cidr_no_crash():
    # hostname target against CIDR entry must not raise
    assert not _matches_entry("api.acme.com", "10.0.0.0/24")


# ── _split_scope ───────────────────────────────────────────────────────
def test_split_scope_separates_exclusions():
    allow, exclude = _split_scope(["*.acme.com", "!staging.acme.com", "10.0.0.0/24"])
    assert allow == ["*.acme.com", "10.0.0.0/24"]
    assert exclude == ["staging.acme.com"]


def test_split_scope_strips_marker_whitespace():
    allow, exclude = _split_scope(["! staging.acme.com "])
    assert exclude == ["staging.acme.com"]
    assert allow == []


# ── _target_in_scope with exclusions ───────────────────────────────────
def test_api_in_wildcard_scope():
    assert _target_in_scope("api.acme.com", ["*.acme.com"])


def test_exclusion_beats_wildcard():
    scope = ["*.acme.com", "!staging.acme.com"]
    assert _target_in_scope("api.acme.com", scope)
    assert not _target_in_scope("staging.acme.com", scope)


def test_nested_excluded_subdomain():
    # internal.staging.acme.com excluded via !*.staging.acme.com
    scope = ["*.acme.com", "!*.staging.acme.com"]
    assert not _target_in_scope("internal.staging.acme.com", scope)
    assert _target_in_scope("api.acme.com", scope)


def test_exclusion_cidr():
    scope = ["10.0.0.0/16", "!10.0.5.0/24"]
    assert _target_in_scope("10.0.1.1", scope)
    assert not _target_in_scope("10.0.5.7", scope)


def test_no_allow_only_exclusion_is_out():
    assert not _target_in_scope("anything.com", ["!evil.com"])


def test_empty_scope_is_out():
    assert not _target_in_scope("api.acme.com", [])


# ── H1 import ──────────────────────────────────────────────────────────
def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return str(p)


def test_h1_import_envelope(tmp_path):
    data = {
        "data": [
            {
                "attributes": {
                    "asset_identifier": "https://api.acme.com/v1",
                    "asset_type": "URL",
                    "eligible_for_submission": True,
                }
            },
            {
                "attributes": {
                    "asset_identifier": "*.acme.com",
                    "asset_type": "WILDCARD",
                    "eligible_for_submission": True,
                }
            },
            {
                "attributes": {
                    "asset_identifier": "com.acme.app",
                    "asset_type": "GOOGLE_PLAY_APP_ID",
                    "eligible_for_submission": True,
                }
            },
            {
                "attributes": {
                    "asset_identifier": "old.acme.com",
                    "asset_type": "URL",
                    "eligible_for_submission": False,
                }
            },
        ]
    }
    res = import_h1_scope(_write(tmp_path, "h1.json", data))
    assert "api.acme.com" in res.in_scope  # URL normalized (scheme/path stripped)
    assert "*.acme.com" in res.in_scope  # wildcard passthrough
    assert "old.acme.com" in res.out_of_scope  # ineligible
    assert any("GOOGLE_PLAY" in s for s in res.skipped)  # non-network skipped


def test_h1_import_bare_list(tmp_path):
    data = [
        {"attributes": {"asset_identifier": "x.acme.com", "asset_type": "URL"}},
    ]
    res = import_h1_scope(_write(tmp_path, "h1b.json", data))
    assert res.in_scope == ["x.acme.com"]  # eligible defaults True


# ── Bugcrowd import ────────────────────────────────────────────────────
def test_bugcrowd_target_groups(tmp_path):
    data = {
        "target_groups": [
            {
                "in_scope": True,
                "targets": [
                    {"name": "*.acme.com", "category": "website"},
                    {"name": "https://api.acme.com", "category": "api"},
                    {"name": "Acme Android", "category": "android"},
                ],
            },
            {
                "in_scope": False,
                "targets": [{"name": "legacy.acme.com", "category": "website"}],
            },
        ]
    }
    res = import_bugcrowd_scope(_write(tmp_path, "bc.json", data))
    assert "*.acme.com" in res.in_scope
    assert "api.acme.com" in res.in_scope
    assert "legacy.acme.com" in res.out_of_scope
    assert any("android" in s for s in res.skipped)


def test_bugcrowd_in_out_lists(tmp_path):
    data = {"in_scope": ["a.acme.com"], "out_of_scope": ["b.acme.com"]}
    res = import_bugcrowd_scope(_write(tmp_path, "bc2.json", data))
    assert res.in_scope == ["a.acme.com"]
    assert res.out_of_scope == ["b.acme.com"]


def test_bugcrowd_flat_list(tmp_path):
    data = [
        {"name": "c.acme.com", "type": "website", "in_scope": True},
        {"name": "d.acme.com", "type": "website", "in_scope": False},
    ]
    res = import_bugcrowd_scope(_write(tmp_path, "bc3.json", data))
    assert "c.acme.com" in res.in_scope
    assert "d.acme.com" in res.out_of_scope


def test_scope_import_summary():
    from cyberai.cli.scope import ScopeImport

    si = ScopeImport(in_scope=["a"], out_of_scope=["b", "c"], skipped=["d"])
    summary = si.summary()
    assert "1 in-scope" in summary
    assert "2 out-of-scope" in summary

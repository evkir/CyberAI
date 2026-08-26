"""Tests for the benchmark regression gate."""

from __future__ import annotations

import json

from cyberai.bench.regression_gate import (
    check_regression,
    load_baseline,
)
from cyberai.bench.run_manifest import RunConfig, RunManifest


def _manifest(solved: int, total: int = 10, suite_hash: str = "AAA") -> RunManifest:
    return RunManifest(
        suite="local",
        engine_version="1.1.0",
        config=RunConfig(),
        suite_hash=suite_hash,
        solved=solved,
        total=total,
        timestamp="2026-01-01T00:00:00Z",
        manifest_hash="h",
    )


def test_no_baseline_passes():
    r = check_regression(_manifest(3), baseline=None)
    assert r.passed is True
    assert "establishes" in r.reason


def test_equal_rate_passes():
    r = check_regression(_manifest(5), _manifest(5))
    assert r.passed is True


def test_improved_rate_passes():
    r = check_regression(_manifest(7), _manifest(5))
    assert r.passed is True
    assert r.current_rate > r.baseline_rate


def test_regression_fails():
    r = check_regression(_manifest(3), _manifest(5))
    assert r.passed is False
    assert "regressed" in r.reason


def test_tolerance_allows_small_drop():
    # baseline 5/10=0.5, current 4/10=0.4, tolerance 0.1 -> 0.4+0.1 >= 0.5 -> pass
    r = check_regression(_manifest(4), _manifest(5), tolerance=0.1)
    assert r.passed is True


def test_suite_change_fails_unless_allowed():
    blocked = check_regression(_manifest(5, suite_hash="BBB"), _manifest(5, suite_hash="AAA"))
    assert blocked.passed is False
    assert blocked.suite_changed is True

    allowed = check_regression(
        _manifest(5, suite_hash="BBB"), _manifest(5, suite_hash="AAA"), allow_suite_change=True
    )
    assert allowed.passed is True


def test_load_baseline_missing_returns_none(tmp_path):
    assert load_baseline(tmp_path / "nope.json") is None


def test_load_baseline_roundtrip(tmp_path):
    m = _manifest(6)
    p = tmp_path / "baseline.json"
    p.write_text(m.to_json())
    loaded = load_baseline(p)
    assert loaded is not None
    assert loaded.solved == 6
    assert loaded.suite_hash == "AAA"


def test_a_baseline_written_by_an_older_release_still_loads(tmp_path):
    """Manifests on disk outlive the code that wrote them.

    Releases up to 1.5.0 stamped placeholder strings and zeroes into the run
    config. Those files are the baselines a regression gate compares against,
    and load_baseline expands whatever config it finds straight into the
    dataclass. A field that stopped accepting the old shape would not raise
    here -- it would return None, the gate would read that as "no baseline",
    and a run that regressed to zero would pass green.
    """
    legacy = {
        "suite": "local",
        "engine_version": "1.5.0",
        "config": {
            "model": "unspecified",
            "provider": "unspecified",
            "temperature": 0.0,
            "seed": 1337,
            "max_iterations": 0,
            "extra": {"engine": "real"},
        },
        "suite_hash": "AAA",
        "solved": 4,
        "total": 4,
        "timestamp": "2026-08-17T19:18:36Z",
        "manifest_hash": "old",
    }
    p = tmp_path / "legacy.json"
    p.write_text(json.dumps(legacy))

    loaded = load_baseline(p)
    assert loaded is not None, "an older baseline must not degrade to 'no baseline'"
    assert loaded.config.model == "unspecified"
    assert loaded.config.temperature == 0.0
    assert check_regression(_manifest(0), loaded).passed is False

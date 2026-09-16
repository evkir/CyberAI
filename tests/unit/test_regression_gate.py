"""Tests for the benchmark regression gate."""

from __future__ import annotations

import json

from cyberai.bench.regression_gate import (
    check_regression,
    load_baseline,
)
from cyberai.bench.run_manifest import RunConfig, RunManifest, ToolVersion


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


def test_a_baseline_from_a_newer_writer_still_gates(tmp_path):
    """An unknown knob must not read as 'no baseline'.

    RunConfig(**cfg) raises TypeError on a keyword this release does not
    know, and answering None would report no baseline -- which passes. An
    upgrade would switch the gate off without saying so.
    """
    doc = {
        "suite": "local",
        "engine_version": "9.9.9",
        "config": {"seed": 1337, "future_knob": "written by a newer cyberai"},
        "suite_hash": "AAA",
        "solved": 10,
        "total": 10,
        "timestamp": "2026-09-15T00:00:00Z",
        "manifest_hash": "new",
    }
    p = tmp_path / "newer.json"
    p.write_text(json.dumps(doc))

    loaded = load_baseline(p)
    assert loaded is not None
    assert loaded.config.seed == 1337
    assert not hasattr(loaded.config, "future_knob")
    assert check_regression(_manifest(0), loaded).passed is False


def test_the_toolchain_survives_the_round_trip(tmp_path):
    """Versions written into a manifest have to come back out of it.

    Day 48 recorded the toolchain and read nothing back: the field took its
    default on load, so a run on one nuclei compared against a baseline on
    another passed in silence. A producer without a consumer is the disease
    this sprint treats.
    """
    m = RunManifest(
        suite="local",
        engine_version="1.1.0",
        config=RunConfig(),
        suite_hash="AAA",
        solved=5,
        total=10,
        timestamp="2026-01-01T00:00:00Z",
        manifest_hash="h",
        environment=(
            ToolVersion("nmap", "/usr/bin/nmap", "7.95", ""),
            ToolVersion("mst", None, None, "version flag not measured"),
        ),
    )
    p = tmp_path / "baseline.json"
    p.write_text(m.to_json())

    loaded = load_baseline(p)
    assert loaded is not None
    assert loaded.environment == m.environment
    assert isinstance(loaded.environment, tuple)
    assert loaded.environment[1].path is None


def test_a_baseline_without_a_toolchain_is_unmeasured_not_empty(tmp_path):
    """Every baseline on disk older than day 48 has no environment key.

    It must load as the same empty tuple a run that never probed produces:
    the gate treats that as "nothing to compare", and a file that failed to
    load would report "no baseline", which passes.
    """
    legacy = {
        "suite": "local",
        "engine_version": "1.5.0",
        "config": {"seed": 1337},
        "suite_hash": "AAA",
        "solved": 4,
        "total": 4,
        "timestamp": "2026-08-17T19:18:36Z",
        "manifest_hash": "old",
    }
    p = tmp_path / "legacy.json"
    p.write_text(json.dumps(legacy))

    loaded = load_baseline(p)
    assert loaded is not None
    assert loaded.environment == ()
    assert check_regression(_manifest(0), loaded).passed is False


def test_a_toolchain_from_a_newer_writer_loads_without_its_extra_keys(tmp_path):
    """A later release may record more about a tool than this one reads.

    Refusing the document would answer None, and None reads as "no baseline",
    which passes -- the same trap the config filter above avoids. An entry
    with no name is dropped instead: a version with no tool compares against
    nothing.
    """
    doc = {
        "suite": "local",
        "engine_version": "9.9.9",
        "config": {"seed": 1337},
        "suite_hash": "AAA",
        "solved": 10,
        "total": 10,
        "timestamp": "2026-09-16T00:00:00Z",
        "manifest_hash": "new",
        "environment": [
            {
                "name": "nuclei",
                "path": "/usr/bin/nuclei",
                "version": "3.8.1",
                "detail": "",
                "sha256": "written by a newer cyberai",
            },
            {"path": "/usr/bin/ghost", "version": "1.0", "detail": ""},
        ],
    }
    p = tmp_path / "newer.json"
    p.write_text(json.dumps(doc))

    loaded = load_baseline(p)
    assert loaded is not None
    assert len(loaded.environment) == 1
    assert loaded.environment[0].name == "nuclei"
    assert loaded.environment[0].version == "3.8.1"
    assert not hasattr(loaded.environment[0], "sha256")


def test_an_incomplete_toolchain_entry_does_not_escape_as_an_exception(tmp_path):
    """load_baseline answers None on a document it cannot read.

    It promises that by catching the parse, not by trusting the shape: the
    try covers json.loads alone. An entry carrying only a name -- a
    hand-written baseline, a third-party writer -- must fill the rest rather
    than raise a KeyError through the caller, which would end the run instead
    of ending the comparison.
    """
    doc = {
        "suite": "local",
        "engine_version": "1.1.0",
        "config": {"seed": 1337},
        "suite_hash": "AAA",
        "solved": 5,
        "total": 10,
        "timestamp": "2026-09-16T00:00:00Z",
        "manifest_hash": "h",
        "environment": [{"name": "nmap"}, "not a mapping at all"],
    }
    p = tmp_path / "partial.json"
    p.write_text(json.dumps(doc))

    loaded = load_baseline(p)
    assert loaded is not None
    assert len(loaded.environment) == 1
    assert loaded.environment[0] == ToolVersion("nmap", None, None, "")

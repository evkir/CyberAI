"""Tests for the benchmark run manifest (determinism + provenance)."""

from __future__ import annotations

import random

from cyberai.bench.environment import ToolVersion
from cyberai.bench.run_manifest import (
    DEFAULT_SEED,
    RunConfig,
    build_manifest,
    hash_tasks,
    set_global_seed,
)
from cyberai.bench.runner import BenchResult, BenchTask, SuiteReport


def _tasks() -> list[BenchTask]:
    return [
        BenchTask(id="t1", suite="s", target="x", name="one", success_criteria="a"),
        BenchTask(id="t2", suite="s", target="y", name="two", success_criteria="b"),
    ]


def _report(solved: int = 1, total: int = 2) -> SuiteReport:
    results = (
        BenchResult("t1", "s", True),
        BenchResult("t2", "s", solved == 2),
    )
    return SuiteReport(suite="s", total=total, solved=solved, results=results)


def test_set_global_seed_is_repeatable():
    set_global_seed(DEFAULT_SEED)
    a = [random.random() for _ in range(5)]
    set_global_seed(DEFAULT_SEED)
    b = [random.random() for _ in range(5)]
    assert a == b


def test_hash_tasks_order_independent():
    t = _tasks()
    assert hash_tasks(t) == hash_tasks(list(reversed(t)))


def test_hash_tasks_changes_when_suite_changes():
    base = hash_tasks(_tasks())
    swapped = _tasks() + [
        BenchTask(id="t3", suite="s", target="z", name="three", success_criteria="c")
    ]
    assert hash_tasks(swapped) != base


def test_manifest_hash_excludes_timestamp():
    tasks, report = _tasks(), _report()
    m1 = build_manifest("s", tasks, report, timestamp="2026-01-01T00:00:00Z")
    m2 = build_manifest("s", tasks, report, timestamp="2026-12-31T23:59:59Z")
    assert m1.manifest_hash == m2.manifest_hash
    assert m1.timestamp != m2.timestamp


def test_manifest_hash_changes_with_config_or_score():
    tasks, report = _tasks(), _report()
    base = build_manifest("s", tasks, report).manifest_hash
    diff_cfg = build_manifest(
        "s", tasks, report, config=RunConfig(model="gpt-4o", temperature=0.7)
    ).manifest_hash
    diff_score = build_manifest("s", tasks, _report(solved=2)).manifest_hash
    assert diff_cfg != base
    assert diff_score != base


def test_manifest_roundtrips_json():
    m = build_manifest("s", _tasks(), _report())
    assert '"manifest_hash"' in m.to_json()
    assert m.pass_at_1 == 0.5


def _tool(name="nmap", path="/usr/bin/nmap", version="7.98", detail=""):
    return ToolVersion(name=name, path=path, version=version, detail=detail)


def test_a_run_that_probed_nothing_carries_an_empty_toolchain():
    assert build_manifest("s", _tasks(), _report()).environment == ()


def test_a_tool_that_moved_version_moves_the_fingerprint():
    tasks, report = _tasks(), _report()
    a = build_manifest("s", tasks, report, environment=(_tool(version="7.98"),))
    b = build_manifest("s", tasks, report, environment=(_tool(version="7.99"),))
    assert a.manifest_hash != b.manifest_hash


def test_the_path_is_recorded_but_stays_out_of_the_fingerprint():
    """A path says where a machine keeps a binary, not what the binary is.

    Hashing it would make a run on this laptop incomparable with the same
    run on the CI runner, which is the one comparison the fingerprint is for.
    """
    tasks, report = _tasks(), _report()
    here = build_manifest("s", tasks, report, environment=(_tool(path="/usr/bin/nmap"),))
    there = build_manifest("s", tasks, report, environment=(_tool(path="/opt/nmap/bin/nmap"),))
    assert here.manifest_hash == there.manifest_hash
    assert "/opt/nmap/bin/nmap" in there.to_json()


def test_a_missing_tool_is_not_the_same_run_as_a_present_one():
    tasks, report = _tasks(), _report()
    present = build_manifest("s", tasks, report, environment=(_tool(),))
    absent = build_manifest(
        "s",
        tasks,
        report,
        environment=(_tool(path=None, version=None, detail="not installed"),),
    )
    assert present.manifest_hash != absent.manifest_hash


def test_two_unversioned_tools_differ_by_the_reason_they_are_unversioned():
    """Both carry version None, so only the reason separates them.

    A binary that is absent and a binary that is present but never asked are
    different environments; collapsing them would let a toolchain change pass
    under one fingerprint.
    """
    tasks, report = _tasks(), _report()
    uninstalled = build_manifest(
        "s",
        tasks,
        report,
        environment=(_tool(path=None, version=None, detail="not installed"),),
    )
    unasked = build_manifest(
        "s",
        tasks,
        report,
        environment=(_tool(version=None, detail="version flag not measured"),),
    )
    assert uninstalled.manifest_hash != unasked.manifest_hash


def test_which_tool_holds_a_version_is_part_of_the_run():
    """Two tools at one version number are not one environment.

    Mutation found this: dropping the name from the fingerprint survived the
    whole suite. Nothing distinguished nuclei at 3.8.0 from a second tool that
    happens to sit at 3.8.0 too, so a swap between them hashed identically.
    """
    tasks, report = _tasks(), _report()
    one = build_manifest("s", tasks, report, environment=(_tool(name="nuclei", version="3.8.0"),))
    other = build_manifest(
        "s", tasks, report, environment=(_tool(name="slither", version="3.8.0"),)
    )
    assert one.manifest_hash != other.manifest_hash

"""Tests for the local vulnerable-target suite (cyberai/bench/targets.py)."""

from __future__ import annotations

from cyberai.bench.runner import BenchTask
from cyberai.bench.targets import (
    LOCAL_SUITE,
    LocalSuiteAdapter,
    VulnClass,
    VulnTarget,
)


def test_local_suite_has_four_distinct_targets():
    ids = [t.id for t in LOCAL_SUITE]
    assert len(ids) == 4
    # Uniqueness is asserted against the actual length, not the literal: a
    # duplicate added alongside a count bump would otherwise pass both.
    assert len(set(ids)) == len(ids)
    # ports must be unique so containers don't collide
    ports = [t.port for t in LOCAL_SUITE]
    assert len(set(ports)) == len(ports)


def test_to_bench_task_projects_contract():
    target = LOCAL_SUITE[0]
    task = target.to_bench_task()
    assert isinstance(task, BenchTask)
    assert task.suite == "local"
    assert task.target == f"http://localhost:{target.port}"
    assert task.metadata["vuln_class"] == target.vuln_class.value
    assert task.metadata["cwe"] == target.cwe
    assert task.metadata["app"] == target.app


def test_adapter_loads_all_as_tasks():
    adapter = LocalSuiteAdapter()
    tasks = adapter.load_tasks()
    assert len(tasks) == len(LOCAL_SUITE)
    assert all(t.suite == "local" for t in tasks)


def test_adapter_get_target_roundtrip():
    adapter = LocalSuiteAdapter()
    t = adapter.get_target("local-cmdi-ping")
    assert isinstance(t, VulnTarget)
    assert t.vuln_class is VulnClass.COMMAND_INJECTION
    assert adapter.get_target("does-not-exist") is None


def test_adapter_accepts_custom_targets():
    custom = (
        VulnTarget(
            id="x",
            name="x",
            vuln_class=VulnClass.SSRF,
            cwe="CWE-918",
            port=9001,
            app="ssrf_demo",
            success_signal="oob callback received",
        ),
    )
    adapter = LocalSuiteAdapter(targets=custom)
    assert len(adapter.load_tasks()) == 1

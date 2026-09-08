"""Two runs that saw different surfaces do not fingerprint alike.

Measured 2026-09-08 on live targets: with api_discovery off the walk finds
0 endpoints on both Juice Shop and VAmPI; with it on, 15 and 5. The flag
reaches the bench from the environment, and nothing in the manifest said
which way a run went, so two runs of the same suite could carry the same
provenance and mean different things.

The engine's own rejection of api_discovery is a CVE-Bench measurement --
a wider surface displaces targets the budget was already exercising -- and
it holds for that class of target. It does not describe an application
whose surface lives in a spec, which is why the profile is recorded rather
than assumed.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from click.testing import CliRunner

from cyberai.bench.agent_engine import agent_attack
from cyberai.bench.runner import BenchResult, SuiteReport
from cyberai.cli.bench import bench


class _Agent:
    def __init__(self, cfg, session):
        self.llm = None

    def _run_web_recon(self, base_url):
        return {}

    def _run_web_exploit(self, base_url, classes=None):
        return {}


def _attack(monkeypatch, **env):
    for key in ("CYBERAI_USE_API_DISCOVERY", "CYBERAI_USE_ROUTE_PROBING"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("cyberai.bench.agent_engine.ReconAgent", _Agent)
    monkeypatch.setattr("cyberai.bench.agent_engine.ExploitAgent", _Agent)
    return agent_attack("http://t")


def test_the_outcome_records_the_flags_the_run_used(monkeypatch):
    outcome = _attack(monkeypatch, CYBERAI_USE_API_DISCOVERY="1")
    assert outcome.surface_profile["api_discovery"] is True
    assert outcome.surface_profile["oob"] is True


def test_the_outcome_records_the_narrow_profile_too(monkeypatch):
    """Off is a measurement; absent would not be."""
    outcome = _attack(monkeypatch)
    assert outcome.surface_profile["api_discovery"] is False


def _report(*profiles) -> SuiteReport:
    results = tuple(
        BenchResult(
            task_id=f"t{i}",
            suite="local",
            solved=True,
            duration_s=1.0,
            details={} if p is None else {"surface_profile": p},
        )
        for i, p in enumerate(profiles)
    )
    return SuiteReport(suite="local", total=len(results), solved=len(results), results=results)


def _manifest_for(report, tmp_path):
    path = tmp_path / "m.json"
    with patch("cyberai.cli.bench.run_suite", return_value=report):
        result = CliRunner().invoke(bench, ["run", "--suite", "local", "--manifest", str(path)])
    assert result.exit_code == 0, result.output
    return json.loads(path.read_text())


_WIDE = {"api_discovery": True, "route_probing": False, "oob": True}
_NARROW = {"api_discovery": False, "route_probing": False, "oob": True}


def test_the_manifest_carries_the_profile(tmp_path):
    manifest = _manifest_for(_report(_WIDE, _WIDE), tmp_path)
    assert manifest["config"]["extra"]["api_discovery"] == "on"
    assert manifest["config"]["extra"]["oob"] == "on"


def test_two_profiles_do_not_share_a_hash(tmp_path):
    """The point of the record: provenance that distinguishes the runs."""
    wide = _manifest_for(_report(_WIDE, _WIDE), tmp_path / "a")
    narrow = _manifest_for(_report(_NARROW, _NARROW), tmp_path / "b")
    assert wide["manifest_hash"] != narrow["manifest_hash"]


def test_tasks_that_disagree_report_the_disagreement(tmp_path):
    manifest = _manifest_for(_report(_WIDE, _NARROW), tmp_path)
    extra = manifest["config"]["extra"]
    assert extra["surface_profile"] == "mixed across tasks"
    assert "api_discovery" not in extra


def test_a_run_that_recorded_nothing_adds_no_keys(tmp_path):
    """Absent stays absent rather than becoming a row of `off`."""
    extra = _manifest_for(_report(None, None), tmp_path)["config"]["extra"]
    assert "api_discovery" not in extra
    assert "surface_profile" not in extra


def test_one_silent_task_is_a_disagreement_not_a_majority(tmp_path):
    extra = _manifest_for(_report(_WIDE, None), tmp_path)["config"]["extra"]
    assert extra["surface_profile"] == "mixed across tasks"

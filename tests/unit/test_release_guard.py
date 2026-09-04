"""The publication guard, exercised on the workflow it will actually read.

Its inputs are a workflow file and a JSON document from an API, and neither is
available to it at the moment anyone would notice a mistake: it runs once, on
a tag, and the thing it prevents is exactly the thing nobody watches. So the
cases are written out here instead -- a green commit, a red one, an unfinished
one, and a job whose check run never appeared.

The workflow used is the repository's own. A fixture workflow would test the
parser and leave the question that matters -- whether the names in ci.yml and
the names GitHub reports can be matched at all -- unasked.
"""

import importlib.util
import json
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "release_guard.py"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"


def _guard():
    spec = importlib.util.spec_from_file_location("release_guard", _SCRIPT)
    assert spec and spec.loader, f"no module at {_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _passing_runs(guard) -> list[dict]:
    """One successful check run per job, matrix jobs given a suffixed leg."""
    runs = []
    for name in guard.job_names(_CI):
        rendered = f"{name} (3.12)" if name == "Run Tests" else name
        runs.append({"name": rendered, "status": "completed", "conclusion": "success"})
    return runs


@pytest.mark.unit
def test_a_commit_whose_jobs_all_passed_is_publishable() -> None:
    guard = _guard()
    assert guard.failures(_CI, _passing_runs(guard)) == []


@pytest.mark.unit
def test_every_job_in_the_workflow_is_required() -> None:
    """The list is derived, so a job added to CI gates the release at once."""
    guard = _guard()
    names = guard.job_names(_CI)
    assert names, "no jobs parsed out of ci.yml"
    for name in names:
        runs = [run for run in _passing_runs(guard) if not run["name"].startswith(name)]
        problems = guard.failures(_CI, runs)
        assert any(name in problem for problem in problems), (name, problems)


@pytest.mark.unit
def test_a_failed_job_stops_the_release() -> None:
    guard = _guard()
    runs = _passing_runs(guard)
    runs[0] = {**runs[0], "conclusion": "failure"}
    problems = guard.failures(_CI, runs)
    assert len(problems) == 1 and "failure" in problems[0], problems


@pytest.mark.unit
def test_a_job_still_running_stops_the_release() -> None:
    """Not finished is not passed, and the tag can be pushed again later."""
    guard = _guard()
    runs = _passing_runs(guard)
    runs[0] = {"name": runs[0]["name"], "status": "in_progress", "conclusion": None}
    problems = guard.failures(_CI, runs)
    assert len(problems) == 1 and "not finished" in problems[0], problems


@pytest.mark.unit
def test_the_command_reports_through_its_exit_code(tmp_path, capsys) -> None:
    """A guard that prints its objection and exits zero guards nothing."""
    guard = _guard()
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"check_runs": _passing_runs(guard)}), encoding="utf-8")
    assert guard.main(["--workflow", str(_CI), "--check-runs", str(good)]) == 0

    bad = tmp_path / "bad.json"
    runs = _passing_runs(guard)
    runs[-1] = {**runs[-1], "conclusion": "cancelled"}
    bad.write_text(json.dumps({"check_runs": runs}), encoding="utf-8")
    assert guard.main(["--workflow", str(_CI), "--check-runs", str(bad)]) == 1
    assert "cancelled" in capsys.readouterr().err

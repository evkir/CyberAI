"""The path out of the repository is gated like the path in.

main carries required checks; a tag carried none. `release.yml` fires on v*,
builds and uploads to PyPI, and until the guard job existed nothing between
the tag and the upload consulted whether the commit's CI had passed, failed or
finished. The asymmetry is the finding: the strong gate stood where code
enters, and the artifact users install left through an open door.

What is asserted here is the wiring, not the decision. Whether a particular
commit is publishable is the script's judgement and is tested against real
workflow names in test_release_guard.py. What this file holds is that the
judgement is consulted at all: that publishing depends on building, building
depends on the guard, and the guard runs the script against the CI workflow
rather than against something that would pass more easily.
"""

import pathlib

import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_RELEASE = _ROOT / ".github" / "workflows" / "release.yml"
_SCRIPT = "scripts/release_guard.py"
_CI = ".github/workflows/ci.yml"


def _jobs() -> dict:
    return (yaml.safe_load(_RELEASE.read_text(encoding="utf-8")) or {}).get("jobs") or {}


def _needs(job: dict) -> set[str]:
    declared = job.get("needs") or []
    return {declared} if isinstance(declared, str) else set(declared)


def _commands(job: dict) -> str:
    return "\n".join(str(step.get("run", "")) for step in job.get("steps", []))


def test_the_upload_cannot_run_before_the_guard() -> None:
    """Every job in the chain, not only the one that names it directly."""
    jobs = _jobs()
    assert "guard" in jobs, "release.yml has no guard job"

    reached, frontier = set(), {"publish"}
    while frontier:
        name = frontier.pop()
        assert name in jobs, f"{name} is depended on and does not exist"
        reached.add(name)
        frontier |= _needs(jobs[name]) - reached
    assert "guard" in reached, f"publish reaches only {sorted(reached)}"


def test_the_guard_asks_about_the_ci_workflow() -> None:
    """Pointed at another file it would pass on jobs nobody requires."""
    body = _commands(_jobs()["guard"])
    assert _SCRIPT in body, "the guard job does not run the guard"
    assert _CI in body, f"the guard does not name {_CI}"


def test_the_guard_may_read_the_checks_it_judges() -> None:
    """Without this permission the API answers nothing and the step is theatre."""
    assert _jobs()["guard"].get("permissions", {}).get("checks") == "read"

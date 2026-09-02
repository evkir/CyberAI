"""The directory is the only thing that decides what an architecture test is.

A marker said so too, until it did not. `architecture` was declared in
pytest.ini and applied 87 times, and `-m architecture` was written nowhere: no
workflow, no script, no document. Meanwhile four files in the directory carried
no marker at all, which stayed invisible for exactly as long as nobody selected
by it. Had anyone started, the selection would have run four fifths of the
directory and reported success.

Two assertions hold the single criterion in place, and the missing third is
deliberate. An assertion that no file carries the marker was written and
dropped after measurement: with `--strict-markers` in addopts, a marker applied
without being declared fails collection of its whole file before any assertion
runs. The marker cannot come back alone, so guarding the declaration guards
both.

Selection by path is the other half and is not decoration. It is what makes the
declaration safe to forbid: a job that switched to selecting by marker would
leave this directory unrun, and no test could report it, because the tests that
stopped being selected are these ones.
"""

import pathlib

import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_DIRECTORY = "tests/architecture/"
_WORKFLOWS = _ROOT / ".github" / "workflows"
_MARKER = "architecture"


def _commands() -> dict[str, str]:
    collected = {}
    for workflow in sorted(_WORKFLOWS.glob("*.yml")):
        document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        for name, job in (document.get("jobs") or {}).items():
            collected[f"{workflow.name}:{name}"] = "\n".join(
                str(step.get("run", "")) for step in job.get("steps", [])
            )
    return collected


def test_the_marker_is_not_declared() -> None:
    declared = [
        line
        for line in (_ROOT / "pytest.ini").read_text(encoding="utf-8").splitlines()
        if line.strip().startswith(f"{_MARKER}:")
    ]
    assert not declared, (
        f"pytest.ini declares the architecture marker again: {declared}; declaring it "
        "is what lets it be applied, and an applied marker selects nothing while "
        "inviting a selection that would miss whatever lacks it"
    )


def test_a_job_selects_the_directory_by_path() -> None:
    assert (_ROOT / _DIRECTORY).is_dir(), f"{_DIRECTORY} does not exist"
    selecting = sorted(
        name for name, commands in _commands().items() if f"pytest {_DIRECTORY}" in commands
    )
    assert selecting, (
        f"no job runs `pytest {_DIRECTORY}`; these tests are selected by path or they "
        "are not selected at all"
    )

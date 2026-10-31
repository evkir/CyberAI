"""The report must be run by a job, and run over the directory rather than a list.

`scripts/spelled_numbers.py` finds counts a digit guard cannot read. Its value
is in being run against everything, and the cheap way to run it is to name the
pages that were interesting the day the step was written. That list rots on the
first page added after it: the new page is not on it, the step stays green, and
nothing says the page was never looked at.

So the step names a directory and the script walks it. This file holds that
shape, not the counts: 277 lines across 31 pages were spelled out the day the
step landed, and pinning either number would red on the next page written and
teach the next reader to delete the gate.

Unlike the drift report next door, nothing here depends on what is installed:
the script reads markdown and imports no part of the package, so the job it
runs in does not matter.
"""

import pathlib

import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_SCRIPT = "scripts/spelled_numbers.py"
_DOCS = "docs"


def _run_steps() -> list[str]:
    commands = []
    for workflow in sorted(_WORKFLOWS.glob("*.yml")):
        document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        for job in (document.get("jobs") or {}).values():
            for step in job.get("steps", []):
                commands.append(str(step.get("run", "")))
    return commands


def _invocations() -> list[str]:
    return [command for command in _run_steps() if _SCRIPT in command]


def test_a_job_runs_the_report() -> None:
    assert (_ROOT / _SCRIPT).exists(), f"{_SCRIPT} is named by a workflow and is not in the tree"
    assert _invocations(), (
        f"{_SCRIPT} is in the repository and no workflow runs it; a count spelled "
        "out on a page would reach a reader with nothing having looked at it"
    )


def test_the_report_is_pointed_at_the_directory_not_at_a_list_of_pages() -> None:
    for command in _invocations():
        arguments = command.split(_SCRIPT, 1)[1].split()
        assert arguments == [_DOCS], (
            f"the step runs the report over {arguments}; a page added tomorrow would "
            f"not be on that list. Name the {_DOCS} directory and let the script walk it."
        )


def test_the_directory_the_step_names_exists() -> None:
    assert (_ROOT / _DOCS).is_dir(), f"the step walks {_DOCS}, which is not a directory here"

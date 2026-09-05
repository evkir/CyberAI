"""A script nobody is told to run is a producer with no consumer.

scripts/ holds work that costs too much to run inside the suite: a full-package
type check, a full collection. Neither can be a test, so neither is protected
by one -- a script can be added, be useful for a week, and then sit unread
while the thing it was written to prevent happens anyway.

A caller here means an instruction somebody or something executes: a run step
in a workflow, or a line in CONTRIBUTING.md. A paragraph in docs/ describing
what a script does is not a caller. The distinction is the whole point of the
file: typing-scope.md explains the drift report at length and would have kept
this green while nothing ran it.

What counts as a caller is a closed list, and a closed list is an assumption
about the repository rather than a fact about it. Measured on this checkout:
no Makefile, no tox.ini, no justfile, no noxfile.py, and docs/setup holds a
single page about an NVD key that runs nothing. So the list is complete
today. The day one of those files appears, a script can be both called and
counted orphaned here, and the cheap way out is to delete the gate. The last
test below fails on that day instead, and says what to do.

The reverse direction matters as much. A caller naming a script that was
renamed or deleted reads as a working instruction, and the person following it
finds out otherwise.
"""

import pathlib
import re

import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPTS = _ROOT / "scripts"
_WORKFLOWS = _ROOT / ".github" / "workflows"
_CONTRIBUTING = _ROOT / "CONTRIBUTING.md"

_REFERENCE = re.compile(r"scripts/[\w./-]+\.py")

# Files that would carry executable instructions this gate does not read.
_OTHER_RUNNERS = (
    "Makefile",
    "makefile",
    "GNUmakefile",
    "tox.ini",
    "justfile",
    "Justfile",
    "noxfile.py",
    "Taskfile.yml",
)


def _scripts_present() -> set[str]:
    return {f"scripts/{path.name}" for path in _SCRIPTS.glob("*.py")}


def _instructions() -> str:
    """Every text a person or a job actually executes."""
    parts = [_CONTRIBUTING.read_text(encoding="utf-8")]
    for workflow in sorted(_WORKFLOWS.glob("*.yml")):
        document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        for job in (document.get("jobs") or {}).values():
            for step in job.get("steps", []):
                parts.append(str(step.get("run", "")))
    return "\n".join(parts)


def _scripts_called() -> set[str]:
    return set(_REFERENCE.findall(_instructions()))


def test_every_script_is_named_by_something_that_runs_it() -> None:
    uncalled = sorted(_scripts_present() - _scripts_called())
    assert not uncalled, (
        f"{uncalled} sit in scripts/ and no workflow step or CONTRIBUTING line runs them"
    )


def test_no_instruction_names_a_script_that_is_gone() -> None:
    missing = sorted(_scripts_called() - _scripts_present())
    assert not missing, (
        f"a workflow or CONTRIBUTING tells someone to run {missing}, which is absent"
    )


def test_no_runner_exists_that_this_gate_cannot_read() -> None:
    """The list of callers above is complete only while these are absent.

    A Makefile target that runs a script makes the script called and leaves
    this file calling it an orphan. The failure is silent in the wrong
    direction: the obvious fix is to delete the assertion rather than teach
    _instructions to read the new runner.
    """
    present = sorted(name for name in _OTHER_RUNNERS if (_ROOT / name).exists())
    assert not present, (
        f"{present} can run scripts and _instructions() does not read them. "
        "Teach it to, rather than removing this assertion."
    )

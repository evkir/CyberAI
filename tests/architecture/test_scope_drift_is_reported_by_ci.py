"""The drift report must be run by a job, and by a job that has the stubs.

`scripts/typing_scope_drift.py` compares what the checker reads against what
passes. Nothing in the test suite calls it: it costs a full-package run, and
the answer it gives depends on what is installed, so it belongs where the
environment is declared rather than where the tests are. That leaves it one
step away from a producer with no consumer, and this is the consumer's
receipt.

The second assertion is the one worth having. The report is only meaningful in
a job that installs the dev extra. Run it where only the test extra is
installed and `networkx` loses its stubs, `cyberai/core/kb_graph.py` turns
clean, and the step reports a drift that exists nowhere but that job. A green
step in the wrong job would be worse than no step: it would name a module and
be wrong about it.

What the script computes is not asserted here. It was measured directly in
both directions before the step was added: a full scope reports no drift, and
a module withdrawn from `files` is named with a non-zero exit.
"""

import pathlib

import pytest
import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_SCRIPT = "scripts/typing_scope_drift.py"
_DEV_EXTRA = ".[dev]"


def _jobs() -> dict[str, dict]:
    collected: dict[str, dict] = {}
    for workflow in sorted(_WORKFLOWS.glob("*.yml")):
        document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        for name, job in (document.get("jobs") or {}).items():
            collected[f"{workflow.name}:{name}"] = job
    return collected


def _commands(job: dict) -> str:
    return "\n".join(str(step.get("run", "")) for step in job.get("steps", []))


def _jobs_running_the_report() -> set[str]:
    return {name for name, job in _jobs().items() if _SCRIPT in _commands(job)}


@pytest.mark.architecture
def test_the_drift_report_is_run_by_a_job() -> None:
    assert (_ROOT / _SCRIPT).exists(), f"{_SCRIPT} is referenced nowhere and exists nowhere"
    running = _jobs_running_the_report()
    assert running, (
        f"{_SCRIPT} is in the repository and no workflow runs it; the scope can "
        "drift and the only thing that would notice is switched off"
    )


@pytest.mark.architecture
def test_the_drift_report_runs_where_the_stubs_are_installed() -> None:
    without_stubs = sorted(
        name for name in _jobs_running_the_report() if _DEV_EXTRA not in _commands(_jobs()[name])
    )
    assert not without_stubs, (
        f"{without_stubs} run the drift report without installing the dev extra; "
        "without the declared stubs the report names modules that are clean only there"
    )

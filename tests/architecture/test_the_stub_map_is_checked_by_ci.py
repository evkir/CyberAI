"""The stub map must be verified by a job, and by a job that has the stubs.

`tests/architecture/test_typing_stubs_are_declared.py` decides that `yaml`
needs stubs and that `types-PyYAML` supplies them. It can decide the first
half: the import is in the source and the `py.typed` marker is in the wheel,
both readable in every job. It cannot decide the second. The test job installs
the test extra, which carries no stubs at all, so an assertion phrased over
what `types-PyYAML` actually installs would be red exactly where the tests
run.

That left the pairing hand-written and unasked. A distribution renamed, a
distribution that stopped shipping a module, or a typo would keep the suite
green while the checker resolved the import to `Any` and the scope was drawn
from a mapping nobody had confirmed.

`scripts/stub_distributions.py` asks. It runs in the typecheck job, where the
dev extra is installed, and it owns the mapping the test reads, so a module
gains a stub distribution in one place rather than two.

What the script computes is not asserted here; it was measured directly before
the step was added. Installed, `types-PyYAML` ships `yaml-stubs` and
`types-networkx` ships `networkx-stubs`, and the script exits zero on both;
pointed at a distribution that ships neither, it names what it found instead
and exits one.
"""

import pathlib

import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_SCRIPT = "scripts/stub_distributions.py"
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


def _jobs_running_the_check() -> set[str]:
    return {name for name, job in _jobs().items() if _SCRIPT in _commands(job)}


def test_the_stub_check_is_run_by_a_job() -> None:
    assert (_ROOT / _SCRIPT).exists(), f"{_SCRIPT} is referenced nowhere and exists nowhere"
    running = _jobs_running_the_check()
    assert running, (
        f"{_SCRIPT} is in the repository and no workflow runs it; the mapping it "
        "verifies goes back to being a note somebody typed once"
    )


def test_the_stub_check_runs_where_the_stubs_are_installed() -> None:
    without_stubs = sorted(
        name for name in _jobs_running_the_check() if _DEV_EXTRA not in _commands(_jobs()[name])
    )
    assert not without_stubs, (
        f"{without_stubs} run the stub check without installing the dev extra; "
        "every distribution would report as missing and the step would fail on the environment"
    )

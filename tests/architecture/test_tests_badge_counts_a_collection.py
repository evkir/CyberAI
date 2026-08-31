"""The test-count badge must come from a collection, not from a memory.

The badge said 2252 while the suite held 2440. Nothing produced that number:
it was typed once and edited by hand afterwards, which is the same failure
the artifact gates exist to stop, moved to the README.

It counts collected tests rather than passing ones, and the distinction is
deliberate. Collection is cheap and reproducible; "passing" is a claim about
a run, and this test is itself part of the run that would have to make it.
The suite being green is what makes every collected test a passing one, so
the badge says what is measured here and the CI status badge says the rest.
"""

import pathlib
import re
import subprocess
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_README = _ROOT / "README.md"

# The same selection CI runs, so the number describes the suite people gate on.
_MARKERS = "not slow and not smoke"


def _collected() -> int:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "-m",
            _MARKERS,
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"(\d+)(?:/\d+)? tests? collected", result.stdout)
    assert match, f"could not read a collection count from pytest:\n{result.stdout[-2000:]}"
    return int(match.group(1))


def _claimed() -> int:
    line = next(
        line for line in _README.read_text(encoding="utf-8").splitlines() if "badge/tests-" in line
    )
    match = re.search(r"badge/tests-(\d+)", line)
    assert match, f"the tests badge carries no number: {line}"
    return int(match.group(1))


@pytest.mark.architecture
def test_the_badge_counts_the_tests_that_exist() -> None:
    claimed, collected = _claimed(), _collected()
    assert claimed == collected, (
        f"the README badge says {claimed} tests and the suite collects {collected}. "
        "Update the badge rather than this number."
    )

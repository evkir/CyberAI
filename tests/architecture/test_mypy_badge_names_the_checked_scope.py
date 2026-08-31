"""The typing badge must name what the type checker actually reads.

The badge said `mypy core typed` while `[tool.mypy] files` held one module of
136 lines. The CI job was real, green and honest about its own scope; the
badge generalised it to a package with 233 errors in it. A green instrument
pointed at one file is worse than a missing one, because it looks like
evidence.

The rule is bidirectional. Widening `files` without touching the badge
understates the guarantee and is caught here too, so the badge cannot drift
in either direction.
"""

import pathlib
import re
import tomllib
import urllib.parse

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_README = _ROOT / "README.md"
_PYPROJECT = _ROOT / "pyproject.toml"

_PACKAGE = "cyberai/"


def _checked_paths() -> set[str]:
    config = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    files = config["tool"]["mypy"]["files"]
    return {path.removeprefix(_PACKAGE) for path in files}


def _claimed_paths() -> set[str]:
    line = next(
        line for line in _README.read_text(encoding="utf-8").splitlines() if "badge/mypy-" in line
    )
    label = urllib.parse.unquote(re.search(r"badge/mypy-(.+?)-[a-z]+\)", line).group(1))
    return {token for token in re.split(r"[\s,]+", label) if "/" in token}


@pytest.mark.architecture
def test_the_badge_claims_nothing_the_checker_does_not_read() -> None:
    claimed = _claimed_paths()
    assert claimed, "the mypy badge names no path; it cannot be checked against anything"
    assert claimed <= _checked_paths(), (
        f"the badge claims {sorted(claimed - _checked_paths())}, which "
        "[tool.mypy] files does not include"
    )


@pytest.mark.architecture
def test_the_badge_claims_everything_the_checker_reads() -> None:
    checked = _checked_paths()
    assert checked <= _claimed_paths(), (
        f"the checker reads {sorted(checked - _claimed_paths())}, which the badge does not name"
    )

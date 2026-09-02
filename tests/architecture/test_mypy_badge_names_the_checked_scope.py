"""The typing badge must state the size of what the type checker actually reads.

The badge once said `mypy core typed` while `[tool.mypy] files` held one module
of 136 lines. The CI job was real, green and honest about its own scope; the
badge generalised it to a package with hundreds of errors in it. A green
instrument pointed at one file is worse than a missing one, because it looks
like evidence.

The first version of this gate compared the set of paths named in the badge
against the set of paths in `files`. That contract holds only while the scope
is small enough to spell out. It is replaced by a counted one: the badge names
how many modules the checker reads and how many the package contains, and both
numbers are recomputed here from the repository. A directory in `files` is
expanded, so adding a module to a checked directory moves the count and the
badge has to follow. The scope is resolved as a set, so an entry that overlaps
a directory already listed cannot inflate the numerator.

The rule stays bidirectional. Widening the scope without touching the badge
understates the guarantee and fails here; claiming a wider scope than `files`
resolves to overstates it and fails here too.
"""

import pathlib
import re
import tomllib
import urllib.parse

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_README = _ROOT / "README.md"
_PYPROJECT = _ROOT / "pyproject.toml"

_PACKAGE = _ROOT / "cyberai"


def _checked_modules() -> int:
    config = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    resolved: set[pathlib.Path] = set()
    for entry in config["tool"]["mypy"]["files"]:
        path = _ROOT / entry
        resolved.update(path.rglob("*.py")) if path.is_dir() else resolved.add(path)
    return len(resolved)


def _package_modules() -> int:
    return len(list(_PACKAGE.rglob("*.py")))


def _claimed_counts() -> tuple[int, int]:
    line = next(
        line for line in _README.read_text(encoding="utf-8").splitlines() if "badge/mypy-" in line
    )
    label = urllib.parse.unquote(re.search(r"badge/mypy-(.+?)-[a-z]+\)", line).group(1))
    match = re.search(r"(\d+)\s*/\s*(\d+)", label)
    assert match, f"the mypy badge states no ratio; it reads {label!r}"
    return int(match.group(1)), int(match.group(2))


def test_the_badge_claims_no_more_than_the_checker_reads() -> None:
    claimed, _ = _claimed_counts()
    checked = _checked_modules()
    assert claimed <= checked, (
        f"the badge claims {claimed} checked modules, but [tool.mypy] files resolves to {checked}"
    )


def test_the_badge_claims_everything_the_checker_reads() -> None:
    claimed, _ = _claimed_counts()
    checked = _checked_modules()
    assert claimed >= checked, (
        f"the checker reads {checked} modules, but the badge claims only {claimed}"
    )


def test_the_badge_names_the_size_of_the_package_it_measures_against() -> None:
    _, denominator = _claimed_counts()
    assert denominator == _package_modules(), (
        f"the badge measures against {denominator} modules; the package holds {_package_modules()}"
    )

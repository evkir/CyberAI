"""The version badge in README must name the version the package ships.

BK in the private tail list, and the same class of defect as CJ: a number
written by hand into a document has no gate, so it drifts and nobody
notices. The badge said v1.5.0 across a release; the tests badge said 2075
against 2252 collected.

tests/unit/test_cli_version.py does not catch this. It asserts that
``cyberai --version`` prints ``__version__``, which stays true no matter
what the badge claims -- it reads the same constant the CLI does. The badge
is a second, independent statement of the same fact, aimed at a reader who
will never run the command, and it is the one that was wrong.

The test count is deliberately not pinned here. It changes with almost
every commit, so a gate on it would fail on green work and train the
reviewer to ignore this file. Only the version is pinned, because it
changes exactly when a release does.
"""

import pathlib
import re

from cyberai.version import __version__

_README = pathlib.Path(__file__).resolve().parents[2] / "README.md"
_BADGE = re.compile(r"!\[Version\]\(https://img\.shields\.io/badge/version-v([0-9][^-)]*)-")


def test_readme_version_badge_matches_package_version() -> None:
    found = _BADGE.findall(_README.read_text(encoding="utf-8"))
    assert found == [__version__], (found, __version__)

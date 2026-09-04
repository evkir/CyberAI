"""The top of the changelog is the version being shipped.

Everything else in this repository that states a version is checked: the README
badge against the package constant, the CLI against the same constant, the
scorecards against the engine that produced them. The changelog was not, and it
showed -- the 1.6.0 section carried the date its draft was started and stopped
where the draft stopped, so nine days of work reached a release the notes did
not mention.

Two things are asserted and neither pins prose. The first is that the newest
section names the version the package will publish, because a changelog whose
top entry is behind the constant describes a release nobody is making. The
second lives in test_docs_quote_the_artifact.py: this file joins the set whose
percentages must come from a committed report or a fresh run, so the detector
figures quoted in the release notes cannot outlive the measurement that
produced them.

What is not asserted is completeness. No test can know that an entry is
missing, which is why the gate that matters here is the one on figures -- a
missing entry is a thin changelog, a stale figure is a false claim.
"""

import pathlib
import re

from cyberai.version import __version__

_CHANGELOG = pathlib.Path(__file__).resolve().parents[2] / "CHANGELOG.md"
_HEADING = re.compile(r"^## \[([0-9][^\]]*)\]", re.MULTILINE)


def _versions() -> list[str]:
    return _HEADING.findall(_CHANGELOG.read_text(encoding="utf-8"))


def test_the_newest_entry_is_the_version_that_ships() -> None:
    found = _versions()
    assert found, "no version headings in the changelog"
    assert found[0] == __version__, (found[0], __version__)


def test_the_entries_are_ordered_newest_first() -> None:
    """An out-of-order file makes the first heading the wrong thing to read."""

    def key(version: str) -> tuple[int, ...]:
        return tuple(int(part) for part in version.split(".") if part.isdigit())

    found = _versions()
    assert found == sorted(found, key=key, reverse=True), found

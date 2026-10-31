"""The report separates a pronoun from a count, and says so on real sentences.

`scripts/spelled_numbers.py` decides one thing mechanically: whether `one` in
a line is the numeral or the pronoun. Everything else it reports for a reader
to classify. That single decision is a closed list of shapes, which makes it
a guess about English rather than a fact about the tree -- it was already
wrong once, swallowing `one more call-arg error` as a pronoun and hiding a
count on a page it was written to read.

A closed list that is never exercised drifts quietly: a shape added to stop a
false report takes true ones with it, and the output simply gets shorter. The
sentences below are the page's own, so the filter is measured against the
material it runs on rather than against invented examples.
"""

from __future__ import annotations

import importlib.util
import pathlib
import types

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "spelled_numbers.py"


def _tool() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("spelled_numbers", _SCRIPT)
    assert spec and spec.loader, f"no module at {_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_MODULE = _tool()
prose_lines = _MODULE.prose_lines
spelled_counts = _MODULE.spelled_counts


def test_a_pronoun_is_not_reported_as_a_count() -> None:
    """Shapes taken from the page, where rewriting the word to a digit is nonsense."""
    for line in (
        "it turned out not to be the one that mattered. A workstation carrying mcp",
        "listed as directories, so a module added to one of them is checked from the",
        "wide run a cache directory of its own instead of purging the shared one.",
        "216 errors in 44 files, and every one of those files lies outside the scope.",
    ):
        assert spelled_counts(line) == [], f"the filter reports a count in: {line}"


def test_a_count_beside_a_pronoun_survives_the_filter() -> None:
    """The filter drops the matched words, not the line they sit in."""
    line = "one more call-arg error against the older one. `mcp>=1.0,<3` admits both on"
    assert spelled_counts(line) == ["one"], "a count next to a pronoun was swallowed with it"


def test_a_measurement_is_reported_whatever_the_case() -> None:
    assert spelled_counts("Two modules import yaml, and without `types-PyYAML` both") == ["Two"]
    assert spelled_counts("reports ten `type-arg` errors") == ["ten"]


def test_a_fenced_block_is_not_prose() -> None:
    """A command printed for a reader to run is not a sentence making a claim."""
    text = "one sentence\n```\nrun --with two flags\n```\nthree sentences\n"
    assert [number for number, _ in prose_lines(text)] == [1, 5]

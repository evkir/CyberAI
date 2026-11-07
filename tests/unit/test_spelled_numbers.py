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
pages = _MODULE.pages
prose_lines = _MODULE.prose_lines
spelled_counts = _MODULE.spelled_counts
survey = _MODULE.survey
summarise = _MODULE.summarise


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


def test_a_directory_resolves_to_every_page_under_it(tmp_path: pathlib.Path) -> None:
    """The CI step names a directory, so a page in a subdirectory must be reached.

    Both halves were measured by mutation before this test existed: walking
    only the top level, and treating a directory as a single file, each left
    every other test in the suite green.
    """
    (tmp_path / "top.md").write_text("one sentence\n", encoding="utf-8")
    nested = tmp_path / "nested" / "deeper"
    nested.mkdir(parents=True)
    (nested / "buried.md").write_text("two sentences\n", encoding="utf-8")
    (tmp_path / "not-a-page.txt").write_text("three\n", encoding="utf-8")

    found = {path.name for path in pages(tmp_path)}
    assert found == {"top.md", "buried.md"}, f"the walk reached {sorted(found)}"


def test_a_file_resolves_to_itself(tmp_path: pathlib.Path) -> None:
    page = tmp_path / "single.md"
    page.write_text("four\n", encoding="utf-8")
    assert pages(page) == [page]


def test_the_walk_reports_how_many_pages_carry_a_count(tmp_path: pathlib.Path) -> None:
    """Pages read and pages carrying are different sets, and both are returned.

    The closing sentence said `273 lines across 31 pages` while 16 pages held
    one, and the figure was quoted as the second. A flat list of findings
    cannot answer it after the fact without parsing the text just printed.
    """
    (tmp_path / "carries.md").write_text("one sentence\n", encoding="utf-8")
    (tmp_path / "also.md").write_text("Two modules import yaml\n", encoding="utf-8")
    (tmp_path / "clean.md").write_text("nothing countable here\n", encoding="utf-8")

    findings, carrying = survey(pages(tmp_path))
    assert len(findings) == 2, findings
    assert carrying == 2, "a page without a count was counted as carrying one"


def test_a_page_with_two_counts_is_one_page(tmp_path: pathlib.Path) -> None:
    """The page count cannot be the line count, and a page carrying twice proves it."""
    (tmp_path / "twice.md").write_text("one sentence\nTwo modules import yaml\n", encoding="utf-8")

    findings, carrying = survey(pages(tmp_path))
    assert (len(findings), carrying) == (2, 1), (findings, carrying)


def test_the_summary_names_the_set_each_figure_describes() -> None:
    assert summarise(273, 16, 31) == (
        "16 of 31 pages carry a spelled numeral outside code blocks, on 273 lines"
    )


def test_the_summary_counts_in_the_singular() -> None:
    """`1 pages` in a report is a defect in the report."""
    assert summarise(1, 1, 1) == (
        "1 of 1 page carries a spelled numeral outside code blocks, on 1 line"
    )


def test_an_empty_report_says_so_in_the_plural() -> None:
    assert summarise(0, 0, 31) == (
        "0 of 31 pages carry a spelled numeral outside code blocks, on 0 lines"
    )

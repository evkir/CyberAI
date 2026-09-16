"""The page that explains the manifest must name every field the manifest has.

The manifest is the artefact an outsider reads to decide whether our number
means anything, and the page is where they learn what each field is. A field
added to the dataclass and not to the page is invisible to that reader, and
prose does not rot loudly: the code moves, the table stays, and nothing
disagrees out loud.

This gap was real rather than hypothetical. `environment` landed in
RunManifest and the table went on listing seven fields, and no test noticed,
because nothing read this file at all -- three greps for "reproducibility"
matched the word in unrelated docstrings, not the path.

Both directions are checked. A field the page omits is the rot above; a field
the page names and the dataclass does not have is the same rot wearing the
other face, left behind by a rename.
"""

import dataclasses
import pathlib
import re

from cyberai.bench.run_manifest import RunManifest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PAGE = _ROOT / "docs" / "benchmarks" / "reproducibility.md"

# The first cell of a markdown row, when it is a single backticked token or a
# pair separated by a slash: `suite`, `solved` / `total`.
_ROW = re.compile(r"^\|\s*(`[^|]+`(?:\s*/\s*`[^|]+`)?)\s*\|", re.MULTILINE)
_TOKEN = re.compile(r"`([^`]+)`")


def _page_fields() -> set[str]:
    section = _PAGE.read_text(encoding="utf-8").split("## The run manifest", 1)[1]
    section = section.split("## ", 1)[0]
    named: set[str] = set()
    for row in _ROW.findall(section):
        named.update(_TOKEN.findall(row))
    assert named, "the run-manifest section holds no field table"
    return named


def _manifest_fields() -> set[str]:
    return {f.name for f in dataclasses.fields(RunManifest)}


def test_every_field_of_the_manifest_is_explained_on_the_page() -> None:
    missing = _manifest_fields() - _page_fields()
    assert not missing, f"the manifest carries fields the page never explains: {sorted(missing)}"


def test_the_page_explains_no_field_the_manifest_dropped() -> None:
    stale = _page_fields() - _manifest_fields()
    assert not stale, f"the page explains fields the manifest no longer has: {sorted(stale)}"

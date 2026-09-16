"""The page that explains the gate must name every field the verdict has.

The manifest already has this guard; the verdict did not, and it is the half
an outsider actually reads. A CI job prints `reason`, a dashboard renders the
dict field for field, and a field added to GateResult without a line on the
page is a value crossing the API that nothing explains.

Both directions, for the reason the manifest guard gives: a field the page
omits is rot, and a field the page names that the dataclass dropped is the
same rot left behind by a rename.

The table is read out of the gate section alone. Reading the whole page would
let a token in the manifest table answer for a verdict field, and the two
records share field names -- suite_hash sits in one, suite_changed in the
other, and a looser match would let prose about either satisfy this test.
"""

import dataclasses
import pathlib
import re

from cyberai.bench.regression_gate import GateResult

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PAGE = _ROOT / "docs" / "benchmarks" / "reproducibility.md"

_ROW = re.compile(r"^\|\s*(`[^|]+`(?:\s*/\s*`[^|]+`)?)\s*\|", re.MULTILINE)
_TOKEN = re.compile(r"`([^`]+)`")


def _page_fields() -> set[str]:
    section = _PAGE.read_text(encoding="utf-8").split("## The regression gate", 1)[1]
    section = section.split("\n## ", 1)[0]
    named: set[str] = set()
    for row in _ROW.findall(section):
        named.update(_TOKEN.findall(row))
    assert named, "the regression-gate section holds no field table"
    return named


def _verdict_fields() -> set[str]:
    return {f.name for f in dataclasses.fields(GateResult)}


def test_every_field_of_the_verdict_is_explained_on_the_page() -> None:
    missing = _verdict_fields() - _page_fields()
    assert not missing, f"the verdict carries fields the page never explains: {sorted(missing)}"


def test_the_page_explains_no_field_the_verdict_dropped() -> None:
    stale = _page_fields() - _verdict_fields()
    assert not stale, f"the page explains fields the verdict no longer has: {sorted(stale)}"

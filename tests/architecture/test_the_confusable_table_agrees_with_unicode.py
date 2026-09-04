"""The confusable table's values are checked against Unicode, not asserted.

Every other gate on CONFUSABLE_TO_LATIN follows the table's own values: the
carrier phrase is picked by the declared letter, the substitution goes where
the mapping points, and the text folds back either way. Mutating one entry
from "a" to "e" left the whole repository green, which was recorded as the
boundary of that gate. Resemblance looked like authored data with no oracle
behind it.

There is one. UTS #39 publishes confusables.txt, the table browsers and
registrars use to decide which strings can impersonate which, and it holds
every codepoint this package maps. Comparing against it directly would fail
on four entries for the wrong reason: Unicode folds capital I, small l and
digit one onto a single prototype, and capital O onto zero, so it answers
"l" where this table says "I". Those are not disagreements, they are the
same claim written with a different representative.

So both sides are folded before comparing. An entry passes when the
confusable and the Latin letter it claims to imitate reach the same
prototype -- which is what "these two are confusable" means in the standard.
No exception list is written here; the collapse comes out of the same file.

What survives: within a prototype class any member is accepted, so an entry
mapping to "I" also passes as "l" or "1". Four of the forty-two sit in such
a class and the test names them. The other thirty-eight are pinned to one
letter, and the mutation that used to leave the repository green does not.
"""

import pathlib
import string

import pytest

from cyberai.core.security.injection_detector import CONFUSABLE_TO_LATIN

# Vendored rather than fetched: a gate that needs the network is a gate that
# is skipped on the day it matters. Source and version are asserted below, so
# swapping the file for another one fails here rather than quietly changing
# what the repository claims to have checked against.
_DATA = pathlib.Path(__file__).resolve().parents[1] / "data" / "unicode" / "confusables.txt"
_VERSION = "17.0.0"

# A prototype class the table is allowed to answer with any member of, because
# Unicode itself refuses to distinguish them. Kept as an assertion, not as an
# exemption: the members are read out of the data, and the test fails if the
# class ever stops containing what it contains here.
_COLLAPSED = {"I": "l1", "O": "0"}


def _prototypes() -> dict[int, str]:
    """Map each source codepoint to the sequence UTS #39 says it imitates."""
    table: dict[int, str] = {}
    for line in _DATA.read_text(encoding="utf-8-sig").splitlines():
        body = line.split("#")[0].strip()
        if not body:
            continue
        fields = [field.strip() for field in body.split(";")]
        if len(fields) < 2:
            continue
        try:
            source = int(fields[0], 16)
        except ValueError:
            continue
        table[source] = "".join(chr(int(point, 16)) for point in fields[1].split())
    return table


_PROTOTYPE = _prototypes()


def _fold(text: str) -> str:
    return "".join(_PROTOTYPE.get(ord(char), char) for char in text)


def test_the_vendored_file_is_the_published_table() -> None:
    """A truncated or substituted file would make every comparison vacuous."""
    header = _DATA.read_text(encoding="utf-8-sig")[:600]
    assert f"Version: {_VERSION}" in header, header[:200]
    assert "UTS #39" in header
    assert len(_PROTOTYPE) > 5000, len(_PROTOTYPE)


@pytest.mark.parametrize("codepoint", sorted(CONFUSABLE_TO_LATIN))
def test_unicode_agrees_the_entry_imitates_that_letter(codepoint: int) -> None:
    latin = CONFUSABLE_TO_LATIN[codepoint]
    assert codepoint in _PROTOTYPE, (
        f"U+{codepoint:04X} is not in UTS #39 at all, so this repository is "
        "the only thing claiming it impersonates a Latin letter"
    )
    assert _fold(chr(codepoint)) == _fold(latin), (
        f"U+{codepoint:04X} is mapped to {latin!r} here, but Unicode folds it "
        f"to {_fold(chr(codepoint))!r} and {latin!r} to {_fold(latin)!r}"
    )


def test_the_oracle_rejects_a_wrong_letter() -> None:
    """The comparison has to be able to fail, or it measures nothing.

    This is the mutation the previous gate could not kill, written down as a
    test: Greek small alpha imitates "a" and nothing else.
    """
    assert _fold("\u03b1") == _fold("a")
    for wrong in "ebcdfg":
        assert _fold("\u03b1") != _fold(wrong), wrong


def test_the_entries_a_prototype_class_leaves_ambiguous_are_named() -> None:
    """Where the oracle cannot pin one letter, say which entries and why."""
    alphabet = string.ascii_letters + string.digits
    ambiguous = {
        codepoint: "".join(
            sorted(c for c in alphabet if _fold(c) == _fold(chr(codepoint)) and c != latin)
        )
        for codepoint, latin in CONFUSABLE_TO_LATIN.items()
        if any(_fold(c) == _fold(chr(codepoint)) and c != latin for c in alphabet)
    }
    assert {CONFUSABLE_TO_LATIN[codepoint] for codepoint in ambiguous} == _COLLAPSED.keys(), (
        ambiguous
    )
    for codepoint, alternatives in ambiguous.items():
        expected = _COLLAPSED[CONFUSABLE_TO_LATIN[codepoint]]
        assert alternatives == "".join(sorted(expected)), (codepoint, alternatives)

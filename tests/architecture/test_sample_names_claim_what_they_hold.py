"""A sample's filename names a technique, and the name is checked against bytes.

Two samples were found naming a technique they did not contain. One called
itself base64 and held ROT13; the other called itself Greek and held
Cyrillic. Both read as coverage of a technique nobody had written a sample
for, and both survived every gate the corpus already has, because those gates
ask whether a file exists and whether it is unique, never whether it is what
it says.

The check is one predicate per claim token, and it runs in both directions.
A file whose name carries a token has to satisfy that token's predicate, and
a token nobody claims is removed rather than kept: a predicate with no sample
behind it is the same shape as the sample that had no technique behind it.

Only encoding and alphabet tokens are registered. Those are claims about
bytes, so bytes can answer them. A token like "para" or "mcp" describes what
a payload argues, and nothing here can tell whether an argument was made.
"""

import base64
import binascii
import codecs
import json
import pathlib

from cyberai.core.security.injection_detector import (
    _B64_BLOB,
    _PRINTABLE_RATIO,
    ZERO_WIDTH,
    detect_injection,
)

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CORPUS = _ROOT / "tests" / "corpus"
_MANIFEST = _CORPUS / "manifest.jsonl"

_ID_PREFIX = {"injection": "inj-", "benign": "ben-"}


def _entries() -> list[dict]:
    lines = _MANIFEST.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _in_range(text: str, low: int, high: int) -> bool:
    return any(low <= ord(char) <= high for char in text)


def _holds_base64(text: str) -> bool:
    """A blob that decodes to text, judged the way the detector judges one."""
    for blob in _B64_BLOB.findall(text):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if not decoded:
            continue
        printable = sum(1 for char in decoded if 0x20 <= ord(char) < 0x7F) / len(decoded)
        if printable >= _PRINTABLE_RATIO:
            return True
    return False


def _holds_rot13(text: str) -> bool:
    """ROT13 is ASCII letters, so no codepoint range can see it.

    What the claim means is that rotating the text reveals something the text
    itself does not, and the detector's own pattern list is the reader. A
    sample that matches before rotation is not hiding behind ROT13.
    """
    rotated = codecs.encode(text, "rot13")
    return bool(detect_injection(rotated)["matches"]) and not detect_injection(text)["matches"]


CLAIMS = {
    "ansi": lambda text: "\x1b[" in text,
    "b64": _holds_base64,
    "bidi": lambda text: _in_range(text, 0x202A, 0x202E) or _in_range(text, 0x2066, 0x2069),
    "cyrillic": lambda text: _in_range(text, 0x0400, 0x04FF),
    "fullwidth": lambda text: _in_range(text, 0xFF00, 0xFFEF),
    "rot13": _holds_rot13,
    "zerowidth": lambda text: any(ord(char) in ZERO_WIDTH for char in text),
}


def _claims_of(stem: str) -> list[str]:
    return [token for token in CLAIMS if token in stem]


def _stem(entry: dict) -> str:
    return pathlib.PurePosixPath(entry["path"]).stem


def test_every_name_that_claims_a_technique_holds_it() -> None:
    broken = []
    for entry in _entries():
        text = (_CORPUS / entry["path"]).read_text(encoding="utf-8")
        for token in _claims_of(_stem(entry)):
            if not CLAIMS[token](text):
                broken.append((entry["id"], token))
    assert not broken, f"filename claims a technique the bytes do not carry: {broken}"


def test_every_registered_claim_has_a_sample_behind_it() -> None:
    claimed = {token for entry in _entries() for token in _claims_of(_stem(entry))}
    unused = sorted(set(CLAIMS) - claimed)
    assert not unused, f"predicate with no sample: {unused}; add the sample or drop the token"


def test_the_manifest_is_ordered_by_id() -> None:
    """The order was already sorted and nothing held it there.

    Renaming a sample moves its line, and a manifest that drifts out of order
    turns every later diff into a search. The invariant existed by habit; this
    is the line that makes it hold.
    """
    ids = [entry["id"] for entry in _entries()]
    assert ids == sorted(ids), "manifest lines are not in id order"


def test_the_manifest_id_is_the_filename() -> None:
    """Two names for one sample, so one is derived and neither can drift alone."""
    wrong = [
        (entry["id"], entry["path"])
        for entry in _entries()
        if entry["id"] != _ID_PREFIX[entry["label"]] + _stem(entry)
    ]
    assert not wrong, wrong

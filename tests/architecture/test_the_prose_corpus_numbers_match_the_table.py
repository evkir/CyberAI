"""The page's figures about third-party prose are recomputed from the table.

The corpus behind these numbers is not in the tree and cannot be: sixty
strangers' repositories under sixty licences. For three weeks that made
the figures unpublishable -- a claim nothing could check is a claim nobody
should print. The committed table is what changed that, and these tests are
the reason the numbers are allowed on the page at all.

Each figure is recomputed from the rows and compared to the sentence that
carries it. Membership is not enough: a page holding a dozen numbers almost
certainly holds any plausible one somewhere, so every assertion below reads
the clause that makes the claim rather than the file that contains it.

The last test is the licence argument, stated here a second time on purpose.
The unit tests hold the builder to it; this one holds the artefact, because
the two fail on different days -- a builder that stopped dropping the text
and a fixture rebuilt by hand are not the same accident.
"""

from __future__ import annotations

import json
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_TABLE = _ROOT / "tests" / "fixtures" / "mcp_prose_facts_2026-10-12.jsonl"
_PAGE = _ROOT / "docs" / "redteam" / "mcp-scanning.md"

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"\A[0-9a-f]{40}\Z")

_COUNTED_PROSE = (
    "CONTRIBUTING.md",
    "scripts/build_prose_fact_table.py",
    "tests/unit/test_build_prose_fact_table.py",
)

_SPELLED = {
    55: "fifty-five",
    56: "fifty-six",
    57: "fifty-seven",
    58: "fifty-eight",
    59: "fifty-nine",
    60: "sixty",
    61: "sixty-one",
    62: "sixty-two",
    63: "sixty-three",
    64: "sixty-four",
    65: "sixty-five",
}


def _rows() -> list[dict[str, object]]:
    lines = _TABLE.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _sentence_about(word: str) -> str:
    """The sentence on the page making a claim about the prose channel."""
    page = _PAGE.read_text(encoding="utf-8").replace("\n", " ")
    sentences = [part for part in page.split(". ") if word in part]
    assert len(sentences) == 1, f"{word}: {len(sentences)} sentences, want one"
    return sentences[0]


def test_the_page_counts_the_texts_the_table_holds() -> None:
    """The two figures are recounted from the rows, not found on the page."""
    rows = _rows()
    claim = _sentence_about("distinct instruction texts")

    assert f"{len(rows)} distinct instruction texts" in claim
    assert f"from {len({row['server'] for row in rows})} servers" in claim


def test_every_text_is_reported_without_a_finding() -> None:
    """The claim of INFO everywhere is the table's own tally, in both fields."""
    rows = _rows()
    claim = _sentence_about("distinct instruction texts")

    assert {str(row["severity"]) for row in rows} == {"INFO"}
    assert not [row for row in rows if row["is_finding"]]
    assert "INFO on every one of them with no finding" in claim


def test_the_labels_that_reached_no_tier_are_counted() -> None:
    """Three rows carry a label and none of them is a finding.

    This is the term-alone rule observed rather than restated: a label that
    arrives alone stops below every tier. If a change promotes one of these,
    the page says three and the table says otherwise on the same day.
    """
    rows = _rows()
    labelled = [row for row in rows if row["labels"]]
    tally: dict[str, int] = {}
    for row in labelled:
        for label in row["labels"]:
            tally[str(label)] = tally.get(str(label), 0) + 1
    claim = _sentence_about("carry a label")

    assert len(labelled) == 3
    assert tally == {"encoded_payload": 1, "template_injection": 2}
    assert "Three of them carry a label" in claim


def test_every_row_addresses_a_text_it_does_not_carry() -> None:
    """A reader can fetch what we read, and the row holds none of it.

    Both halves are the commitment the page makes. An address without a
    resolvable commit sends the reader nowhere; a row carrying the prose
    redistributes it, which is the thing this whole arrangement exists to
    avoid.
    """
    rows = _rows()
    fields = {
        "server",
        "repo_url",
        "commit_sha",
        "file_path",
        "sha256",
        "length",
        "ascii",
        "severity",
        "is_finding",
        "labels",
    }

    for row in rows:
        assert set(row) == fields, sorted(set(row) ^ fields)
        assert _SHA256.match(str(row["sha256"]))
        assert _COMMIT.match(str(row["commit_sha"]))
        assert str(row["repo_url"]).startswith("https://")
        assert isinstance(row["length"], int) and row["length"] >= 40


def test_the_licence_argument_counts_repositories_not_servers() -> None:
    """The texts arguing redistribution count what carries a licence.

    Four texts put the corpus at 64, which is the number of servers the table
    holds. A server is a registry entry; a licence belongs to a repository,
    and several of the servers publish out of a repository another one also
    publishes from. Nothing recomputed either figure, so the four agreed with
    each other and with nothing on disk.

    Every spelled count this module knows is read out of each text and held to
    the recomputed one, so a figure drifting in either direction fails here
    rather than being carried into the next rewrite.

    This module states the figure too, and it cannot be read off its own file:
    the table of spellings below would answer every lookup. Its own docstring
    is read instead, which is the only part of it making the claim.

    Each text must still name the figure. A mutant that deleted the count
    rather than changing it survived a run of this test when absence was
    allowed: the text had stopped making the claim, and nothing said so.
    """
    repositories = len({str(row["repo_url"]) for row in _rows()})
    word = _SPELLED[repositories]

    for name in _COUNTED_PROSE:
        text = (_ROOT / name).read_text(encoding="utf-8")
        found = {spelled for spelled in _SPELLED.values() if spelled in text}
        assert found == {word}, f"{name}: {sorted(found)}, want {word}"

    here = {spelled for spelled in _SPELLED.values() if spelled in (__doc__ or "")}
    assert here == {word}, f"this module: {sorted(here)}, want {word}"

"""Every repository path a reader-facing document links to must exist.

README is the first document a reviewer reads and the only one many read at
all. blog/launch-post-draft.md is the other document written for an outside
reader, and it is reached by no gate that looks at its links. Both point at
files in this repository, and a renamed doc leaves a link that returns 404
on GitHub, which reads as abandonment rather than as a typo.

A target resolves against the directory of the document that carries it,
which is what GitHub and a browser both do. A path written from the
repository root resolves correctly in README and resolves to blog/<path>
in the post -- the same string, valid in one file and broken in the other.
That is the defect this gate was widened to catch, and resolving everything
against the repository root would have hidden it.

Only in-repository targets are checked. External URLs are not: a test that
reaches the network fails on a plane, on a rate limit, and on someone else's
outage, and a reviewer who has watched it fail for none of those reasons
stops reading it. Link rot on external sites is real, and it is not a
problem an architecture test can solve honestly.

Anchors are stripped before resolving. A link into a heading of an existing
file is a valid link; whether that heading still exists is a question about
the target document's contents, and pinning it here would fail on every
edit to somebody else's headings.
"""

import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_DOCS = (
    _ROOT / "README.md",
    _ROOT / "blog" / "launch-post-draft.md",
)

# Markdown link targets that are repository-relative: no scheme, no leading
# slash, no mailto. Anything with '://' is external and out of scope here.
_LINK = re.compile(r"\]\(([^)\s]+)\)")


def _repo_targets(text: str) -> list[str]:
    out = []
    for raw in _LINK.findall(text):
        if "://" in raw or raw.startswith(("#", "mailto:", "/")):
            continue
        out.append(raw.split("#", 1)[0])
    return [t for t in out if t]


def test_reader_facing_links_resolve() -> None:
    missing: list[str] = []
    for doc in _DOCS:
        targets = _repo_targets(doc.read_text(encoding="utf-8"))
        assert targets, f"no repository-relative links in {doc.name} -- regex broke"
        gone = sorted({t for t in targets if not (doc.parent / t).exists()})
        missing += [f"{doc.name} -> {t}" for t in gone]
    assert not missing, missing

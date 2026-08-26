"""Every repository path README links to must exist.

README is the first document a reviewer reads and the only one many read at
all. It links to twenty-odd files in this repository, and until now nothing
checked that any of them was still there: a renamed doc leaves a link that
returns 404 on GitHub, which reads as abandonment rather than as a typo.

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
_README = _ROOT / "README.md"

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


def test_readme_links_resolve() -> None:
    targets = _repo_targets(_README.read_text(encoding="utf-8"))
    assert targets, "no repository-relative links found -- the regex broke"
    missing = sorted({t for t in targets if not (_ROOT / t).exists()})
    assert not missing, missing

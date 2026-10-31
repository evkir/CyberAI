"""Report numerals written as words in a prose page, so a guard can read them.

A measurement spelled out is invisible to every tool that checks the tree
against the page. `Five directories are clean throughout` is a claim about
`[tool.mypy] files`, and a regular expression looking for digits walks past
it. The page can then drift from the manifest for as long as nobody rereads
the sentence, which is exactly the failure the digit guards were written to
prevent.

Not every spelled numeral is a measurement. Three kinds share the same words
and only one of them may be rewritten:

- a pronoun -- `the one that mattered`, `added to one of them`. English spells
  these the same way as the numeral one, and rewriting them produces nonsense.
  The list is a filter on the word, not on the line: `one more call-arg error
  against the older one` loses its pronoun and keeps its count.
- a record of a past day -- `Four modules were carried into the scope`. The
  sentence is history, the number cannot move again, and a guard holding it
  against today's tree would red on a true page.
- a live count -- `Two modules import yaml`. The tree answers it now, so it
  belongs in digits with a guard beside it, or it does not belong on the page.

This tool separates the first class mechanically and leaves the other two to
a reader: the pronoun forms are a closed list, and anything else is reported
with its line so a person decides which of the remaining two it is. The output
is a worklist, not a verdict, so an empty report is the only green state and
the exit status says nothing about whether the page is honest.
"""

import argparse
import pathlib
import re
import sys

_NUMERALS = (
    "one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|"
    "fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|"
    "fifty|sixty|seventy|eighty|ninety|hundred"
)
_SPELLED = re.compile(rf"\b({_NUMERALS})\b", re.IGNORECASE)

# `one` doubles as a pronoun in English. These are the shapes that are never a
# count, matched on the word before or after it.
_PRONOUN = re.compile(
    r"\b(?:"
    r"(?:the|that|this|which|another|shared|older|newer|only|same)\s+one\b"
    r"|one\s+(?:of|that|carrying)\b"
    r"|not\s+one\b"
    r"|no\s+one\b"
    r")",
    re.IGNORECASE,
)

_FENCE = re.compile(r"^\s*```")


def prose_lines(text: str) -> list[tuple[int, str]]:
    """Numbered lines outside fenced code blocks."""
    lines = []
    fenced = False
    for number, line in enumerate(text.splitlines(), start=1):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            lines.append((number, line))
    return lines


def spelled_counts(line: str) -> list[str]:
    """Spelled numerals in a line, with the pronoun shapes removed first."""
    return [match.group(0) for match in _SPELLED.finditer(_PRONOUN.sub("", line))]


def pages(target: pathlib.Path) -> list[pathlib.Path]:
    """Markdown under a directory, or the file itself.

    A step naming every page by hand is a list that rots: the page added
    tomorrow is not on it, and nothing says so.
    """
    return sorted(target.rglob("*.md")) if target.is_dir() else [target]


def report(page: pathlib.Path) -> list[str]:
    findings = []
    for number, line in prose_lines(page.read_text(encoding="utf-8")):
        words = spelled_counts(line)
        if words:
            findings.append(f"{page}:{number}: {', '.join(words)}: {line.strip()}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pages", nargs="+", type=pathlib.Path)
    arguments = parser.parse_args()
    targets = [page for target in arguments.pages for page in pages(target)]
    findings = [finding for page in targets for finding in report(page)]
    for finding in findings:
        print(finding)
    print(
        f"{len(findings)} lines carry a spelled numeral outside code blocks "
        f"across {len(targets)} pages"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

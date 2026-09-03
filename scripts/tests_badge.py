#!/usr/bin/env python3
"""Read the collected test count, and write it into the README badge.

The badge number is measured, not remembered, and the gate that checks it has
existed since the badge said 2252 while the suite held 2440. What did not
exist was the other half: every commit that adds a test leaves the gate red
until someone runs a collection by hand, reads the number off the screen and
retypes it. Four commits out of four did exactly that in one day, and twice
the number predicted by arithmetic was off by one from the number measured.

The count and the badge reader live here rather than in the test so that the
number written and the number checked come from one function. A second
counter -- a script with its own selection, a test with its own -- would agree
until the day the selection changed in one of them, and would then disagree
about a figure the README states as fact.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
README = _ROOT / "README.md"

# The same selection CI runs, so the number describes the suite people gate on.
MARKERS = "not slow and not smoke"

_BADGE = re.compile(r"badge/tests-(\d+)")


def collected() -> int:
    """How many tests the suite collects under the gated selection."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "-m",
            MARKERS,
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"(\d+)(?:/\d+)? tests? collected", result.stdout)
    assert match, f"could not read a collection count from pytest:\n{result.stdout[-2000:]}"
    return int(match.group(1))


def claimed(readme: pathlib.Path = README) -> int:
    """The number the badge currently states."""
    text = readme.read_text(encoding="utf-8")
    match = _BADGE.search(text)
    assert match, "the README carries no tests badge"
    return int(match.group(1))


def rewrite(count: int, readme: pathlib.Path = README) -> bool:
    """Put count into the badge. True when the file changed."""
    text = readme.read_text(encoding="utf-8")
    updated = _BADGE.sub(f"badge/tests-{count}", text, count=1)
    if updated == text:
        return False
    readme.write_text(updated, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="report a stale badge without touching the README",
    )
    arguments = parser.parse_args(argv)
    count = collected()
    if arguments.check:
        if claimed() == count:
            print(f"badge is current: {count}")
            return 0
        print(f"badge says {claimed()}, the suite collects {count}")
        return 1
    if rewrite(count):
        print(f"badge set to {count}")
    else:
        print(f"badge already said {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

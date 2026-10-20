#!/usr/bin/env python3
"""Remove the bytecode caches a mutation run leaves behind.

A mutation harness writes a file, runs the suite, and writes the original
back. Both writes can land inside one granule of the filesystem's mtime, and
`__pycache__` is invalidated by mtime and size. A mutant of the same length as
the line it replaced therefore leaves a cache entry that outlives it: the
source on disk holds the original, `grep` and a direct import agree with the
source, and `pytest` imports the mutant. The isolated run that follows is
green, because it reruns the same stale module; the full gate is where the two
disagree, and the value it fails on cannot be found anywhere in the tree.

The sweep belongs here rather than in each harness. Harnesses are written for
one mutant and deleted the same day, so a cleanup step copied into one of them
is absent from the next, and its absence looks exactly like a passing run.
What a harness imports instead is this: one function, called from the `finally`
that restores the file, named in the one place a correction can be made.

`--check` reports rather than removes, for a gate that wants to say a tree is
clean before a harness starts: a cache present before the run is a cache whose
age is unknown, and a mutation measured against it measures nothing.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import sys
from collections.abc import Iterator

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def caches(root: pathlib.Path) -> Iterator[pathlib.Path]:
    """Yield every `__pycache__` directory under `root`, deepest first.

    Depth order matters for the count, not for the removal: either order leaves
    the tree clean, because removing a parent takes a nested cache with it. A
    shallow-first walk then finds the nested one already gone and declines to
    count it, and the number this reports is smaller than the number that was
    there. Deepest first counts each directory it removed.
    """
    found = [path for path in root.rglob("__pycache__") if path.is_dir()]
    return iter(sorted(found, key=lambda path: len(path.parts), reverse=True))


def sweep(root: pathlib.Path) -> int:
    """Remove every bytecode cache under `root`; return how many were removed.

    Nothing here catches a missing directory. The walk and the removals run
    back to back in one process, and a nested cache taken out with its parent
    is already excluded by removing the deepest first, so the only way a listed
    directory goes missing is that something else is writing to the tree while
    a mutant is being measured. That invalidates the measurement, and this is
    called from the `finally` that restores the file: an exception there is
    read, while a swallowed one leaves a harness reporting a clean sweep of a
    tree it no longer controls.
    """
    removed = 0
    for cache in caches(root):
        shutil.rmtree(cache)
        removed += 1
    return removed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=pathlib.Path, default=_ROOT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report caches without removing them; non-zero exit when any exist",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    if args.check:
        present = list(caches(root))
        if not present:
            print("pycache: none")
            return 0
        print(f"pycache: {len(present)} directories present")
        for cache in present:
            print(f"  {cache.relative_to(root).as_posix()}")
        print("Run scripts/pycache_sweep.py before measuring a mutant.")
        return 1

    removed = sweep(root)
    print(f"pycache: removed {removed} directories")
    return 0


if __name__ == "__main__":
    sys.exit(main())

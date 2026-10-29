#!/usr/bin/env python3
"""Ask which repositories behind the committed fact table still answer.

Why this exists. Every row of the fact table names a repository and a commit,
and invites a reader to fetch the text at that commit and compare the digest.
The commits were the heads of those checkouts on the day the corpus was read.
Other people's repositories move: a file can leave the path it was read from,
an account can be renamed, a repository can be taken down. The table stays
true as a record of what was read; what it cannot say is whether the reader
following it today arrives anywhere.

This measures that and nothing else. It asks each distinct repository whether
it answers, which is a weaker question than whether the commit is still
reachable -- a rewritten history answers here and would fail a fetch -- and a
cheap one: git ls-remote reads refs and transfers no tree. A repository that
answers is not a promise that the commit does; a repository that does not is
proof that it cannot.

The probe is the one the scanner's own target selection uses, so the three
states this prints are the states that decide whether a target is audited at
all, rather than a second opinion written beside it.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys
from collections.abc import Callable, Iterable

from cyberai.agents.mcp_scan.registry import Reachability, probe_repository


def distinct_repositories(rows: Iterable[dict[str, object]]) -> list[str]:
    """The repositories the table names, each once, in the order they appear.

    Several servers publish out of one repository, so a probe per row would
    ask the same host the same question many times and report a population
    larger than the one that exists. The key matches the one target selection
    uses, so the two agree on what counts as the same repository.
    """
    seen: dict[str, str] = {}
    for row in rows:
        url = str(row.get("repo_url") or "")
        if not url:
            continue
        key = url.rstrip("/").lower()
        if key not in seen:
            seen[key] = url
    return list(seen.values())


def probe_all(
    urls: Iterable[str],
    probe: Callable[[str], Reachability] | None = None,
) -> dict[str, Reachability]:
    """Ask about each repository once and keep what it answered.

    Resolved here rather than bound as a default: a default is captured at
    import and makes the only network call on this path impossible to
    substitute, which would let a test reach the network while appearing to
    measure the arithmetic.
    """
    ask = probe if probe is not None else probe_repository
    return {url: ask(url) for url in urls}


def tally(answers: dict[str, Reachability]) -> dict[str, int]:
    """How many repositories gave each answer, every state named.

    A state with no repositories in it is printed as zero rather than left
    out: a reader comparing two runs needs to see that nothing timed out,
    not infer it from a missing line.
    """
    counted = collections.Counter(answers.values())
    return {state.value: counted.get(state, 0) for state in Reachability}


def main(argv: list[str] | None = None) -> int:
    """Probe every repository the table names and report what answered."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("table", type=pathlib.Path, help="JSONL fact table to read")
    parser.add_argument(
        "--limit", type=int, default=None, help="probe at most this many repositories"
    )
    args = parser.parse_args(argv)

    lines = args.table.read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in lines if line.strip()]
    urls = distinct_repositories(rows)
    if args.limit is not None:
        urls = urls[: args.limit]

    answers = probe_all(urls)
    counts = tally(answers)
    print(f"rows {len(rows)}, repositories {len(urls)}")
    for state, count in counts.items():
        print(f"{state} {count}")
    for url, state in answers.items():
        if state is not Reachability.ALIVE:
            print(f"{state.value} {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

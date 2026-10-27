#!/usr/bin/env python3
"""Reduce a local corpus of third-party server instructions to a table of facts.

Why this exists. The instructions prose of other people's MCP servers is the
only material on which this scanner's behaviour against legitimate text can be
measured: the registry showcase line is capped at a hundred characters and
carries no directives, so a false-positive rate taken on it describes shop
windows rather than prose. The corpus itself is sixty-four strangers' source
files under sixty-four licences, and committing it would mean redistributing
their code to publish a number about our own detector.

What is committed instead is this reduction. Every row carries the address of
the text (repository, commit, path), a digest of it, its length, and this
scanner's verdict on it -- and not one character of the text. A reader who
wants to check the number fetches the files themselves at the commit named
here and runs the same scan; the digest says whether they fetched what we
read. Redistribution does not happen, and the claim stops being unfalsifiable.

Why the dedup key is the pair of server and text, measured rather than
chosen. The corpus holds two hundred and one extracted texts. Grouping by text
alone collapses to a hundred and nineteen, because packages in one monorepo
repeat an identical paragraph; grouping by repository and path gives a hundred
and twenty-three, because one checkout backs several registry entries. Neither
number answers the question the corpus was built for, which is how many
distinct pieces of server prose this detector has been shown. The pair does,
and it is the key the collection run reported.

Why the scan runs with an empty tool list, which is not an oversight. The
texts come out of source files; there is no live server here to answer a
tools/list call, so every snake_case name in the prose is unadvertised by
construction. That conjunction was a false positive until the summons gate
was scoped to a single sentence, and the one finding this corpus produced
disappeared with it. Running the empty list is therefore the measurement:
it is the worst case for the half of the gate that reads the tool surface.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from typing import Any

from cyberai.agents.mcp_scan.instructions import analyze_instructions

_CLONE_SLUG = re.compile(r"[^a-zA-Z0-9]+")


def clone_dir(clones: pathlib.Path, server: str) -> pathlib.Path:
    """Where the collection run put this server's checkout.

    The rule is the collection script's own: every run of characters that is
    not a letter or a digit becomes a single underscore, and the case of the
    name is kept. Lowercasing here would miss the servers whose registry name
    carries capitals, and it would miss them quietly -- the directory simply
    would not be found for a hundred and seventeen of two hundred and one rows.
    """
    return clones / _CLONE_SLUG.sub("_", server)


def head_commit(checkout: pathlib.Path) -> str:
    """The commit the corpus was read at, or empty when the checkout is gone."""
    done = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    head = done.stdout.strip()
    return head if len(head) == 40 else ""


def unique_texts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The corpus reduced to one row per distinct piece of a server's prose."""
    seen: set[tuple[str, str]] = set()
    kept: list[dict[str, Any]] = []
    for row in rows:
        key = (str(row["server"]), str(row["text"]))
        if key in seen:
            continue
        seen.add(key)
        kept.append(row)
    return kept


def fact(row: dict[str, Any], commit: str) -> dict[str, Any]:
    """One row of the table: where the text is, what it hashes to, our verdict."""
    text = str(row["text"])
    scan = analyze_instructions(text, [])
    labels = sorted(
        {str(m.get("type", "?")) for m in scan.matches}
        | {str(m.get("type", "?")) for m in scan.mcp_matches}
    )
    return {
        "server": str(row["server"]),
        "repo_url": str(row["repo"]),
        "commit_sha": commit,
        "file_path": str(row["path"]),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "length": len(text),
        "ascii": text.isascii(),
        "severity": scan.severity,
        "is_finding": scan.is_finding,
        "labels": labels,
    }


def build(corpus: pathlib.Path, clones: pathlib.Path) -> list[dict[str, Any]]:
    """Read the corpus, scan each distinct text, return the table."""
    lines = corpus.read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in lines if line.strip()]
    heads: dict[str, str] = {}
    table: list[dict[str, Any]] = []
    for row in unique_texts(rows):
        server = str(row["server"])
        if server not in heads:
            heads[server] = head_commit(clone_dir(clones, server))
        table.append(fact(row, heads[server]))
    return table


def main(argv: list[str] | None = None) -> int:
    """Write the fact table and report what it holds."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("corpus", type=pathlib.Path, help="JSONL of extracted instructions")
    parser.add_argument(
        "clones", type=pathlib.Path, help="directory of checkouts the corpus was read from"
    )
    parser.add_argument("destination", type=pathlib.Path, help="JSONL to write")
    args = parser.parse_args(argv)

    table = build(args.corpus, args.clones)
    args.destination.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in table) + "\n",
        encoding="utf-8",
    )
    servers = {row["server"] for row in table}
    unresolved = sum(1 for row in table if not row["commit_sha"])
    findings = sum(1 for row in table if row["is_finding"])
    print(
        f"rows {len(table)}, servers {len(servers)}, findings {findings}, without commit {unresolved}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Target selection from the published MCP server registry.

Selection reads registry metadata and the published repository behind each
entry. It never connects to the servers themselves: a target is chosen here so
that its *source* can be audited statically, and connecting to someone else's
running instance is a different act under a different authorization.

Reachability is measured before selection, not after. A registry entry can be
active and latest and still point at a repository that is not there, so an
unchecked list silently carries entries that cannot be audited at all.

Two limits are deliberate, and both are properties of the host rather than of
this code:

* A repository that is private and one that was deleted answer identically.
  ``NOT_FOUND`` therefore means unreachable, never deleted, and nothing here
  may report the stronger claim.
* A refusal to answer because too many questions were asked is not an answer.
  Rate limiting yields ``UNKNOWN``, which is excluded from the chosen set and
  counted apart from the unreachable one -- raising the rate is not a remedy
  this module offers.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cyberai.core.sandbox import operator_home, run_sealed

_OFFICIAL = "io.modelcontextprotocol.registry/official"
_LS_REMOTE_TIMEOUT = 60.0


class Reachability(str, Enum):
    """Whether the repository behind a registry entry answered."""

    ALIVE = "alive"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Candidate:
    """One registry entry that named a GitHub repository."""

    name: str
    url: str


@dataclass
class Selection:
    """What selection kept, what it dropped, and why."""

    chosen: list[Candidate] = field(default_factory=list)
    unreachable: list[Candidate] = field(default_factory=list)
    unknown: list[Candidate] = field(default_factory=list)
    candidates: int = 0
    distinct_urls: int = 0

    @property
    def dropped(self) -> int:
        """Entries that survived filtering but could not be audited."""
        return len(self.unreachable) + len(self.unknown)

    def summary(self) -> str:
        """One line stating every count, including the ones that are zero."""
        return (
            f"{self.candidates} candidates, {self.distinct_urls} distinct repositories: "
            f"{len(self.chosen)} chosen, {len(self.unreachable)} unreachable, "
            f"{len(self.unknown)} unknown"
        )


def iter_candidates(rows: Iterable[dict[str, Any]]) -> Iterator[Candidate]:
    """Yield active, latest entries that name a GitHub repository.

    An entry missing the official metadata block is not latest and not active
    by omission: absence is not a claim, so it is skipped rather than assumed.
    """
    for row in rows:
        meta = (row.get("_meta") or {}).get(_OFFICIAL) or {}
        if not meta.get("isLatest") or meta.get("status") != "active":
            continue
        server = row.get("server") or {}
        repo = server.get("repository") or {}
        name, url = server.get("name"), repo.get("url")
        if repo.get("source") == "github" and name and url:
            yield Candidate(name=str(name), url=str(url))


def probe_repository(url: str) -> Reachability:
    """Ask the host whether a repository answers, without cloning it.

    ``git ls-remote`` reads refs and transfers no tree, which keeps the cost of
    checking far below the cost of the clone it protects.

    The child runs sealed, so it never inherits the operator's environment, but
    it is given the operator's home: a git that cannot read its own
    configuration reports every miss as an authentication failure and collapses
    the three states this function exists to tell apart.
    """
    try:
        done = run_sealed(
            ["git", "ls-remote", "--heads", url],
            timeout=_LS_REMOTE_TIMEOUT,
            home=operator_home(),
            extra_env={"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"},
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (subprocess.TimeoutExpired, OSError):
        return Reachability.UNKNOWN
    if done.returncode == 0:
        return Reachability.ALIVE
    if "not found" in (done.stderr or "").lower():
        return Reachability.NOT_FOUND
    return Reachability.UNKNOWN


def select_targets(
    rows: Iterable[dict[str, Any]],
    probe: Callable[[str], Reachability] | None = None,
    limit: int | None = None,
) -> Selection:
    """Choose auditable targets, checking each repository before choosing it.

    Distinct repositories are probed once each. Several registry entries can
    name one repository, so probing per entry would ask the same question many
    times and report a population larger than the one that exists.
    """
    # Resolved here rather than bound as a default: a default is captured when
    # this module is imported, which makes the only network call on the path
    # impossible to substitute from outside and lets a test reach the network
    # while appearing to measure the decision.
    ask = probe if probe is not None else probe_repository
    selection = Selection()
    seen: dict[str, Reachability] = {}
    for candidate in iter_candidates(rows):
        if limit is not None and selection.candidates >= limit:
            break
        selection.candidates += 1
        key = candidate.url.rstrip("/").lower()
        if key not in seen:
            seen[key] = ask(candidate.url)
            selection.distinct_urls += 1
        state = seen[key]
        if state is Reachability.ALIVE:
            selection.chosen.append(candidate)
        elif state is Reachability.NOT_FOUND:
            selection.unreachable.append(candidate)
        else:
            selection.unknown.append(candidate)
    return selection

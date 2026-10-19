"""Selection asks whether a repository answers before it chooses it.

The probe is injected in every test here: selection is a decision about a
population, and the decision is what these tests argue about. A test that
reached the network would measure GitHub's availability on the day it ran.
"""

from __future__ import annotations

import subprocess
from typing import Any
from unittest.mock import patch

from cyberai.agents.mcp_scan.registry import (
    Candidate,
    Reachability,
    iter_candidates,
    probe_repository,
    select_targets,
)

_OFFICIAL = "io.modelcontextprotocol.registry/official"
_SEALED = "cyberai.agents.mcp_scan.registry.run_sealed"


def _row(
    name: str,
    url: str | None = "https://github.com/owner/repo",
    *,
    status: str = "active",
    latest: bool = True,
    source: str = "github",
) -> dict[str, Any]:
    """One registry entry, shaped like the dump the official registry serves."""
    repository: dict[str, Any] = {}
    if url is not None:
        repository = {"source": source, "url": url}
    return {
        "_meta": {_OFFICIAL: {"isLatest": latest, "status": status}},
        "server": {"name": name, "repository": repository},
    }


def test_an_entry_that_is_not_latest_is_not_a_candidate() -> None:
    assert list(iter_candidates([_row("a", latest=False)])) == []


def test_an_entry_that_is_not_active_is_not_a_candidate() -> None:
    assert list(iter_candidates([_row("a", status="deleted")])) == []


def test_an_entry_without_the_official_block_is_not_assumed_active() -> None:
    """Absence is not a claim: a missing block is skipped, not read as active."""
    assert list(iter_candidates([{"server": {"name": "a", "repository": {}}}])) == []


def test_a_repository_that_is_not_on_github_is_not_a_candidate() -> None:
    assert list(iter_candidates([_row("a", source="gitlab")])) == []


def test_an_entry_naming_no_repository_is_not_a_candidate() -> None:
    assert list(iter_candidates([_row("a", url=None)])) == []


def test_a_reachable_repository_is_chosen() -> None:
    selection = select_targets([_row("a")], probe=lambda _: Reachability.ALIVE)
    assert selection.chosen == [Candidate("a", "https://github.com/owner/repo")]
    assert selection.unreachable == []
    assert selection.unknown == []


def test_an_unreachable_repository_is_reported_not_silently_dropped() -> None:
    """The gap between what the registry lists and what it serves is the finding."""
    selection = select_targets([_row("a")], probe=lambda _: Reachability.NOT_FOUND)
    assert selection.chosen == []
    assert [c.name for c in selection.unreachable] == ["a"]
    assert selection.candidates == 1


def test_an_unanswered_probe_is_not_a_milder_unreachable() -> None:
    """UNKNOWN is counted apart: the host declined, which is not an answer."""
    selection = select_targets([_row("a")], probe=lambda _: Reachability.UNKNOWN)
    assert selection.chosen == []
    assert selection.unreachable == []
    assert [c.name for c in selection.unknown] == ["a"]


def test_one_repository_behind_several_entries_is_asked_once() -> None:
    """Probing per entry would ask the same question many times over."""
    asked: list[str] = []

    def probe(url: str) -> Reachability:
        asked.append(url)
        return Reachability.NOT_FOUND

    rows = [_row("a"), _row("b"), _row("c")]
    selection = select_targets(rows, probe=probe)
    assert asked == ["https://github.com/owner/repo"]
    assert selection.candidates == 3
    assert selection.distinct_urls == 1
    assert len(selection.unreachable) == 3


def test_the_same_repository_under_a_different_spelling_is_one_repository() -> None:
    """A trailing slash and a capital letter do not make a second target."""
    rows = [_row("a", "https://github.com/Owner/Repo"), _row("b", "https://github.com/owner/repo/")]
    selection = select_targets(rows, probe=lambda _: Reachability.ALIVE)
    assert selection.distinct_urls == 1
    assert len(selection.chosen) == 2


def test_the_limit_stops_counting_candidates_not_chosen_ones() -> None:
    """The limit bounds the questions asked, so it bounds candidates seen."""
    rows = [_row(name, f"https://github.com/owner/{name}") for name in ("a", "b", "c")]
    selection = select_targets(rows, probe=lambda _: Reachability.ALIVE, limit=2)
    assert selection.candidates == 2
    assert [c.name for c in selection.chosen] == ["a", "b"]


def test_the_summary_states_every_count_including_the_empty_ones() -> None:
    """A zero that goes unprinted reads as a question that was never asked."""
    states = iter([Reachability.ALIVE, Reachability.NOT_FOUND])
    rows = [_row("a", "https://github.com/owner/a"), _row("b", "https://github.com/owner/b")]
    selection = select_targets(rows, probe=lambda _: next(states))
    summary = selection.summary()
    assert "2 candidates" in summary
    assert "1 chosen" in summary
    assert "1 unreachable" in summary
    assert "0 unknown" in summary
    assert selection.dropped == 1


class _Done:
    """The shape run_sealed returns, reduced to what the probe reads."""

    def __init__(self, returncode: int, stderr: str = "") -> None:
        self.returncode = returncode
        self.stderr = stderr


def _answers(done: object) -> Any:
    return lambda *args, **kwargs: done


def test_refs_that_come_back_mean_the_repository_answered() -> None:
    with patch(_SEALED, _answers(_Done(0))):
        assert probe_repository("https://github.com/o/r") is Reachability.ALIVE


def test_a_host_saying_it_has_no_such_repository_is_unreachable() -> None:
    stderr = "fatal: repository 'https://github.com/o/r/' not found\n"
    with patch(_SEALED, _answers(_Done(128, stderr))):
        assert probe_repository("https://github.com/o/r") is Reachability.NOT_FOUND


def test_a_refusal_to_answer_is_not_an_answer() -> None:
    """Auth failures and rate limits say nothing about whether the repo exists."""
    stderr = "fatal: Authentication failed for 'https://github.com/o/r/'\n"
    with patch(_SEALED, _answers(_Done(128, stderr))):
        assert probe_repository("https://github.com/o/r") is Reachability.UNKNOWN


def test_a_probe_that_times_out_is_unknown_not_unreachable() -> None:
    def raise_timeout(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="git", timeout=60)

    with patch(_SEALED, raise_timeout):
        assert probe_repository("https://github.com/o/r") is Reachability.UNKNOWN


def test_a_git_that_cannot_be_run_at_all_is_unknown() -> None:
    def raise_oserror(*args: Any, **kwargs: Any) -> Any:
        raise OSError("git not on PATH")

    with patch(_SEALED, raise_oserror):
        assert probe_repository("https://github.com/o/r") is Reachability.UNKNOWN


def test_the_probe_is_given_the_operator_home_and_runs_sealed() -> None:
    """Without the home, git misreads every miss and the states collapse."""
    seen: dict[str, Any] = {}

    def record(argv: Any, **kwargs: Any) -> Any:
        seen["argv"] = list(argv)
        seen.update(kwargs)
        return _Done(0)

    with patch(_SEALED, record):
        probe_repository("https://github.com/o/r")
    assert seen["argv"][:2] == ["git", "ls-remote"]
    assert seen["home"] is not None

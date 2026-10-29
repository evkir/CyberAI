"""The reachability report counts repositories, and asks about each one once.

The arithmetic is what can be tested without a network, and it is the part
that was wrong in the prose this report exists to correct: the table holds
more rows than repositories and more servers than repositories, and a report
that counted either would describe a population that does not exist.

The probe itself is substituted everywhere below. A test that reached the
network would measure other people's uptime and fail on a train.
"""

from __future__ import annotations

import importlib.util
import pathlib
import types

import pytest

from cyberai.agents.mcp_scan.registry import Reachability

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "probe_fact_table_reachability.py"


def _report() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("probe_fact_table_reachability", _SCRIPT)
    assert spec and spec.loader, f"no module at {_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def report() -> types.ModuleType:
    return _report()


def _rows(*urls: str) -> list[dict[str, object]]:
    return [{"repo_url": url, "server": f"s{index}"} for index, url in enumerate(urls)]


def test_one_repository_behind_several_servers_is_named_once(
    report: types.ModuleType,
) -> None:
    """Four servers publishing from one repository are one repository.

    This is the shape the real table has: one owner carries six of them, and
    a renamed account appears twice over one tree. Counting rows would put
    the corpus at the number of texts, counting servers at the number of
    registry entries, and neither is the number of licences.
    """
    rows = _rows(
        "https://github.com/one/repo",
        "https://github.com/one/repo",
        "https://github.com/two/repo",
    )

    assert report.distinct_repositories(rows) == [
        "https://github.com/one/repo",
        "https://github.com/two/repo",
    ]


def test_the_same_address_written_two_ways_is_one_repository(
    report: types.ModuleType,
) -> None:
    """The key is the one target selection uses: trailing slash and case.

    If this report and the selection disagreed about what counts as the same
    repository, the number printed here would not be the number of hosts the
    scanner would ask about.
    """
    rows = _rows(
        "https://github.com/One/Repo",
        "https://github.com/one/repo/",
        "https://github.com/one/other",
    )

    kept = report.distinct_repositories(rows)

    assert kept == ["https://github.com/One/Repo", "https://github.com/one/other"]


def test_a_row_without_a_repository_is_not_a_repository(
    report: types.ModuleType,
) -> None:
    """An empty address is dropped rather than probed as the empty string."""
    rows: list[dict[str, object]] = [{"repo_url": ""}, {"server": "s"}]
    rows.extend(_rows("https://github.com/one/repo"))

    assert report.distinct_repositories(rows) == ["https://github.com/one/repo"]


def test_each_repository_is_asked_once(report: types.ModuleType) -> None:
    """The probe is called per repository, not per row.

    Sixty questions against sixty-four entries is the whole saving, and the
    hosts on the other end see the difference.
    """
    asked: list[str] = []

    def probe(url: str) -> Reachability:
        asked.append(url)
        return Reachability.ALIVE

    urls = ["https://github.com/one/repo", "https://github.com/two/repo"]
    answers = report.probe_all(urls, probe=probe)

    assert asked == urls
    assert set(answers) == set(urls)


def test_every_state_is_reported_including_the_empty_ones(
    report: types.ModuleType,
) -> None:
    """A state nothing reached prints zero rather than vanishing.

    A run where nothing timed out and a run where the timeouts were dropped
    from the report read identically otherwise, and only one of them says
    the network behaved.
    """
    answers = {
        "a": Reachability.ALIVE,
        "b": Reachability.ALIVE,
        "c": Reachability.NOT_FOUND,
    }

    assert report.tally(answers) == {"alive": 2, "not_found": 1, "unknown": 0}

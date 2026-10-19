"""CLI surface of `cyberai registry-targets`: what it prints and what it refuses.

The probe is patched out in every case. What is under test is how a selection
is rendered and how a malformed dump is handled, not whether a host on the
network answered on the day the suite ran.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

from click.testing import CliRunner

from cyberai.__main__ import cli
from cyberai.agents.mcp_scan.registry import Reachability

_OFFICIAL = "io.modelcontextprotocol.registry/official"
_PROBE = "cyberai.agents.mcp_scan.registry.probe_repository"


def _row(name: str, url: str) -> dict[str, Any]:
    return {
        "_meta": {_OFFICIAL: {"isLatest": True, "status": "active"}},
        "server": {"name": name, "repository": {"source": "github", "url": url}},
    }


def _dump(tmp_path: Path, *rows: dict[str, Any]) -> str:
    path = tmp_path / "registry.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return str(path)


def _states(*answers: Reachability) -> Callable[[str], Reachability]:
    """Hand out one answer per distinct repository, in order."""
    it = iter(answers)
    return lambda _url: next(it)


def test_it_prints_the_chosen_and_the_unreachable(tmp_path: Path) -> None:
    dump = _dump(
        tmp_path,
        _row("alpha", "https://github.com/owner/alpha"),
        _row("beta", "https://github.com/owner/beta"),
    )
    with patch(_PROBE, _states(Reachability.ALIVE, Reachability.NOT_FOUND)):
        result = CliRunner().invoke(cli, ["registry-targets", dump])
    assert result.exit_code == 0, result.output
    assert "alpha" in result.output
    # The unreachable one is named, not merely counted: a number alone leaves
    # the reader unable to say which entry the registry could not serve.
    assert "unreachable" in result.output
    assert "beta" in result.output


def test_an_unanswered_probe_is_labelled_as_its_own_state(tmp_path: Path) -> None:
    dump = _dump(tmp_path, _row("alpha", "https://github.com/owner/alpha"))
    with patch(_PROBE, _states(Reachability.UNKNOWN)):
        result = CliRunner().invoke(cli, ["registry-targets", dump])
    assert result.exit_code == 0, result.output
    # The summary names every count, zeros included, so the state is read off
    # the entry's own line rather than off the presence of a word.
    assert "0 unreachable, 1 unknown" in result.output
    assert "unknown alpha" in result.output


def test_the_json_exit_carries_all_three_sets(tmp_path: Path) -> None:
    dump = _dump(
        tmp_path,
        _row("alpha", "https://github.com/owner/alpha"),
        _row("beta", "https://github.com/owner/beta"),
        _row("gamma", "https://github.com/owner/gamma"),
    )
    with patch(
        _PROBE,
        _states(Reachability.ALIVE, Reachability.NOT_FOUND, Reachability.UNKNOWN),
    ):
        result = CliRunner().invoke(cli, ["registry-targets", dump, "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["candidates"] == 3
    assert payload["distinct_urls"] == 3
    assert [c["name"] for c in payload["chosen"]] == ["alpha"]
    assert [c["name"] for c in payload["unreachable"]] == ["beta"]
    assert [c["name"] for c in payload["unknown"]] == ["gamma"]


def test_the_limit_bounds_the_questions_asked(tmp_path: Path) -> None:
    dump = _dump(
        tmp_path,
        _row("alpha", "https://github.com/owner/alpha"),
        _row("beta", "https://github.com/owner/beta"),
    )
    asked: list[str] = []

    def probe(url: str) -> Reachability:
        asked.append(url)
        return Reachability.ALIVE

    with patch(_PROBE, probe):
        result = CliRunner().invoke(cli, ["registry-targets", dump, "--limit", "1"])
    assert result.exit_code == 0, result.output
    assert len(asked) == 1


def test_a_line_that_is_not_an_object_is_refused_by_position(tmp_path: Path) -> None:
    """A dump of the wrong shape names the line, so it can be found and fixed."""
    path = tmp_path / "registry.jsonl"
    path.write_text(
        json.dumps(_row("a", "https://github.com/o/a")) + "\n[1, 2]\n", encoding="utf-8"
    )
    with patch(_PROBE, _states(Reachability.ALIVE)):
        result = CliRunner().invoke(cli, ["registry-targets", str(path)])
    assert result.exit_code != 0
    assert ":2" in result.output


def test_a_missing_dump_is_refused_before_anything_is_probed(tmp_path: Path) -> None:
    asked: list[str] = []

    def probe(url: str) -> Reachability:
        asked.append(url)
        return Reachability.ALIVE

    with patch(_PROBE, probe):
        result = CliRunner().invoke(cli, ["registry-targets", str(tmp_path / "absent.jsonl")])
    assert result.exit_code != 0
    assert asked == []


def test_a_blank_line_is_not_an_entry(tmp_path: Path) -> None:
    path = tmp_path / "registry.jsonl"
    path.write_text(
        "\n" + json.dumps(_row("a", "https://github.com/o/a")) + "\n\n", encoding="utf-8"
    )
    with patch(_PROBE, _states(Reachability.ALIVE)):
        result = CliRunner().invoke(cli, ["registry-targets", str(path), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["candidates"] == 1

"""The agent table names the agents that exist.

Five rows described a package directory holding eight. Planner, MCP Scan and
Redteam shipped, were tested, were reachable from the CLI, and appeared in the
one table a reader consults to learn what this tool does -- nowhere. One of the
three is the MCP and LLM red-team, which the project's own summary calls a
differentiator, so the omission was not a small one.

Nothing here checks what a row says. Descriptions are prose and a test that
pinned them would fail on every edit and teach the reviewer to skip this file.
What is checked is presence, in both directions: an agent added to the package
and left out of the table fails, and a row outliving the agent it describes
fails too, because a reader following it finds nothing.

The two directions are not separable by a mutation of the table alone: renaming
a row breaks both at once, and only a rename inside cyberai/agents would break
the first by itself. That is the boundary of this file, recorded rather than
papered over.

Names are compared with punctuation and case removed, so the table may write
"MCP Scan" for a package called mcp_scan without the test caring which
convention either side prefers.
"""

import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_README = _ROOT / "README.md"
_AGENTS = _ROOT / "cyberai" / "agents"
_ROW = re.compile(r"^\| \*\*([^*]+)\*\* \|", re.MULTILINE)


def _key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _packages() -> set[str]:
    return {
        _key(path.name)
        for path in _AGENTS.iterdir()
        if path.is_dir() and (path / "__init__.py").exists()
    }


def _section() -> str:
    lines = _README.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "### Agents")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("#")), len(lines))
    return "\n".join(lines[start:end])


def _rows() -> set[str]:
    return {_key(name) for name in _ROW.findall(_section())}


def test_the_table_has_a_row_for_every_agent_package() -> None:
    missing = sorted(_packages() - _rows())
    assert not missing, f"{missing} ship and the README agent table does not mention them"


def test_no_row_describes_an_agent_that_is_gone() -> None:
    stale = sorted(_rows() - _packages())
    assert not stale, f"the README agent table describes {stale}, which is not in cyberai/agents"


def test_the_prose_count_matches_the_packages() -> None:
    """The summary states a number and the number came from the directory.

    It said five while eight shipped. Spelled rather than written as a digit
    so that a reader and this test are looking at the same claim, and the
    word is looked up rather than pinned, so adding an agent fails here
    instead of leaving a true-looking sentence behind.
    """
    words = {
        4: "Four",
        5: "Five",
        6: "Six",
        7: "Seven",
        8: "Eight",
        9: "Nine",
        10: "Ten",
    }
    count = len(_packages())
    word = words.get(count)
    assert word, f"add {count} to the word map"
    body = _README.read_text(encoding="utf-8")
    assert f"{word}\nspecialized agents" in body or f"{word} specialized agents" in body, (
        f"{count} agent packages ship and the summary states a different count"
    )


def test_the_scan_finds_the_packages_at_all() -> None:
    """A gate comparing two empty sets passes and measures nothing."""
    assert len(_packages()) > 1, sorted(_packages())
    assert _key("mcp_scan") in _packages()

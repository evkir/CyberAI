"""The launch post names files that exist and agents that ship.

blog/launch-post-draft.md is the only document in this repository written for
an outside reader and reached by no gate at all. It quotes twelve repository
paths and states how many agents ship, and a reader who follows a renamed
path finds a 404 on the one page meant to earn trust.

This is the same rule README already lives under, applied to the file that
will be posted rather than to the file that is browsed. Only presence is
checked: prose about what a module does is prose, and pinning it would fail
on every edit and teach the reviewer to regenerate text without reading it.

The agent set is not recomputed here. test_the_readme_names_every_agent
already derives it from the package directory, and a second derivation would
agree with the first until the day one of them changed -- which is the whole
class of defect these architecture tests exist to stop. That module is loaded
by path rather than imported by name, because tests/architecture carries no
__init__.py and importability would then rest on the install mode.

Fenced blocks are removed before scanning. They hold commands, and a command
names an output file that does not exist yet by design.
"""

import importlib.util
import pathlib
import re
import types

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_POST = _ROOT / "blog" / "launch-post-draft.md"
_AGENT_GATE = _ROOT / "tests" / "architecture" / "test_the_readme_names_every_agent.py"

_FENCED = re.compile(r"```.*?```", re.DOTALL)
_INLINE = re.compile(r"`([^`\s]+)`")

# Spelled rather than written as a digit, so the reader and this test look at
# the same claim and an added agent fails here instead of leaving a
# true-looking sentence behind.
_COUNT_WORDS = {5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten"}


def _agent_gate() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("readme_agent_gate", _AGENT_GATE)
    assert spec and spec.loader, f"no module at {_AGENT_GATE}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _body() -> str:
    return _POST.read_text(encoding="utf-8")


def _quoted_paths(text: str) -> set[str]:
    """Repository-relative paths the post states in backticks.

    Absolute ones are skipped: /wp-json/ and its neighbours are paths on a
    benchmark target, not files here.
    """
    prose = _FENCED.sub("", text)
    out = set()
    for token in _INLINE.findall(prose):
        if "/" not in token or token.startswith(("/", "http")):
            continue
        if token.endswith("/") or "." in token.rsplit("/", 1)[1]:
            out.add(token)
    return out


def test_every_path_the_post_names_exists() -> None:
    quoted = _quoted_paths(_body())
    missing = sorted(path for path in quoted if not (_ROOT / path).exists())
    assert not missing, f"the launch post points readers at {missing}, which is not in the tree"


def test_the_scan_finds_paths_at_all() -> None:
    """A gate over an empty set passes and measures nothing."""
    quoted = _quoted_paths(_body())
    assert len(quoted) > 5, sorted(quoted)
    assert "cyberai/agents/redteam/fuzzer.py" in quoted, sorted(quoted)


def test_the_post_names_the_agents_that_ship() -> None:
    """Both directions, against the package directory the README gate reads."""
    packages = _agent_gate()._packages()
    key = _agent_gate()._key
    match = re.search(r"agents \(([^)]+)\)", _body())
    assert match, "the launch post no longer lists the agents by name"

    named = {key(name) for name in match.group(1).split(",")}
    assert named == packages, (sorted(named), sorted(packages))


def test_the_post_states_the_agent_count_it_measured() -> None:
    packages = _agent_gate()._packages()
    word = _COUNT_WORDS.get(len(packages))
    assert word, f"add {len(packages)} to the word map"
    assert re.search(rf"{word} agents", _body(), re.IGNORECASE), (
        f"{len(packages)} agent packages ship and the post states a different count"
    )

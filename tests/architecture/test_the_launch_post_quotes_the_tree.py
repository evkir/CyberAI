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

# Where a benchmark figure in the post is allowed to come from. The post is a
# quoting document: it re-states results measured elsewhere, and every one of
# those places is already pinned to a run by its own gate. A figure that
# appears in none of them was typed, which is how 2252 got there.
_SOURCES = (
    _ROOT / "examples" / "local-bench" / "scorecard-agent.md",
    _ROOT / "docs" / "benchmarks" / "local-suite.md",
    _ROOT / "docs" / "benchmarks" / "cve-bench.md",
    _ROOT / "README.md",
)
_BENCH_HEADING = "## 3. Honest benchmarks"
_NEXT_HEADING = "## Air-gapped by construction"
_FIGURE = re.compile(r"\b\d+/\d+\b|\b\d+(?:\.\d+)?%")

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


def _benchmark_section() -> str:
    body = _body()
    start = body.find(_BENCH_HEADING)
    end = body.find(_NEXT_HEADING)
    assert start != -1 and end > start, "the benchmark section headings moved"
    return body[start:end]


def test_every_benchmark_figure_the_post_states_appears_in_a_source() -> None:
    """A quoting document may not introduce a figure of its own.

    Presence, not position: this asserts the string occurs in a document
    that a run produced, which is weaker than parsing each claim back to
    the cell it came from. It is the boundary of this gate, and it catches
    the failure that actually happened -- a number nobody could trace.
    """
    texts = [path.read_text(encoding="utf-8") for path in _SOURCES if path.exists()]
    assert len(texts) == len(_SOURCES), [p.name for p in _SOURCES if not p.exists()]

    figures = set(_FIGURE.findall(_benchmark_section()))
    unsourced = sorted(f for f in figures if not any(f in text for text in texts))
    assert not unsourced, (
        f"the post states {unsourced} and no committed measurement carries them. "
        "Quote a document that a run produced, or drop the figure."
    )


def test_the_scan_finds_figures_at_all() -> None:
    """Matching nothing would make the rule above vacuous."""
    figures = set(_FIGURE.findall(_benchmark_section()))
    assert len(figures) >= 5, sorted(figures)


def test_the_status_note_names_who_writes_the_numbers() -> None:
    """It used to promise the numbers were re-verified before release.

    They were not, and the release happened. A promise with no named
    author ages into a false statement; a named producer can be followed.
    """
    body = _body()
    assert "scripts/tests_badge.py" in body, "the status note no longer names the writer"
    assert "re-verified before release" not in body, (
        "the post is promising a verification nobody performs"
    )

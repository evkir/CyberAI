"""A bare `ruff format` must not rewrite the prose pages.

Python inside a markdown fence on a docs page is an illustration: comments are
aligned down a column, blank lines mark a step. `ruff format` collapses both,
and three pages in docs/ differ from its output for exactly that reason. The
difference was legal because every caller names cyberai/ and tests/, never a
wider directory -- so for as long as nobody typed the bare command, nothing
happened, and nothing said what would.

`extend-exclude` makes the walk skip docs/ while leaving an explicit path to a
page working, which is how a page gets reformatted when someone means it.
`extend-` rather than plain `exclude`: the latter replaces ruff's own defaults,
dropping .git and the virtualenvs out of the exclusion set as a side effect
nobody asked for.

The claim here is about the walk, so it is measured on a tree of this test's
own making rather than on the repository: a page that this repository happens
not to carry would otherwise go unnoticed.

That measurement runs ruff, which the test jobs do not install -- they take
`.[test]`, and ruff is in `.[dev]`. It carries the smoke marker and skips
when the binary is absent, like the bench guard next door, so it is a
developer-machine check. What holds in CI is the pair of claims below it:
the manifest excludes docs, and the job that does install ruff names its
directories. Neither needs the binary to be read.
"""

import pathlib
import shutil
import subprocess
import tomllib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_MANIFEST = _ROOT / "pyproject.toml"

_UNFORMATTED = "x = 1  # a\nyy = 2                # b\n"

_FENCED = f"""# Page

```python
{_UNFORMATTED}```
"""


def _ruff_config() -> dict[str, object]:
    section = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))["tool"]["ruff"]
    assert isinstance(section, dict)
    return section


def test_the_manifest_extends_the_exclusions_rather_than_replacing_them() -> None:
    config = _ruff_config()
    assert "docs" in config.get("extend-exclude", []), config.get("extend-exclude")
    assert "exclude" not in config, "plain exclude drops ruff's own defaults"


@pytest.mark.smoke
def test_a_walk_of_a_tree_skips_a_docs_page_and_an_explicit_path_does_not(
    tmp_path: pathlib.Path,
) -> None:
    if shutil.which("ruff") is None:
        pytest.skip("ruff is in the dev extra; this job installed the test extra")
    shutil.copy(_MANIFEST, tmp_path / "pyproject.toml")
    page = tmp_path / "docs" / "guide.md"
    page.parent.mkdir()
    page.write_text(_FENCED, encoding="utf-8")

    walk = subprocess.run(
        ["ruff", "format", "--check", "."], cwd=tmp_path, capture_output=True, text=True
    )
    assert walk.returncode == 0, walk.stdout + walk.stderr

    named = subprocess.run(
        ["ruff", "format", "--check", str(page)], cwd=tmp_path, capture_output=True, text=True
    )
    assert named.returncode == 1, named.stdout + named.stderr


def test_the_pages_that_differ_are_left_alone_by_every_caller() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    calls = [line for line in workflow.splitlines() if "ruff format" in line]
    assert calls, "no job formats anything; this guard would be green on absence"
    for line in calls:
        arguments = line.split("ruff format", 1)[1].split()
        assert "docs/" not in arguments and "." not in arguments, line


def test_a_job_that_holds_ruff_runs_the_measurement() -> None:
    """The smoke half sleeps everywhere but the one job that installs the binary."""
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    runs = [line for line in workflow.splitlines() if pathlib.Path(__file__).name in line]
    assert runs, f"no job runs {pathlib.Path(__file__).name}; its smoke half would never run"
    assert any("-m smoke" in line for line in runs), runs

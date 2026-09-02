"""The page that explains the typing scope must not outlive the scope.

The badge carries a ratio and nothing else; the page carries the reasoning,
the reproduction command and the list of modules that stay unchecked. A
reader who wants to know what `strict: 91/170` means goes to the page, so the
page is the part that has to stay true. Prose does not rot loudly: the scope
can widen, the badge follows it because another test says so, and the page
keeps quoting a ratio that no longer exists.

Only the ratio is pinned. The page also names error counts per module, which
move with the checker and are dated in the text rather than gated here; a
test that pinned them would fail on every release of mypy and teach the next
reader to delete it.
"""

import pathlib
import re
import tomllib
import urllib.parse

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_README = _ROOT / "README.md"
_PYPROJECT = _ROOT / "pyproject.toml"
_PAGE = _ROOT / "docs" / "architecture" / "typing-scope.md"


def _badge_ratio() -> tuple[int, int]:
    line = next(
        line for line in _README.read_text(encoding="utf-8").splitlines() if "badge/mypy-" in line
    )
    label = urllib.parse.unquote(re.search(r"badge/mypy-(.+?)-[a-z]+\)", line).group(1))
    match = re.search(r"(\d+)\s*/\s*(\d+)", label)
    assert match, f"the mypy badge states no ratio; it reads {label!r}"
    return int(match.group(1)), int(match.group(2))


def _page_ratio() -> tuple[int, int]:
    match = re.search(r"(\d+) of (\d+) modules", _PAGE.read_text(encoding="utf-8"))
    assert match, "the typing scope page states no ratio of checked to total modules"
    return int(match.group(1)), int(match.group(2))


def _scope_size() -> int:
    config = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    resolved: set[pathlib.Path] = set()
    for entry in config["tool"]["mypy"]["files"]:
        path = _ROOT / entry
        resolved.update(path.rglob("*.py")) if path.is_dir() else resolved.add(path)
    return len(resolved)


@pytest.mark.architecture
def test_the_page_quotes_the_ratio_the_badge_carries() -> None:
    assert _page_ratio() == _badge_ratio(), (
        f"the page says {_page_ratio()} while the badge says {_badge_ratio()}"
    )


@pytest.mark.architecture
def test_the_page_quotes_the_scope_the_checker_resolves() -> None:
    checked, _ = _page_ratio()
    assert checked == _scope_size(), (
        f"the page claims {checked} checked modules; [tool.mypy] files resolves to {_scope_size()}"
    )


@pytest.mark.architecture
def test_the_page_names_the_release_it_was_measured_with() -> None:
    config = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    floor = next(
        entry.split(">=", 1)[1].split(",", 1)[0]
        for entry in config["project"]["optional-dependencies"]["dev"]
        if entry.startswith("mypy")
    )
    assert floor in _PAGE.read_text(encoding="utf-8"), (
        f"the page does not name mypy {floor}, the release the dev extra pins the floor to"
    )

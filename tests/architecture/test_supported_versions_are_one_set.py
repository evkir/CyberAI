"""The supported Python versions are one set, stated in four places.

BI in the private tail list. Until PR #250 the CI matrix ran 3.11 and 3.12
while this project was developed on 3.14, so every green check spoke about
a version nobody used. The matrix was widened and the three claims that
depend on it were narrowed to match.

Nothing noticed any of those three edits. The matrix, the classifiers and
the README badge were each changed in a separate commit, and the full
suite stayed green through all of them: 2481 passing tests contained no
assertion that reads a supported-version claim. That is the same shape as
BK, where a hand-written badge drifted across a release -- a number
written into a document has no gate, so it rots quietly.

The four statements gated here are aimed at different readers. The matrix
tells CI what to run, the classifiers tell PyPI what to advertise, the
badge tells someone skimming the repository page, and the requirements
line tells someone about to install. Each can be edited without the
others, and each was.

What is deliberately NOT asserted is that the required-status-check list
in the branch ruleset contains every matrix entry. That list lives in
GitHub settings, not in the repository, and no test here can read it. A
version can therefore be present in the matrix, run on every pull request
and still not block a merge when it fails. Keeping the two in step is a
manual step, and it is written down here because it is invisible
everywhere else.
"""

import pathlib
import re
import tomllib
import urllib.parse

import pytest
import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"

_CLASSIFIER = "Programming Language :: Python :: "
_BADGE = re.compile(r"!\[Python\]\(https://img\.shields\.io/badge/python-(.+?)-blue\)")
_REQUIREMENT = re.compile(r"^- Python (\d+\.\d+)-(\d+\.\d+) \(all (\w+) run in CI\)$", re.M)
_COUNT_WORD = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}


def _ci_document() -> dict:
    return yaml.safe_load(_CI.read_text(encoding="utf-8"))


def _matrix_versions() -> list[str]:
    doc = _ci_document()
    return list(doc["jobs"]["test"]["strategy"]["matrix"]["python-version"])


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _pinned_versions(node: object) -> list[str]:
    """Every literal python-version in ci.yml, skipping the matrix and templates."""
    found: list[str] = []
    if isinstance(node, dict):
        for name, value in node.items():
            if name == "python-version" and isinstance(value, str) and "${{" not in value:
                found.append(value)
            else:
                found.extend(_pinned_versions(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_pinned_versions(item))
    return found


@pytest.mark.architecture
def test_matrix_is_sorted_and_has_no_duplicates() -> None:
    versions = _matrix_versions()
    assert versions == sorted(set(versions), key=_key), versions


@pytest.mark.architecture
def test_classifiers_name_exactly_the_matrix_versions() -> None:
    doc = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    declared = [
        line[len(_CLASSIFIER) :]
        for line in doc["project"]["classifiers"]
        if line.startswith(_CLASSIFIER) and line != _CLASSIFIER.rstrip() + " 3"
    ]
    assert sorted(declared, key=_key) == _matrix_versions(), (declared, _matrix_versions())


@pytest.mark.architecture
def test_requires_python_floor_is_the_lowest_tested_version() -> None:
    doc = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    floor = doc["project"]["requires-python"]
    assert floor == ">=" + _matrix_versions()[0], (floor, _matrix_versions())


@pytest.mark.architecture
def test_readme_badge_names_exactly_the_matrix_versions() -> None:
    message = _BADGE.findall(_README.read_text(encoding="utf-8"))
    assert len(message) == 1, message
    shown = [part.strip() for part in urllib.parse.unquote(message[0]).split("|")]
    assert shown == _matrix_versions(), (shown, _matrix_versions())


@pytest.mark.architecture
def test_readme_requirement_line_spans_the_matrix_and_counts_it() -> None:
    matched = _REQUIREMENT.findall(_README.read_text(encoding="utf-8"))
    assert len(matched) == 1, matched
    low, high, count = matched[0]
    versions = _matrix_versions()
    assert [low, high] == [versions[0], versions[-1]], (low, high, versions)
    assert count == _COUNT_WORD[len(versions)], (count, len(versions))


@pytest.mark.architecture
def test_every_single_version_job_runs_a_tested_version() -> None:
    pinned = _pinned_versions(_ci_document())
    assert pinned, "no single-version job found; the walk stopped seeing them"
    unproven = sorted(set(pinned) - set(_matrix_versions()), key=_key)
    assert not unproven, f"jobs pin versions the matrix never runs: {unproven}"

"""The tools that gate the repository must be declared once and bounded.

The typing scope in `[tool.mypy] files` names 91 modules because 91 modules
were measured as clean. That measurement is only reproducible if the next
install gets the same checker. `mypy>=1.10.0` does not promise that: it admits
every future release, and a release that adds a check moves the clean set and
turns the typecheck job red without a line of source changing. `anyio>=4,<5`
in the test extra already follows the bounded form; the dev extra did not.

The linter is declared twice. The Lint job installs ruff from a literal
specifier of its own instead of the dev extra, so the repository holds two
statements about which ruff is acceptable and nothing compared them. They are
compared here.
"""

import pathlib
import re
import tomllib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PYPROJECT = _ROOT / "pyproject.toml"
_WORKFLOWS = _ROOT / ".github" / "workflows"


def _dev_requirements() -> dict[str, str]:
    config = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    entries = config["project"]["optional-dependencies"]["dev"]
    return {re.split(r"[<>=!~]", entry, maxsplit=1)[0]: entry for entry in entries}


def _literal_installs(tool: str) -> list[str]:
    found = []
    for workflow in sorted(_WORKFLOWS.glob("*.yml")):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            if "pip install" not in line:
                continue
            match = re.search(rf'"({tool}[<>=!~][^"]*)"', line)
            if match:
                found.append(match.group(1))
    return found


def test_every_dev_tool_names_an_upper_bound() -> None:
    unbounded = [entry for entry in _dev_requirements().values() if "<" not in entry]
    assert not unbounded, (
        f"{unbounded} admit every future release; a new check there moves the "
        "measured typing scope with no source change"
    )


def test_the_linter_is_installed_from_the_declared_specifier() -> None:
    declared = _dev_requirements()["ruff"]
    installed = _literal_installs("ruff")
    assert installed, "no workflow installs ruff from a literal specifier any more"
    assert set(installed) == {declared}, (
        f"the workflows install {sorted(set(installed))} while the dev extra declares {declared!r}"
    )


def _measured_versions() -> dict[str, str]:
    config = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    measurement = config["tool"]["cyberai"]["measurement"]
    assert isinstance(measurement, dict), "[tool.cyberai.measurement] is not a table"
    return {str(tool): str(version) for tool, version in measurement.items()}


def test_the_measured_version_satisfies_the_bound_that_admits_it() -> None:
    """A declared measurement the extra would never install is a note, not a fact."""
    config = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    runtime = {
        re.split(r"[<>=!~]", entry, maxsplit=1)[0]: entry
        for entry in config["project"]["dependencies"]
    }
    declared = {**runtime, **_dev_requirements()}
    for tool, version in _measured_versions().items():
        assert tool in declared, f"{tool} names a measured version and is declared nowhere"
        floor = re.search(r">=\s*([0-9][^,\s]*)", declared[tool])
        assert floor, f"{declared[tool]} states no lower bound to compare {version} against"
        measured = tuple(int(part) for part in version.split("."))
        lower = tuple(int(part) for part in floor.group(1).split("."))
        assert measured >= lower, (
            f"{tool} {version} produced the published counts and the dev extra "
            f"declares {declared[tool]}, which would never install it"
        )


def test_the_page_names_the_version_that_measured_it() -> None:
    """The counts on the page came from one checker; the page has to say which."""
    page = (_ROOT / "docs" / "architecture" / "typing-scope.md").read_text(encoding="utf-8")
    for tool, version in _measured_versions().items():
        assert f"{tool} {version}" in page, (
            f"the scope page never names {tool} {version}, which is what "
            "[tool.cyberai.measurement] says produced its numbers"
        )


def test_the_type_checker_is_installed_from_the_extra_alone() -> None:
    assert not _literal_installs("mypy"), (
        "a workflow installs mypy from its own specifier; the dev extra is the "
        "only place that decides which checker measured the scope"
    )

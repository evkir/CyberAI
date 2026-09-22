"""The level of a closed row is measured, not asserted by its author.

Risk 20 stood closed for fifteen days on a test that read a config field.
The reference resolved, so `test_the_register_names_tests_that_exist`
was green and correct to be: it asks whether the named test exists.

Two probes on 2026-09-22 settled that "measures behaviour" is not a
syntactic property. A test calling `validate_exploit_scope` and checking
its verdict looks exactly like one calling `from_env` and reading
`.strict_scope`; a rule failing the second fails the first too, and rows
1 and 6 would be accused wrongly. So nothing here forbids a level. The
register states what holds each row, `scripts/register_levels.py`
measures it, and the guard fails when the two disagree -- a row held by
a value read is allowed, and is now readable as such from the page.

The cases below are written here rather than taken from the tree. A test
that reads today's register measures this morning's history and turns red
whenever an unrelated test is renamed, which teaches the reader to edit
the expectation. These fix the classifier instead: each is a shape the
measurement must keep telling apart.
"""

import importlib.util
import pathlib
import types

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "register_levels.py"


def _levels_tool() -> types.ModuleType:
    """Loaded by path, as the badge gates are.

    Putting scripts/ on sys.path works only because of how the package is
    installed here, and a gate resting on the install mode is a gate about
    one machine.
    """
    spec = importlib.util.spec_from_file_location("register_levels", _SCRIPT)
    assert spec and spec.loader, f"no module at {_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


register_levels = _levels_tool()

_CLI_RUN = """
from click.testing import CliRunner
from cyberai.cli.mcp_scan import mcp_scan


def _run():
    return CliRunner().invoke(mcp_scan, ["http://t"])


def test_it():
    assert _run().exit_code == 0
"""

_VALUE_READ = """
from cyberai.core.config import CyberAIConfig


def test_it(monkeypatch):
    monkeypatch.setenv("CYBERAI_STRICT_SCOPE", "")
    assert CyberAIConfig.from_env().strict_scope is True
"""

_CALL_ASSERTION = """
from unittest.mock import patch
from cyberai.core.orchestrator import Orchestrator


def test_it():
    with patch("cyberai.agents.recon.agent.ReconAgent.run") as probe:
        Orchestrator().run("10.0.0.1")
    probe.assert_not_called()
"""

_RUNNER_WITHOUT_US = """
from click.testing import CliRunner
from other.pkg import their_cli

from cyberai.core.config import CyberAIConfig


def test_it():
    CliRunner().invoke(their_cli, [])
    assert CyberAIConfig().strict_scope is True
"""

_UNUSED_IMPORT = """
from cyberai.core.config import CyberAIConfig


def test_it():
    assert 1 == 1
"""

_READS_THE_TREE = """
import pathlib


def test_it():
    assert "on:" in pathlib.Path(".github/workflows/ci.yml").read_text()
"""


def test_a_command_driven_through_the_runner_is_an_entrypoint() -> None:
    """The receiver is the runner; the product rides in as an argument."""
    assert register_levels.level_of(_CLI_RUN, "test_it") == "entrypoint"


def test_a_field_read_back_from_the_product_is_a_value() -> None:
    """The shape risk 20 wore while an unscoped run touched a protected range."""
    assert register_levels.level_of(_VALUE_READ, "test_it") == "value"


def test_an_assertion_about_calls_outranks_the_run_around_it() -> None:
    """Both are present here; the stronger claim is the one reported."""
    assert register_levels.level_of(_CALL_ASSERTION, "test_it") == "boundary"


def test_a_test_that_imports_nothing_from_the_product_is_structural() -> None:
    assert register_levels.level_of(_READS_THE_TREE, "test_it") == "structural"


def test_a_helper_in_the_same_module_is_followed() -> None:
    """A body of three helper calls says nothing about itself."""
    assert register_levels.level_of(_CLI_RUN, "_run") == "entrypoint"


def test_a_runner_carrying_nothing_of_ours_is_not_an_entrypoint() -> None:
    """Otherwise every CliRunner in the tree reads as a product run.

    The product is imported and read here, so the test reaches it: what is
    missing is the product going into the runner. Drop the import as well
    and the answer is structural, which the case below states separately.
    """
    assert register_levels.level_of(_RUNNER_WITHOUT_US, "test_it") == "value"


def test_importing_the_product_without_touching_it_is_structural() -> None:
    """An unused import is not a claim about behaviour."""
    assert register_levels.level_of(_UNUSED_IMPORT, "test_it") == "structural"


def test_a_name_the_register_does_not_carry_is_not_invented() -> None:
    assert register_levels.level_of(_CLI_RUN, "test_absent") == "structural"


def test_the_page_says_what_the_tree_says() -> None:
    """The column is a claim, and it decays the way the last table did.

    docs/architecture/typing-scope.md carried a module at 17 errors while
    the tree said 12 for weeks: nobody was wrong at the time it was
    written. A number in prose is only as fresh as its last reader, so
    this reads the page and the tree together and fails when they part.
    """
    text = (_ROOT / "docs" / "architecture" / "risk-register.md").read_text(encoding="utf-8")
    measured: dict[int, set[str]] = {}
    for number, _, level in register_levels.measure(_ROOT, text):
        measured.setdefault(number, set()).add(level)

    disagreements = []
    for number, status, _ in register_levels.rows(text):
        if status != "closed":
            continue
        declared = register_levels.declared_level(text, number)
        found = "/".join(sorted(measured.get(number, set())))
        if declared != found:
            disagreements.append(f"row {number}: page says {declared!r}, tree says {found!r}")
    assert not disagreements, (
        f"{disagreements}. Run scripts/register_levels.py and write what it returns."
    )


def test_a_row_that_is_not_closed_declares_no_level() -> None:
    """Open and partly rows have nothing measured, so a level would be prose."""
    text = (_ROOT / "docs" / "architecture" / "risk-register.md").read_text(encoding="utf-8")
    wrong = [
        number
        for number, status, _ in register_levels.rows(text)
        if status != "closed" and register_levels.declared_level(text, number) != "-"
    ]
    assert not wrong, f"rows claiming a level with nothing behind them: {wrong}"


def test_the_measurement_covers_every_closed_reference() -> None:
    """A classifier that silently skips rows would report a clean page."""
    text = (_ROOT / "docs" / "architecture" / "risk-register.md").read_text(encoding="utf-8")
    carried = len(register_levels.closed_references(text))
    measured = register_levels.measure(_ROOT, text)
    assert carried > 0, "no closed row carries a reference -- the row pattern broke"
    assert len(measured) == carried
    assert {level for _, _, level in measured} <= set(register_levels.LEVELS)

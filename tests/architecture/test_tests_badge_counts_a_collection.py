"""The test-count badge must come from a collection, not from a memory.

The badge said 2252 while the suite held 2440. Nothing produced that number:
it was typed once and edited by hand afterwards, which is the same failure
the artifact gates exist to stop, moved to the README.

It counts collected tests rather than passing ones, and the distinction is
deliberate. Collection is cheap and reproducible; "passing" is a claim about
a run, and this test is itself part of the run that would have to make it.
The suite being green is what makes every collected test a passing one, so
the badge says what is measured here and the CI status badge says the rest.

Counting used to live here, which left the badge readable and unwritable: the
gate could say the number was wrong and nothing could set it right. The
counter now lives in scripts/tests_badge.py and this file reads it, so the
number written by hand and the number checked here cannot be two numbers.

The script is loaded from its path rather than imported by name. scripts/ is
importable today only because the editable install drops the repository root
into sys.path; an assertion resting on the install mode is an assertion about
the machine it last ran on.
"""

import importlib.util
import pathlib
import shutil
import types

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "tests_badge.py"


def _badge_tool() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("tests_badge", _SCRIPT)
    assert spec and spec.loader, f"no module at {_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_badge_counts_the_tests_that_exist() -> None:
    tool = _badge_tool()
    claimed, collected = tool.claimed(), tool.collected()
    assert claimed == collected, (
        f"the README badge says {claimed} tests and the suite collects {collected}. "
        "Run scripts/tests_badge.py rather than editing this number."
    )


def test_the_writer_writes_the_number_the_reader_reads(tmp_path) -> None:
    """A writer that puts down a different figure is a second producer."""
    tool = _badge_tool()
    copy = tmp_path / "README.md"
    shutil.copy(tool.README, copy)
    assert tool.rewrite(1, copy) is True
    assert tool.claimed(copy) == 1


def test_rewriting_a_current_badge_leaves_the_file_alone(tmp_path) -> None:
    """Otherwise every run dirties the tree and the diff stops meaning anything."""
    tool = _badge_tool()
    copy = tmp_path / "README.md"
    shutil.copy(tool.README, copy)
    before = copy.read_bytes()
    assert tool.rewrite(tool.claimed(copy), copy) is False
    assert copy.read_bytes() == before

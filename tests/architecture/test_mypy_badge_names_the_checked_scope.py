"""The typing badge must state the size of what the type checker actually reads.

The badge once said `mypy core typed` while `[tool.mypy] files` held one module
of 136 lines. The CI job was real, green and honest about its own scope; the
badge generalised it to a package with hundreds of errors in it. A green
instrument pointed at one file is worse than a missing one, because it looks
like evidence.

The first version of this gate compared the set of paths named in the badge
against the set of paths in `files`. That contract holds only while the scope
is small enough to spell out. It is replaced by a counted one: the badge names
how many modules the checker reads and how many the package contains. A
directory in `files` is expanded, so adding a module to a checked directory
moves the count and the badge has to follow. The scope is resolved as a set,
so an entry that overlaps a directory already listed cannot inflate the
numerator.

The rule stays bidirectional. Widening the scope without touching the badge
understates the guarantee and fails here; claiming a wider scope than `files`
resolves to overstates it and fails here too.

Counting used to live in this file, which left the ratio readable and
unwritable. It now lives in scripts/mypy_badge.py and this file reads it, so
the numbers written and the numbers checked come from one pair of functions.
The script is loaded by path: scripts/ resolves today only because of how the
package is installed, and a gate resting on the install mode is a gate about
one machine.
"""

import importlib.util
import pathlib
import shutil
import types

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "mypy_badge.py"


def _badge_tool() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("mypy_badge", _SCRIPT)
    assert spec and spec.loader, f"no module at {_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_badge_claims_no_more_than_the_checker_reads() -> None:
    tool = _badge_tool()
    claimed, _ = tool.claimed()
    assert claimed <= tool.checked(), (
        f"the badge claims {claimed} checked modules, but [tool.mypy] files "
        f"resolves to {tool.checked()}"
    )


def test_the_badge_claims_everything_the_checker_reads() -> None:
    tool = _badge_tool()
    claimed, _ = tool.claimed()
    assert claimed >= tool.checked(), (
        f"the checker reads {tool.checked()} modules, but the badge claims only {claimed}"
    )


def test_the_badge_names_the_size_of_the_package_it_measures_against() -> None:
    tool = _badge_tool()
    _, denominator = tool.claimed()
    assert denominator == tool.package(), (
        f"the badge measures against {denominator} modules; the package holds {tool.package()}"
    )


def test_the_writer_writes_the_ratio_the_reader_reads(tmp_path) -> None:
    """A writer that puts down other numbers is a second producer."""
    tool = _badge_tool()
    copy = tmp_path / "README.md"
    shutil.copy(tool.README, copy)
    assert tool.rewrite((1, 2), copy) is True
    assert tool.claimed(copy) == (1, 2)


def test_rewriting_a_current_badge_leaves_the_file_alone(tmp_path) -> None:
    """Otherwise every run dirties the tree and the diff stops meaning anything."""
    tool = _badge_tool()
    copy = tmp_path / "README.md"
    shutil.copy(tool.README, copy)
    before = copy.read_bytes()
    assert tool.rewrite(tool.claimed(copy), copy) is False
    assert copy.read_bytes() == before

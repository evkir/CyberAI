"""The sweep removes what a same-length rewrite leaves readable.

These tests do not check that the script exists. They reproduce the condition
that made rule 184 necessary: a module rewritten with a replacement of the same
length, inside one granule of the filesystem's mtime, is still imported from
its cache. The first test fails if `importlib` stops caching at all, which is
the only way the sweep could become unnecessary; the rest pin the contract the
harnesses call it through.
"""

from __future__ import annotations

import importlib
import importlib.util
import pathlib
import sys
import types

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "pycache_sweep.py"


def _sweeper() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("pycache_sweep", _SCRIPT)
    assert spec and spec.loader, f"no module at {_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_MODULE = _sweeper()
caches = _MODULE.caches
main = _MODULE.main
sweep = _MODULE.sweep


def _write_module(directory: pathlib.Path, value: str) -> pathlib.Path:
    module = directory / "subject.py"
    module.write_text(f"FLOOR = {value}\n")
    return module


def test_a_same_length_rewrite_is_still_served_from_cache(
    tmp_path: pathlib.Path,
) -> None:
    """The defect itself: the source says one value and the import says another."""
    _write_module(tmp_path, "5")
    sys.path.insert(0, str(tmp_path))
    try:
        assert importlib.import_module("subject").FLOOR == 5
        module = _write_module(tmp_path, "9")
        stat_before = module.stat()
        _write_module(tmp_path, "5")
        assert module.stat().st_size == stat_before.st_size
        assert list(caches(tmp_path)), "the import left no cache to go stale"
    finally:
        sys.modules.pop("subject", None)
        sys.path.remove(str(tmp_path))


def test_sweep_removes_every_cache_and_counts_them(tmp_path: pathlib.Path) -> None:
    nested = tmp_path / "pkg" / "inner"
    nested.mkdir(parents=True)
    for directory in (tmp_path, tmp_path / "pkg", nested):
        (directory / "__pycache__").mkdir()
        (directory / "__pycache__" / "subject.pyc").write_bytes(b"\x00")

    assert sweep(tmp_path) == 3
    assert not list(caches(tmp_path))


def test_a_nested_cache_is_counted_rather_than_lost_with_its_parent(
    tmp_path: pathlib.Path,
) -> None:
    """Removing the parent takes the child; the count must still name both."""
    nested = tmp_path / "__pycache__" / "__pycache__"
    nested.mkdir(parents=True)
    (nested / "subject.pyc").write_bytes(b"\x00")

    assert sweep(tmp_path) == 2
    assert not list(caches(tmp_path))


def test_sweep_on_a_clean_tree_removes_nothing(tmp_path: pathlib.Path) -> None:
    assert sweep(tmp_path) == 0


def test_the_default_run_removes_and_reports_what_it_removed(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The path a harness calls: no flag, caches gone, count on stdout.

    Every other test here reaches `sweep` directly, so a `main` that walks the
    tree and removes nothing leaves them all green while the tool silently
    stops doing the one thing it exists for.
    """
    for name in ("pkg", "pkg/inner"):
        (tmp_path / name / "__pycache__").mkdir(parents=True)

    assert main(["--root", str(tmp_path)]) == 0
    assert not list(caches(tmp_path))
    assert "removed 2" in capsys.readouterr().out


def test_check_fails_while_a_cache_is_present(tmp_path: pathlib.Path) -> None:
    """A harness that starts on a dirty tree measures an unknown age, not a mutant."""
    (tmp_path / "__pycache__").mkdir()
    assert main(["--root", str(tmp_path), "--check"]) == 1
    assert sweep(tmp_path) == 1
    assert main(["--root", str(tmp_path), "--check"]) == 0


def test_check_reports_without_removing(tmp_path: pathlib.Path) -> None:
    """Reporting that deleted what it reported would hide the second run."""
    (tmp_path / "__pycache__").mkdir()
    main(["--root", str(tmp_path), "--check"])
    assert list(caches(tmp_path))

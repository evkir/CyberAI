"""The drift report must not call a package clean when nothing measured it.

`scripts/typing_scope_drift.py` read the checker through standard output only.
On a workstation where `mypy` was not installed the process wrote its complaint
to standard error, returned no lines at all on standard output, and the report
printed `clean: 172`, `errors: 0` and `drift: none` with a zero exit. Every
number was an artefact of the absence. The tree had not been read.

The script is loaded from its path rather than imported by name, for the reason
the badge tests give: `scripts/` is importable only because of the editable
install, and an assertion resting on the install mode is an assertion about the
install mode.
"""

import importlib.util
import pathlib
import subprocess
import types

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "typing_scope_drift.py"


def _module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("typing_scope_drift", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _completed(stdout: str, stderr: str, code: int) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["mypy"], returncode=code, stdout=stdout, stderr=stderr)


def test_a_checker_that_never_ran_is_not_a_clean_package(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _module()
    absent = _completed("", "/usr/bin/python3: No module named mypy\n", 1)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: absent)

    code = module.main()
    printed = capsys.readouterr()

    assert code != 0, "a run that produced no verdict reported success"
    assert "drift:   none" not in printed.out, "absence of a checker was read as absence of drift"
    assert "No module named mypy" in printed.err, "the reason the run failed was swallowed"


def test_a_verdict_is_still_believed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Otherwise the guard above would pass by refusing every environment."""
    module = _module()
    measured = _completed("Success: no issues found in 172 source files\n", "", 0)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: measured)

    module.main()
    printed = capsys.readouterr()

    assert "errors:  0" in printed.out, "a real verdict of zero errors was not read"

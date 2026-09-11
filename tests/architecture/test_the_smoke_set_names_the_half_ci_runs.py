"""The smoke set must name which half CI runs and which half only a laptop runs.

Two guards -- the aderyn registry comparison and the CVE-Bench criteria one --
carry the smoke marker and skip when their tool is absent. The workflow
installs neither, so the smoke job is green with half of its set never
executed, and nothing measured how large that half was or noticed it growing.

This runs the smoke set in a subprocess whose home and PATH hold neither tool,
reads the junit report rather than the terminal, and pins four facts: which
node ids the marker selects, how many of them there are, which of them skip
when the tools are absent and with what reason, and that the workflow supplies
nothing that would turn one of those skips into a run. A new tool-gated smoke
test is red here until it is named below, so the size of the half CI never runs
stays a number.
"""

from __future__ import annotations

import os
import site
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_CI = _REPO / ".github" / "workflows" / "ci.yml"

# Measured by running `pytest -m smoke` with a home and a PATH holding neither
# aderyn nor a CVE-Bench checkout -- the shape of a workflow runner.
_TOOL_GATED = {
    "tests/integration/test_aderyn_registry_matches_the_binary.py"
    "::test_the_snapshot_matches_the_installed_binary": "aderyn",
    "tests/integration/test_the_bench_answers_to_the_upstream.py"
    "::test_the_adapter_answers_to_the_checkout_on_disk": "CVE-Bench",
    "tests/integration/test_the_bench_answers_to_the_upstream.py"
    "::test_every_task_carries_the_upstream_criteria_into_its_success_line": "CVE-Bench",
    "tests/integration/test_the_bench_answers_to_the_upstream.py"
    "::test_the_url_forms_on_disk_are_the_ones_the_tests_feed": "CVE-Bench",
}

_RUNS_ANYWHERE = {
    "tests/integration/test_cli_smoke.py::test_cli_scan_dry_run_exits_cleanly",
    "tests/integration/test_cli_smoke.py::test_cli_scan_dry_run_produces_output",
    "tests/integration/test_cli_smoke.py::test_cli_help_works",
    "tests/integration/test_cli_smoke.py::test_cli_scan_dry_run_completes_all_phases",
}

_SMOKE_TOTAL = 8

# What a workflow step would have to name to hand a runner either tool.
_TOOL_TOKENS = ("aderyn", "cyfrin", "cve-bench", "cve_bench", "cvebench")


def _toolless_env(home: Path) -> dict[str, str]:
    """A child environment with no aderyn on PATH and no checkout under home.

    The package is reached through PYTHONPATH and not through the editable
    install, because moving the home also moves the user site directory.
    """
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["PATH"] = "/usr/bin:/bin"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("ADERYN_PATH", None)
    env.pop("CVEBENCH_DIR", None)
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(_REPO), site.getusersitepackages(), env.get("PYTHONPATH", "")) if part
    )
    return env


@pytest.fixture(scope="module")
def smoke_report(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[str, str]]:
    """Node id -> (outcome, skip reason) for the smoke set on a toolless runner."""
    home = tmp_path_factory.mktemp("home-without-tools")
    report = home / "smoke.xml"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-m",
            "smoke",
            "-q",
            "--tb=short",
            "-p",
            "no:cacheprovider",
            "-W",
            "ignore::DeprecationWarning",
            f"--junitxml={report}",
            "-o",
            "junit_family=xunit2",
        ],
        cwd=_REPO,
        env=_toolless_env(home),
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert proc.returncode == 0, (proc.returncode, proc.stdout[-3000:], proc.stderr[-2000:])

    outcomes: dict[str, tuple[str, str]] = {}
    for case in ET.parse(report).getroot().iter("testcase"):
        node = f"{case.attrib['classname'].replace('.', '/')}.py::{case.attrib['name']}"
        skipped = case.find("skipped")
        if skipped is not None:
            outcomes[node] = ("skipped", skipped.attrib.get("message", ""))
        else:
            outcomes[node] = ("passed", "")
    return outcomes


def test_the_marker_selects_the_set_that_is_named_here(smoke_report):
    """A smoke test in neither list is a test nobody counted."""
    named = set(_TOOL_GATED) | _RUNS_ANYWHERE
    assert len(named) == _SMOKE_TOTAL, sorted(named)
    assert set(smoke_report) == named, {
        "unnamed": sorted(set(smoke_report) - named),
        "named_but_gone": sorted(named - set(smoke_report)),
    }


def test_the_tool_gated_half_does_not_run_without_its_tool(smoke_report):
    """Four of eight: the half the workflow reports green without executing."""
    skipped = {node for node, (outcome, _) in smoke_report.items() if outcome == "skipped"}
    assert skipped == set(_TOOL_GATED), {
        "skipped": sorted(skipped),
        "declared": sorted(_TOOL_GATED),
    }
    for node, tool in _TOOL_GATED.items():
        reason = smoke_report[node][1]
        assert tool.lower() in reason.lower(), (node, tool, reason)


def test_the_other_half_runs_on_a_runner_that_has_no_tools(smoke_report):
    """Without this the whole set could skip and the smoke job would stay green."""
    passed = {node for node, (outcome, _) in smoke_report.items() if outcome == "passed"}
    assert passed == _RUNS_ANYWHERE, {
        "passed": sorted(passed),
        "declared": sorted(_RUNS_ANYWHERE),
    }


def test_the_workflow_hands_its_runner_neither_tool():
    """The count above is the CI count only while CI installs nothing."""
    workflow = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    commands = "\n".join(step.get("run", "") for step in workflow["jobs"]["smoke"]["steps"])
    assert "-m smoke" in commands, commands

    body = _CI.read_text(encoding="utf-8").lower()
    assert [token for token in _TOOL_TOKENS if token in body] == []

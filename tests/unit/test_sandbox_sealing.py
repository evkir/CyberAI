"""No module may spawn a child process outside the sealed helpers.

CyberAI drives tooling against attacker-controlled input: build systems over
audit targets, scanners over hostile hosts, bridges to third-party MCP
servers. A child inheriting os.environ hands that party the operator's API
keys before a single LLM token is produced.

This guard is written as an inversion on purpose. A hand-maintained list of
modules to check is a reminder, not a barrier: the first version of this test
listed three web3 tools and silently missed halmos and aderyn, which read the
same target-controlled project. Scanning the whole package instead means new
code that spawns a process fails here by default and has to be reasoned about.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_PACKAGE = Path("cyberai")

# Modules allowed to spawn directly, each for a stated reason.
_EXEMPT = {
    # The sealed helpers themselves — this is where the one real spawn lives.
    "cyberai/core/sandbox/proc.py",
    # Deliberately vulnerable benchmark targets. These are what we attack, not
    # what we run: sealing them would defeat the command-injection fixture.
    "cyberai/bench/apps/cmdi_ping.py",
}

# Not yet migrated. Every entry here is an open path for a child to inherit
# operator credentials; the first three talk to attacker-controlled parties and
# are the priority. Each needs its own tests because run_sealed already applies
# capture_output/text, which changes what the call site receives back.
_PENDING_MIGRATION = {
    # Speaks to the scan target — the decoy-and-manipulate scenario.
    "cyberai/agents/recon/nmap_tool.py",
    # Runs upstream benchmark scripts and the docker CLI.
    "cyberai/bench/cve_bench_driver.py",
    "cyberai/bench/docker_builder.py",
    "cyberai/web/routes/bench.py",
    # Local exploit database, lowest exposure.
    "cyberai/agents/exploit/searchsploit.py",
}

_SPAWN_ATTRS = {"run", "Popen", "call", "check_call", "check_output", "getoutput"}


def _spawn_calls(tree: ast.AST) -> list[str]:
    """Names of direct process-spawning calls, e.g. 'subprocess.Popen'."""
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id == "subprocess" and func.attr in _SPAWN_ATTRS:
                found.append(f"subprocess.{func.attr}")
            elif func.value.id == "os" and func.attr in {"system", "popen", "execv"}:
                found.append(f"os.{func.attr}")
    return found


def _python_files() -> list[Path]:
    return sorted(p for p in _PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)


def test_the_package_has_files_to_scan():
    """Guards the guard: a broken glob would make every check below vacuous."""
    assert len(_python_files()) > 50


@pytest.mark.parametrize("path", _python_files(), ids=str)
def test_no_unsealed_process_spawn(path: Path):
    calls = _spawn_calls(ast.parse(path.read_text()))
    if not calls:
        return
    if path.as_posix() in _PENDING_MIGRATION:
        pytest.xfail("sealed-exec migration pending")
    assert path.as_posix() in _EXEMPT, (
        f"{path} spawns a child via {', '.join(sorted(set(calls)))}. "
        "Use run_sealed/popen_sealed from cyberai.core.sandbox so the child "
        "cannot inherit the operator's credentials, or add an explicit "
        "exemption with a reason."
    )


def test_exemptions_still_exist():
    """A stale exemption hides a module that no longer needs one."""
    for rel in _EXEMPT | _PENDING_MIGRATION:
        assert Path(rel).exists(), f"exempt module {rel} is gone; drop the entry"

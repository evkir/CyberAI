"""Reading a benchmark record must not start the toolchain probe.

The probe imports nine agent modules and the sandbox; the record it fills is
four strings. A reader -- the regression gate, the web verdict route -- builds
those strings off disk and runs no tool, so it must not pay for the probe.

Each check runs in a fresh interpreter on purpose. Inside the shared pytest
process ``cyberai.bench.environment`` is already imported by the probe's own
tests, so an in-process assertion would answer according to collection order
rather than according to the import graph.
"""

from __future__ import annotations

import subprocess
import sys

_PROGRAM = "import sys\nimport {module}\nprint('cyberai.bench.environment' in sys.modules)\n"


def _pulls_the_probe(module: str) -> bool:
    proc = subprocess.run(
        [sys.executable, "-c", _PROGRAM.format(module=module)],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip() == "True"


def test_the_manifest_does_not_pull_the_probe() -> None:
    assert not _pulls_the_probe("cyberai.bench.run_manifest")


def test_the_gate_does_not_pull_the_probe() -> None:
    assert not _pulls_the_probe("cyberai.bench.regression_gate")

"""Halmos symbolic-execution wrapper for Solidity contracts.

Runs `halmos --root <project> --json-output <report>.json` and parses the JSON
report into structured findings. A halmos COUNTEREXAMPLE (exitcode 1) is a
concrete input that breaks an asserted invariant — surfaced as a finding.
Degrades gracefully when the binary is absent, mirroring the slither/aderyn
wrappers. Halmos (symbolic testing over Foundry) is invoked as an external
process, never imported.

Unlike slither/aderyn, halmos does not scan a raw .sol file: it builds a Foundry
project via `forge` and executes symbolic test functions (`check_` / `invariant_`
prefixes). The target is therefore a project root, not a single source file.

Real `--json-output` shape (verified against the halmos 0.3.x result model):
  {"exitcode": int,
   "test_results": {
     "<path>:<Contract>": [
        {"name": "check_...(...)", "exitcode": int, "num_models": int|null,
         "models": [...]|null, "num_paths": [total, ok, blocked]|null,
         "time": [...]|null, "num_bounded_loops": int|null}]}}
Exit codes: 0 pass, 1 counterexample, 2 timeout, 3 stuck, 4 revert-all,
5 exception. Only exitcode == 1 (counterexample) is a confirmed invariant break.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyberai.web3.halmos")

_FALLBACK_PATHS = [
    os.path.expanduser("~/.local/bin/halmos"),
    os.path.expanduser("~/.cargo/bin/halmos"),
    "/usr/local/bin/halmos",
]

# Symbolic execution is slow; allow far more headroom than static analyzers.
DEFAULT_TIMEOUT = 600

# halmos exit codes (verified against the halmos 0.3.x Exitcode enum).
PASS = 0
COUNTEREXAMPLE = 1
TIMEOUT = 2
STUCK = 3
REVERT_ALL = 4
EXCEPTION = 5


def find_halmos() -> Optional[str]:
    """Locate the halmos binary: env, PATH, then known fallback dirs."""
    env = os.getenv("HALMOS_PATH")
    if env and os.path.exists(env):
        return env
    found = shutil.which("halmos")
    if found:
        return found
    for p in _FALLBACK_PATHS:
        if os.path.exists(p):
            return p
    return None


@dataclass
class HalmosFinding:
    """One halmos symbolic counterexample — a proven invariant break."""

    test_name: str  # e.g. "check_noReentrancy(address)"
    contract: str  # "<path>:<Contract>" key from test_results
    exitcode: int
    num_models: int = 0
    models: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def check(self) -> str:
        """Symbolic-analysis id, aligned with Slither/Aderyn `.check`.

        Intentionally not a SWC-mappable detector name: the guarded property is
        test-specific, so severity is left to the impact/confidence fallback and
        refined at the merge layer, never blanket-escalated here.
        """
        return "symbolic-counterexample"

    @property
    def impact(self) -> str:
        # The guarded invariant's value is unknown at the tool layer; stay
        # conservative rather than inflating every counterexample to Critical.
        return "Medium"

    @property
    def confidence(self) -> str:
        # A concrete counterexample is a mathematical proof, not a heuristic.
        return "High"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "test": self.test_name,
            "contract": self.contract,
            "num_models": self.num_models,
            "models": self.models,
            "source": "halmos",
        }


def parse_halmos_json(output: str) -> List[HalmosFinding]:
    """Parse a halmos `--json-output` report into counterexample findings.

    Only tests with exitcode == COUNTEREXAMPLE (1) are surfaced; passing,
    timing-out, or erroring tests are not findings.
    """
    output = output.strip()
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    results = data.get("test_results") or {}
    if not isinstance(results, dict):
        return []
    findings: List[HalmosFinding] = []
    for contract, tests in results.items():
        for test in tests or []:
            if test.get("exitcode") != COUNTEREXAMPLE:
                continue
            findings.append(
                HalmosFinding(
                    test_name=test.get("name", ""),
                    contract=contract,
                    exitcode=test.get("exitcode", COUNTEREXAMPLE),
                    num_models=test.get("num_models") or 0,
                    models=test.get("models") or [],
                    raw=test,
                )
            )
    return findings


class HalmosTool:
    """Runs halmos symbolic tests against a Foundry project root."""

    def __init__(self, halmos_path: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT):
        self.halmos_path = halmos_path or find_halmos()
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.halmos_path and os.path.exists(self.halmos_path))

    def analyze(
        self,
        project_root: str,
        contract: Optional[str] = None,
        function: str = "check_",
        loop: int = 2,
    ) -> List[HalmosFinding]:
        """Run halmos on a Foundry project. [] when unavailable or on failure.

        `project_root` must be a Foundry project (halmos builds via `forge`); a
        raw .sol file is not a valid target. `function` is the test-name prefix
        (halmos default `check_`); `loop` sets the loop-unroll bound.
        """
        if not self.available:
            logger.warning("halmos not found — skipping symbolic analysis")
            return []
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "halmos-report.json")
            cmd = [
                self.halmos_path or "halmos",
                "--root",
                project_root,
                "--function",
                function,
                "--loop",
                str(loop),
                "--json-output",
                out_path,
            ]
            if contract:
                cmd += ["--contract", contract]
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                logger.warning("halmos timed out after %ss", self.timeout)
                return []
            except Exception as exc:  # noqa: BLE001 — never hard-fail
                logger.warning("halmos execution failed: %s", exc)
                return []
            report = Path(out_path)
            if not report.exists():
                return []
            try:
                return parse_halmos_json(report.read_text(encoding="utf-8"))
            except OSError as exc:
                logger.warning("could not read halmos report: %s", exc)
                return []

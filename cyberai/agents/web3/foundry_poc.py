"""Foundry on-chain proof-of-concept runner for Web3 findings.

Runs `forge test --json` on a Foundry project whose exploit test replays a
candidate attack against a mainnet fork and asserts profit / state change. A
passing exploit test is a *confirmed* exploit: the profit assertion held on real
forked state, so the finding is proven rather than inferred — the on-chain
analog of an out-of-band callback for blind web vulnerabilities.

Only Success-status exploit tests surface as findings; failing or skipped runs
are dropped (an exploit that does not pay off is not a finding). Forge is invoked
as an external process, never imported, and the runner degrades gracefully when
the binary is absent, mirroring the slither/aderyn/halmos wrappers.

Real `forge test --json` shape (verified against forge 1.7.x):
  {"<path>:<Contract>": {
     "duration": "<humantime str>",
     "test_results": {
       "<testName>()": {
         "status": "Success" | "Failure" | "Skipped",
         "reason": str | null,
         "decoded_logs": [str, ...],   # populated with -vvv; carries evidence
         "kind": {"Unit": {"gas": int}} | {"Fuzz": ...} | {"Invariant": ...},
         ...}},
     "warnings": [...]}}
`status` is the TestStatus enum serialized as a string. `-vvv` populates
`decoded_logs`, where a harness `log_named_uint("profit_wei", ...)` becomes the
line `profit_wei: <n>` — parsed as profit evidence.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyberai.web3.foundry")

_FALLBACK_PATHS = [
    os.path.expanduser("~/.foundry/bin/forge"),
    os.path.expanduser("~/.local/bin/forge"),
    "/usr/local/bin/forge",
]

# Fork replay compiles and runs a test; allow generous headroom.
DEFAULT_TIMEOUT = 600

# forge TestStatus values, serialized as strings.
SUCCESS = "Success"
FAILURE = "Failure"
SKIPPED = "Skipped"

# A harness `log_named_uint("profit_wei", x)` decodes to `profit_wei: <n>`.
_PROFIT_LOG = re.compile(r"profit_wei:\s*(\d+)")


def find_forge() -> Optional[str]:
    """Locate the forge binary: env, PATH, then known fallback dirs."""
    env = os.getenv("FORGE_PATH")
    if env and os.path.exists(env):
        return env
    found = shutil.which("forge")
    if found:
        return found
    for p in _FALLBACK_PATHS:
        if os.path.exists(p):
            return p
    return None


@dataclass
class PoCFinding:
    """A confirmed on-chain exploit: a Foundry test that passed on a fork.

    Only ever constructed for Success-status exploit tests, so ``confirmed`` is
    always true; the field is kept explicit so serialized findings self-describe.
    """

    test_name: str  # e.g. "testExploit()"
    contract: str  # "<path>:<Contract>" key from the report
    status: str
    profit_wei: int = 0
    reason: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return self.status == SUCCESS

    @property
    def check(self) -> str:
        """Detector id, aligned with Slither/Aderyn/Halmos `.check`."""
        return "onchain-poc-exploit"

    @property
    def impact(self) -> str:
        # Unlike a symbolic counterexample (impact-unknown -> conservative), a
        # passing Foundry PoC replays a real exploit on a mainnet fork and its
        # profit assertion held: fund extraction is demonstrated, not inferred.
        # Rated High; combined with High confidence this classifies Critical.
        # Economic magnitude is refined at the Immunefi-export layer.
        return "High"

    @property
    def confidence(self) -> str:
        # A replayed on-chain exploit is proof, not a heuristic.
        return "High"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "test": self.test_name,
            "contract": self.contract,
            "status": self.status,
            "confirmed": self.confirmed,
            "profit_wei": self.profit_wei,
            "source": "foundry",
        }


def _extract_profit(decoded_logs: Any) -> int:
    """Pull `profit_wei: <n>` out of a test's decoded logs (0 if absent)."""
    if not isinstance(decoded_logs, list):
        return 0
    for line in decoded_logs:
        if not isinstance(line, str):
            continue
        m = _PROFIT_LOG.search(line)
        if m:
            return int(m.group(1))
    return 0


def parse_forge_test_json(output: str, match: str = "testExploit") -> List[PoCFinding]:
    """Parse `forge test --json` into confirmed-exploit findings.

    A test surfaces only when its name starts with `match` (the exploit
    entrypoint) and its status is Success — a passing PoC whose profit/impact
    assertion held. Failing, skipped, and non-exploit tests are dropped.
    """
    output = output.strip()
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    findings: List[PoCFinding] = []
    for contract, suite in data.items():
        if not isinstance(suite, dict):
            continue
        results = suite.get("test_results") or {}
        if not isinstance(results, dict):
            continue
        for name, res in results.items():
            if not isinstance(res, dict):
                continue
            if not name.startswith(match):
                continue
            if res.get("status") != SUCCESS:
                continue
            findings.append(
                PoCFinding(
                    test_name=name,
                    contract=contract,
                    status=SUCCESS,
                    profit_wei=_extract_profit(res.get("decoded_logs")),
                    reason=res.get("reason"),
                    raw=res,
                )
            )
    return findings


class ForgePoCTool:
    """Runs a Foundry exploit test against a fork and reports confirmed PoCs."""

    def __init__(self, forge_path: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT):
        self.forge_path = forge_path or find_forge()
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.forge_path and os.path.exists(self.forge_path))

    def run(
        self,
        project_root: str,
        rpc_url: Optional[str] = None,
        match: str = "testExploit",
    ) -> List[PoCFinding]:
        """Run `forge test --json --match-test <match>` in a Foundry project.

        `project_root` is a Foundry project holding the exploit test. When
        `rpc_url` is set the test forks that endpoint (`--fork-url`). Returns []
        when forge is unavailable, the run errors, or no confirmed PoC results.
        """
        if not self.available:
            logger.warning("forge not found — skipping on-chain PoC")
            return []
        cmd = [
            self.forge_path or "forge",
            "test",
            "--root",
            project_root,
            "--match-test",
            match,
            "-vvv",  # populate decoded_logs (profit_wei evidence)
            "--json",
        ]
        if rpc_url:
            cmd += ["--fork-url", rpc_url]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,  # forge exits non-zero when any test fails; parse stdout anyway
            )
        except subprocess.TimeoutExpired:
            logger.warning("forge test timed out after %ss", self.timeout)
            return []
        except Exception as exc:  # noqa: BLE001 — never hard-fail
            logger.warning("forge test failed: %s", exc)
            return []
        return parse_forge_test_json(proc.stdout, match=match)

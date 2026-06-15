"""Slither static-analysis wrapper for Solidity contracts (day 24).

Runs `slither <target> --json -` and parses results.detectors into structured
findings. Degrades gracefully when the binary is absent. Slither resolves the
compiler via solc-select automatically.

Real slither 0.11.5 JSON shape:
  {"success": bool, "error": ..., "results": {"detectors": [
     {"check","impact","confidence","description","markdown","id","elements"}
  ]}}
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyberai.web3.slither")

_FALLBACK_PATHS = [
    os.path.expanduser("~/.local/bin/slither"),
    "/usr/local/bin/slither",
    "/usr/bin/slither",
]

DEFAULT_TIMEOUT = 180


def find_slither() -> Optional[str]:
    """Locate the slither binary: env, PATH, then known fallback dirs."""
    env = os.getenv("SLITHER_PATH")
    if env and os.path.exists(env):
        return env
    found = shutil.which("slither")
    if found:
        return found
    for p in _FALLBACK_PATHS:
        if os.path.exists(p):
            return p
    return None


@dataclass
class SlitherFinding:
    """One slither detector result."""

    check: str
    impact: str
    confidence: str
    description: str
    detector_id: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "impact": self.impact,
            "confidence": self.confidence,
            "description": self.description.strip(),
            "detector_id": self.detector_id,
        }


def parse_slither_json(output: str) -> List[SlitherFinding]:
    """Parse `slither --json -` output into findings."""
    output = output.strip()
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    detectors = (data.get("results") or {}).get("detectors", []) or []
    findings = []
    for d in detectors:
        findings.append(
            SlitherFinding(
                check=d.get("check", ""),
                impact=d.get("impact", "Informational"),
                confidence=d.get("confidence", "Low"),
                description=d.get("description", ""),
                detector_id=d.get("id", ""),
                raw=d,
            )
        )
    return findings


class SlitherTool:
    """Runs slither against a Solidity source file or directory."""

    def __init__(
        self,
        slither_path: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.slither_path = slither_path or find_slither()
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.slither_path and os.path.exists(self.slither_path))

    def analyze(self, target: str) -> List[SlitherFinding]:
        """Run slither on a .sol file/dir. [] when unavailable or on failure.

        slither writes JSON to stdout with `--json -`; it exits non-zero when
        findings exist, so the return code is not treated as failure.
        """
        if not self.available:
            logger.warning("slither not found — skipping static analysis")
            return []
        cmd = [self.slither_path or "slither", target, "--json", "-"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("slither timed out after %ss", self.timeout)
            return []
        except Exception as exc:  # noqa: BLE001 — never hard-fail
            logger.warning("slither execution failed: %s", exc)
            return []
        # slither prints JSON to stdout even when detectors are found (rc!=0).
        return parse_slither_json(proc.stdout)

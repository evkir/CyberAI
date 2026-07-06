"""Aderyn static-analysis wrapper for Solidity contracts.

Runs `aderyn <root|file.sol> -o <report>.json --skip-update-check` and parses the
JSON report into structured findings. Degrades gracefully when the binary is
absent, mirroring the slither wrapper. Aderyn (Cyfrin, Rust) is invoked as an
external process, never imported.

Real aderyn JSON shape:
  {"issue_count": {"high": N, "low": M},
   "high_issues": {"issues": [
       {"title", "description", "detector_name", "instances": [...]}]},
   "low_issues": {"issues": [...]}}
Aderyn groups findings as High / Low; `detector_name` is a kebab-case id.
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

logger = logging.getLogger("cyberai.web3.aderyn")

_FALLBACK_PATHS = [
    os.path.expanduser("~/.cyfrin/bin/aderyn"),
    os.path.expanduser("~/.local/bin/aderyn"),
    os.path.expanduser("~/.cargo/bin/aderyn"),
    "/usr/local/bin/aderyn",
]

DEFAULT_TIMEOUT = 180

# Aderyn severity groups -> (impact, confidence) compatible with immunefi.classify.
_GROUP_IMPACT = {
    "critical": ("High", "High"),
    "high": ("High", "Medium"),
    "medium": ("Medium", "Medium"),
    "low": ("Low", "Medium"),
}


def find_aderyn() -> Optional[str]:
    """Locate the aderyn binary: env, PATH, then known fallback dirs."""
    env = os.getenv("ADERYN_PATH")
    if env and os.path.exists(env):
        return env
    found = shutil.which("aderyn")
    if found:
        return found
    for p in _FALLBACK_PATHS:
        if os.path.exists(p):
            return p
    return None


@dataclass
class AderynFinding:
    """One aderyn detector result (normalized for merge + severity)."""

    detector_name: str
    title: str
    severity: str  # aderyn group: "High" | "Low" (or Critical/Medium if present)
    description: str
    instances: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def check(self) -> str:
        """Detector id, aligned with SlitherFinding.check for shared handling."""
        return self.detector_name

    @property
    def impact(self) -> str:
        return _GROUP_IMPACT.get(self.severity.lower(), ("Low", "Medium"))[0]

    @property
    def confidence(self) -> str:
        return _GROUP_IMPACT.get(self.severity.lower(), ("Low", "Medium"))[1]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.detector_name,
            "title": self.title.strip(),
            "severity": self.severity,
            "description": self.description.strip(),
            "instances": self.instances,
            "source": "aderyn",
        }


def parse_aderyn_json(output: str) -> List[AderynFinding]:
    """Parse an aderyn JSON report (string) into findings."""
    output = output.strip()
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    findings: List[AderynFinding] = []
    for group in ("critical_issues", "high_issues", "medium_issues", "low_issues"):
        label = group.replace("_issues", "").capitalize()
        for issue in (data.get(group) or {}).get("issues", []) or []:
            findings.append(
                AderynFinding(
                    detector_name=issue.get("detector_name", ""),
                    title=issue.get("title", ""),
                    severity=label,
                    description=issue.get("description", ""),
                    instances=len(issue.get("instances", []) or []),
                    raw=issue,
                )
            )
    return findings


class AderynTool:
    """Runs aderyn against a Solidity file or Foundry/Hardhat project root."""

    def __init__(self, aderyn_path: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT):
        self.aderyn_path = aderyn_path or find_aderyn()
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.aderyn_path and os.path.exists(self.aderyn_path))

    def analyze(self, target: str) -> List[AderynFinding]:
        """Run aderyn on a .sol file / project root. [] when unavailable or on failure."""
        if not self.available:
            logger.warning("aderyn not found — skipping static analysis")
            return []
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "aderyn-report.json")
            cmd = [
                self.aderyn_path or "aderyn",
                target,
                "-o",
                out_path,
                "--skip-update-check",
            ]
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                logger.warning("aderyn timed out after %ss", self.timeout)
                return []
            except Exception as exc:  # noqa: BLE001 — never hard-fail
                logger.warning("aderyn execution failed: %s", exc)
                return []
            report = Path(out_path)
            if not report.exists():
                return []
            try:
                return parse_aderyn_json(report.read_text(encoding="utf-8"))
            except OSError as exc:
                logger.warning("could not read aderyn report: %s", exc)
                return []

"""MST bridge — optional MAS-Sentry Toolkit integration for low-level MCP fuzzing.

Shells out to the ``mas-sentry`` CLI (a separate MASec Lab tool) for
protocol-level malformed-traffic fuzzing of MCP servers, complementing
CyberAI's static scans. MST is invoked as an external process — never imported —
so it stays a fully optional dependency and its findings are parsed from the
JSON report it writes. Degrades gracefully when the binary is absent
(available=False, empty results), mirroring the searchsploit/slither wrappers.

CLI contract (``mas-sentry mcp scan``)::

    mas-sentry mcp scan --target <stdio://cmd | http(s)://host/mcp> \
        --checks all --out <report.json> [--confirm-scope]

Report JSON shape: ``[{"check": str, "severity": str, "detail": str}, ...]``.
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
from urllib.parse import urlparse

from cyberai.core.scan_session import Severity

logger = logging.getLogger("cyberai.mcp.mst_bridge")

MST_BINARY = "mas-sentry"
DEFAULT_TIMEOUT = 120
_LAB_SUFFIXES = (".lab", ".test", ".local")
_LAB_HOSTS = {"localhost", "127.0.0.1", "::1"}

# MST severity strings map 1:1 onto CyberAI Severity; unknown -> INFO.
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


def find_mst() -> Optional[str]:
    """Locate the mas-sentry binary: env override (MAS_SENTRY_PATH), then PATH."""
    env = os.getenv("MAS_SENTRY_PATH")
    if env and os.path.exists(env):
        return env
    return shutil.which(MST_BINARY)


def map_severity(raw: str) -> Severity:
    """Map an MST severity string onto the CyberAI Severity enum (INFO fallback)."""
    return _SEVERITY_MAP.get((raw or "").strip().upper(), Severity.INFO)


def build_target(endpoint: str, transport: Optional[str] = None) -> str:
    """Map a CyberAI (endpoint, transport) pair to an MST ``--target`` string.

    http(s):// passes through; sse:// becomes https://; anything else (a bare
    command or a forced-stdio transport) becomes a ``stdio://`` command target.
    """
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    if endpoint.startswith("sse://"):
        return "https://" + endpoint[len("sse://") :]
    if endpoint.startswith("stdio://"):
        return endpoint
    return f"stdio://{endpoint}"


def is_lab_target(target: str) -> bool:
    """True when MST's ``--confirm-scope`` is not required.

    stdio targets run as a local subprocess (always in scope); http(s) targets
    are lab-safe only for localhost or the .lab/.test/.local suffixes.
    """
    if target.startswith("stdio://"):
        return True
    host = (urlparse(target).hostname or "").lower()
    return host in _LAB_HOSTS or host.endswith(_LAB_SUFFIXES)


@dataclass
class MSTFinding:
    """One finding parsed from an MST MCP scan report."""

    check: str
    severity: Severity
    detail: str
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity.value,
            "detail": self.detail,
        }


class MSTBridge:
    """Optional bridge to the mas-sentry CLI for low-level MCP fuzzing.

    When mas-sentry is not installed, ``available`` is False and ``fuzz()``
    returns [] without raising. Non-lab targets are skipped unless the caller
    explicitly confirms scope, matching CyberAI's authorized-scope discipline.
    """

    def __init__(self, mst_path: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT):
        self.mst_path = mst_path or find_mst()
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.mst_path and os.path.exists(self.mst_path))

    def fuzz(
        self,
        endpoint: str,
        transport: Optional[str] = None,
        confirm_scope: bool = False,
    ) -> List[MSTFinding]:
        """Run ``mas-sentry mcp scan`` against endpoint and parse findings.

        Returns [] when MST is unavailable, when a non-lab target is not
        scope-confirmed, or on any invocation/parse error.
        """
        if not self.available:
            logger.warning("mas-sentry not found — skipping MST low-level fuzzing")
            return []
        target = build_target(endpoint, transport)
        lab = is_lab_target(target)
        if not lab and not confirm_scope:
            logger.warning(
                "MST fuzzing skipped for non-lab target %s (scope not confirmed)", target
            )
            return []
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "mst_mcp.json")
            cmd = [
                self.mst_path or MST_BINARY,
                "mcp",
                "scan",
                "--target",
                target,
                "--checks",
                "all",
                "--out",
                out_path,
            ]
            if not lab:
                cmd.append("--confirm-scope")
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
            except (subprocess.SubprocessError, OSError) as exc:
                logger.warning("mas-sentry invocation failed: %s", exc)
                return []
            return self._parse_report(out_path)

    @staticmethod
    def _parse_report(out_path: str) -> List[MSTFinding]:
        """Parse the MST report JSON (list of check/severity/detail dicts)."""
        path = Path(out_path)
        if not path.exists():
            return []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("could not parse MST report: %s", exc)
            return []
        findings: List[MSTFinding] = []
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict):
                continue
            findings.append(
                MSTFinding(
                    check=str(item.get("check", "")),
                    severity=map_severity(str(item.get("severity", ""))),
                    detail=str(item.get("detail", "")),
                    raw=item,
                )
            )
        return findings

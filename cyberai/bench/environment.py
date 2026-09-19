"""
Toolchain probe -- which external binaries a run would actually use, and at
which version.

A benchmark number is produced by a specific toolchain. Publishing the score
without the versions leaves it unreproducible in the only way that matters: a
reader cannot tell whether a difference came from our code or from nuclei
moving a template underneath it.

Three decisions here are measurements, not preferences.

  - The path comes from the owning module's own ``find_*`` resolver, never
    from ``shutil.which``. Every resolver honours an env override
    (``NMAP_PATH``, ``ADERYN_PATH``, ...) and its own fallback directories,
    so ``which`` would record the version of a binary the run never runs.
  - Success is a parsed version, not a return code. A tool is free to exit
    non-zero while printing its version, and free to exit zero while printing
    a help page.
  - The version line is the first non-empty line of stdout, falling back to
    stderr, and the first line is load-bearing rather than convenient:
    measured here, nmap's third line names liblua 5.4.8 and forge's third
    carries a build timestamp, both of which parse as dotted numbers.
    Measured streams: nmap, slither, aderyn, forge, anvil and halmos answer
    on stdout, nuclei on stderr. Colour codes are left in place -- nuclei
    colours its banner, but no tool on this toolchain emits a line that is
    non-empty before colour removal and empty after, so stripping them would
    change no outcome, and a guard that changes no outcome is not a guard.

Absence is recorded, never invented. A tool that is not installed, whose
version flag has not been measured, or that answers in an unparsed shape
yields ``version=None`` together with the reason: a guessed version in a
provenance record reads as a measurement.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from cyberai.agents.exploit.nuclei_engine import find_nuclei
from cyberai.agents.exploit.searchsploit import find_searchsploit
from cyberai.agents.mcp_scan.mst_bridge import find_mst
from cyberai.agents.recon.nmap_tool import find_nmap
from cyberai.agents.web3.aderyn_tool import find_aderyn
from cyberai.agents.web3.anvil_harness import find_anvil
from cyberai.agents.web3.foundry_poc import find_forge
from cyberai.agents.web3.halmos_tool import find_halmos
from cyberai.agents.web3.slither_tool import find_slither
from cyberai.bench.run_manifest import ToolVersion
from cyberai.core.sandbox import run_sealed

VERSION_TIMEOUT = 20

# Shorter than VERSION_TIMEOUT, and the difference is the caller, not the tool.
# A benchmark manifest is written once and has to record a version even from a
# tool that starts slowly. `status` is the command an operator runs when
# something is already wrong, and nine hung binaries at VERSION_TIMEOUT would
# hold that answer for three minutes. Measured: a binary that never answers
# costs exactly the timeout, 20.02 s at the default.
STATUS_VERSION_TIMEOUT = 3

NOT_INSTALLED = "not installed"
FLAG_NOT_MEASURED = "version flag not measured"
NOT_PARSED = "version not parsed"

_VERSION = re.compile(r"\d+\.\d+(?:\.\d+)?")


@dataclass(frozen=True)
class ToolProbe:
    """How to ask one external binary for its version.

    ``flag`` is None when this toolchain has not measured how the tool reports
    a version. A None flag means the binary is located but never executed.
    """

    name: str
    resolver: Callable[[], str | None]
    flag: str | None


TOOL_PROBES: tuple[ToolProbe, ...] = (
    ToolProbe("nmap", find_nmap, "--version"),
    ToolProbe("nuclei", find_nuclei, "-version"),
    ToolProbe("searchsploit", find_searchsploit, None),
    ToolProbe("slither", find_slither, "--version"),
    ToolProbe("aderyn", find_aderyn, "--version"),
    ToolProbe("forge", find_forge, "--version"),
    ToolProbe("anvil", find_anvil, "--version"),
    ToolProbe("halmos", find_halmos, "--version"),
    ToolProbe("mas-sentry", find_mst, None),
)


def _first_line(text: str) -> str:
    """First non-empty line, stripped."""
    for raw in text.splitlines():
        line = raw.strip()
        if line:
            return line
    return ""


def parse_version(stdout: str, stderr: str) -> str | None:
    """First dotted number on the first non-empty line; stdout before stderr."""
    for stream in (stdout, stderr):
        line = _first_line(stream)
        if not line:
            continue
        found = _VERSION.search(line)
        if found:
            return found.group(0)
    return None


def probe_tool(probe: ToolProbe, *, timeout: float = VERSION_TIMEOUT) -> ToolVersion:
    """Resolve one binary and read its version. Never raises.

    ``timeout`` is keyword-only and defaults to the manifest's budget, so the
    callers that were here before this parameter existed read the same way.
    """
    path = probe.resolver()
    if path is None:
        return ToolVersion(probe.name, None, None, NOT_INSTALLED)
    if probe.flag is None:
        return ToolVersion(probe.name, path, None, FLAG_NOT_MEASURED)
    try:
        proc = run_sealed([path, probe.flag], timeout=timeout)
    except (subprocess.SubprocessError, OSError) as exc:
        return ToolVersion(probe.name, path, None, f"probe failed: {type(exc).__name__}")
    version = parse_version(proc.stdout, proc.stderr)
    if version is None:
        return ToolVersion(probe.name, path, None, NOT_PARSED)
    return ToolVersion(probe.name, path, version, "")


def probe_toolchain(
    probes: Sequence[ToolProbe] = TOOL_PROBES, *, timeout: float = VERSION_TIMEOUT
) -> tuple[ToolVersion, ...]:
    """Probe every binary the platform drives, in registry order.

    A tuple, not a list: the result is stored on a frozen RunManifest and
    fingerprinted, and a mutable sequence there would be a shared reference
    into a record that claims to be immutable.
    """
    return tuple(probe_tool(probe, timeout=timeout) for probe in probes)

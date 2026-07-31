"""Anvil mainnet-fork harness for on-chain proof-of-concept validation.

Spins up a local `anvil` node that forks a live network over an RPC endpoint,
so a candidate exploit can be replayed against real mainnet state instead of a
toy deployment. The node is a managed subprocess: started on context entry,
torn down on exit. Anvil is invoked as an external process, never imported, and
the harness degrades gracefully when the binary is absent (no fork, no crash) —
mirroring the slither/aderyn/halmos wrappers.

Readiness is detected from anvil's startup banner, which prints a line of the
form `Listening on 127.0.0.1:<port>` once the JSON-RPC server is accepting
connections (verified against anvil 1.7.x).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Optional

from cyberai.core.sandbox import operator_home, popen_sealed

logger = logging.getLogger("cyberai.web3.anvil")

_FALLBACK_PATHS = [
    os.path.expanduser("~/.foundry/bin/anvil"),
    os.path.expanduser("~/.local/bin/anvil"),
    "/usr/local/bin/anvil",
]

# Default JSON-RPC port anvil binds when none is given.
DEFAULT_PORT = 8545
# Seconds to wait for the fork node to come up before giving up.
DEFAULT_TIMEOUT = 30
_READY_MARKER = "Listening on"


def find_anvil() -> Optional[str]:
    """Locate the anvil binary: env, PATH, then known fallback dirs."""
    env = os.getenv("ANVIL_PATH")
    if env and os.path.exists(env):
        return env
    found = shutil.which("anvil")
    if found:
        return found
    for p in _FALLBACK_PATHS:
        if os.path.exists(p):
            return p
    return None


class AnvilFork:
    """A managed anvil fork node, usable as a context manager.

    ``rpc_url`` is populated only once the node is confirmed listening; callers
    check it and skip the on-chain path when it is ``None`` (unavailable binary,
    early exit, or readiness timeout).
    """

    def __init__(
        self,
        fork_url: Optional[str] = None,
        fork_block: Optional[int] = None,
        port: int = DEFAULT_PORT,
        anvil_path: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.fork_url = fork_url
        self.fork_block = fork_block
        self.port = port
        self.anvil_path = anvil_path or find_anvil()
        self.timeout = timeout
        self.rpc_url: Optional[str] = None
        self._proc: Optional[subprocess.Popen] = None
        self._log_path: Optional[str] = None

    @property
    def available(self) -> bool:
        return bool(self.anvil_path and os.path.exists(self.anvil_path))

    def _build_cmd(self) -> List[str]:
        cmd = [self.anvil_path or "anvil", "--port", str(self.port)]
        if self.fork_url:
            cmd += ["--fork-url", self.fork_url]
        if self.fork_block is not None:
            cmd += ["--fork-block-number", str(self.fork_block)]
        return cmd

    def start(self) -> bool:
        """Launch anvil and block until it reports listening. False on failure."""
        if not self.available:
            logger.warning("anvil not found — skipping on-chain fork")
            return False
        log_file = tempfile.NamedTemporaryFile(
            prefix="anvil-", suffix=".log", delete=False, mode="w"
        )
        self._log_path = log_file.name
        try:
            self._proc = popen_sealed(
                self._build_cmd(),
                stdout=log_file,
                stderr=subprocess.STDOUT,
                home=operator_home(),
            )
        except Exception as exc:  # noqa: BLE001 — never hard-fail on spawn
            logger.warning("anvil failed to start: %s", exc)
            self._cleanup_log()
            return False
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                logger.warning("anvil exited before becoming ready")
                self.stop()
                return False
            try:
                banner = Path(self._log_path).read_text(encoding="utf-8")
            except OSError:
                banner = ""
            if _READY_MARKER in banner:
                self.rpc_url = f"http://127.0.0.1:{self.port}"
                return True
            time.sleep(0.2)
        logger.warning("anvil did not report ready within %ss", self.timeout)
        self.stop()
        return False

    def stop(self) -> None:
        """Terminate the node and drop the rpc endpoint."""
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        self.rpc_url = None
        self._cleanup_log()

    def _cleanup_log(self) -> None:
        if self._log_path and os.path.exists(self._log_path):
            try:
                os.unlink(self._log_path)
            except OSError:
                pass
        self._log_path = None

    def __enter__(self) -> AnvilFork:
        self.start()
        return self

    def __exit__(self, *exc) -> bool:
        self.stop()
        return False

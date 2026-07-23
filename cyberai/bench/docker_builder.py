"""
Ephemeral Docker builder for the local vulnerable-target suite.

Builds and runs our own bench apps (cyberai/bench/apps/) in throwaway
containers so the engine can be measured against live targets. Degrades
gracefully when Docker is absent (available=False) — exactly like the nuclei
and slither wrappers — so CI and Docker-less environments never break.
"""

from __future__ import annotations

import logging
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from cyberai.bench.targets import VulnTarget

logger = logging.getLogger("cyberai.bench.docker")

_BASE_IMAGE = "python:3.12-slim"
DEFAULT_TIMEOUT = 120
# Directory holding our vulnerable apps; mounted read-only into the container.
_APPS_DIR = Path(__file__).resolve().parent / "apps"
# How long to wait for the app inside the container to accept connections.
READY_TIMEOUT = 20


@dataclass(frozen=True)
class RunningTarget:
    """Handle to a live benchmark container."""

    target_id: str
    container_id: str
    base_url: str


class DockerBuilder:
    """Builds/runs bench-app containers. No-op (graceful) without Docker."""

    def __init__(self, base_image: str = _BASE_IMAGE) -> None:
        self.base_image = base_image

    @property
    def available(self) -> bool:
        """True only if a usable docker CLI is on PATH."""
        return shutil.which("docker") is not None

    def _run(self, args: list[str], timeout: int = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)

    def start(self, target: VulnTarget) -> RunningTarget | None:
        """Start a container for `target`. Returns None when Docker is absent
        or the run fails — callers treat None as 'target unavailable'."""
        if not self.available:
            logger.info("docker unavailable; skipping target %s", target.id)
            return None
        name = f"cyberai-bench-{target.id}"
        try:
            proc = self._run(
                [
                    "run",
                    "-d",
                    "--rm",
                    "--name",
                    name,
                    "-p",
                    f"{target.port}:{target.port}",
                    "-v",
                    f"{_APPS_DIR}:/apps:ro",
                    "-w",
                    "/apps",
                    self.base_image,
                    "python",
                    f"/apps/{target.app}.py",
                    str(target.port),
                ]
            )
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("docker start failed for %s: %s", target.id, exc)
            return None
        if proc.returncode != 0:
            logger.warning("docker start nonzero for %s: %s", target.id, proc.stderr.strip())
            return None
        running = RunningTarget(
            target_id=target.id,
            container_id=proc.stdout.strip(),
            base_url=f"http://localhost:{target.port}",
        )
        if not self._wait_ready(target.port):
            logger.warning("target %s never accepted connections; stopping", target.id)
            self.stop(running)
            return None
        return running

    @staticmethod
    def _wait_ready(port: int, timeout: int = READY_TIMEOUT) -> bool:
        """Poll the published port until the app inside the container listens."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    return True
            time.sleep(0.3)
        return False

    def stop(self, running: RunningTarget) -> bool:
        """Stop a container. False on failure or when Docker is absent."""
        if not self.available:
            return False
        try:
            proc = self._run(["stop", running.container_id])
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("docker stop failed for %s: %s", running.target_id, exc)
            return False
        return proc.returncode == 0

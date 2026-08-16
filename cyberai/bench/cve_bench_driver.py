"""
Sandbox driver for CVE-Bench: bring one upstream task up, and take it down.

The upstream stack per task is not a container, it is a compose project: the
target, a database, a secrets initialiser that plants the canaries the grader
reads, two networks, and a generated override that publishes the ports. All of
that is theirs and it moves between releases. Reimplementing it here would be a
slow, silent drift into measuring something that is no longer CVE-Bench, so
this driver shells out to their own `run` script and owns nothing but the
timeouts and the failure handling.

Cleanup is the part that has to be reliable: a leaked compose project keeps
host ports 9090/9091 bound and every later task fails for a reason that has
nothing to do with the agent. `stop()` is therefore called on every failure
path, including a start that timed out halfway.

Absent Docker, `uv` or the checkout, `start()` returns None and says why —
the same contract as DockerBuilder, so a runner treats an unavailable target
as unsolved rather than as an error in CyberAI.
"""

from __future__ import annotations

import logging
import shutil
import socket
import subprocess
import time
from pathlib import Path

import httpx

from cyberai.bench.cve_bench import APP_PORT, DEFAULT_VERSION, EVALUATOR_PORT, CVEBenchAdapter
from cyberai.bench.docker_builder import RunningTarget
from cyberai.bench.runner import BenchTask
from cyberai.core.sandbox import operator_home, run_sealed

logger = logging.getLogger("cyberai.bench.cve_bench_driver")

# Upstream `up` waits for health itself with a 180s cap, then we still have to
# survive an image pull on first contact with a task.
UP_TIMEOUT = 1800
DOWN_TIMEOUT = 300
# How long to wait for the grader to report the stack healthy after `up`.
READY_TIMEOUT = 90


class CVEBenchSandbox:
    """Runs one CVE-Bench task at a time through the upstream `run` script."""

    def __init__(
        self,
        root: Path | str | None = None,
        version: str = DEFAULT_VERSION,
        build: bool = False,
        up_timeout: int = UP_TIMEOUT,
        down_timeout: int = DOWN_TIMEOUT,
        ready_timeout: int = READY_TIMEOUT,
    ) -> None:
        adapter = CVEBenchAdapter(root=root, version=version)
        self.root = adapter.root
        self.version = version
        # Building all forty images locally takes hours; the upstream images
        # are published, so pulling is the default and building is opt-in.
        self.build = build
        self.up_timeout = up_timeout
        self.down_timeout = down_timeout
        self.ready_timeout = ready_timeout
        self._adapter = adapter
        self._compose_ok: bool | None = None

    # -- availability ---------------------------------------------------
    @property
    def unavailable_reason(self) -> str | None:
        """Why a task cannot be brought up, in words an operator can act on."""
        reason = self._adapter.unavailable_reason
        if reason is not None:
            return reason
        if shutil.which("docker") is None:
            return "docker is not on PATH"
        if shutil.which("uv") is None:
            return "uv is not on PATH; the upstream run script needs it"
        if not self._compose_available():
            return "docker compose v2 is not installed; the upstream stack needs it"
        return None

    def _port_in_use(self, port: int = APP_PORT) -> bool:
        """True when something already holds the host port a task publishes on.

        Upstream publishes every task on the same two host ports, so anything
        else already listening -- a phantom-grid on its default 9090, a task
        that leaked -- makes `up` fail, and the log then attributes that to the
        stack. A connect probe, not a bind: a bind would have to release the
        port again before `up` claims it, and the gap is a race we would own.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex(("127.0.0.1", port)) == 0

    def _compose_available(self) -> bool:
        """Check the compose plugin once, and remember the answer.

        Checking `docker` alone is not enough: the upstream script swallows a
        compose failure and still exits zero, so without this the driver would
        bring nothing up and then wait out the full readiness timeout on every
        task in the suite, reporting each as a target that failed to start.
        """
        if self._compose_ok is None:
            try:
                # A bare plugin probe: no operator HOME needed, so the
                # child does not get one.
                proc = run_sealed(["docker", "compose", "version"], timeout=30, check=False)
                self._compose_ok = proc.returncode == 0
            except (subprocess.SubprocessError, OSError):
                self._compose_ok = False
        return self._compose_ok

    @property
    def available(self) -> bool:
        return self.unavailable_reason is None

    # -- lifecycle ------------------------------------------------------
    def start(self, task: BenchTask) -> RunningTarget | None:
        """Bring `task` up. None means unavailable, never a silent failure."""
        reason = self.unavailable_reason
        if reason is not None:
            logger.info("CVE-Bench unavailable, skipping %s: %s", task.id, reason)
            return None

        if self._port_in_use():
            logger.warning(
                "host port %s is already taken; skipping %s. Stop the other "
                "listener first -- phantom-grid defaults to this port.",
                APP_PORT,
                task.id,
            )
            return None

        args = ["up", task.id] + ([] if self.build else ["--no-build"])
        proc = self._run(args, self.up_timeout)
        running = RunningTarget(
            target_id=task.id,
            # Upstream names the compose project after the lowercased CVE.
            container_id=task.id.lower(),
            base_url=f"http://127.0.0.1:{APP_PORT}",
        )
        if proc is None or proc.returncode != 0:
            detail = "timed out" if proc is None else (proc.stderr or proc.stdout).strip()[-400:]
            logger.warning("CVE-Bench up failed for %s: %s", task.id, detail)
            # A partial stack still holds the ports; tear it down regardless.
            self.stop(running)
            return None

        if not self._wait_healthy():
            logger.warning("grader never reported %s healthy; tearing down", task.id)
            self.stop(running)
            return None
        return running

    def stop(self, running: RunningTarget) -> bool:
        """Take the task down and drop its volumes. False if that failed."""
        if self._adapter.unavailable_reason is not None:
            return False
        proc = self._run(["down", running.target_id], self.down_timeout)
        if proc is None or proc.returncode != 0:
            logger.warning("CVE-Bench down failed for %s", running.target_id)
            return False
        return True

    # -- internals ------------------------------------------------------
    def _run(self, args: list[str], timeout: int) -> subprocess.CompletedProcess | None:
        """Invoke the upstream run script; None on timeout or a missing binary.

        The script used to receive a copy of os.environ, which handed our LLM
        API keys to third-party benchmark code and to every container it
        starts. It gets exactly one variable now.

        operator_home is required rather than convenient: the script shells out
        to `uv run`, which resolves its cache under ~/.cache/uv. A synthetic
        home would re-resolve the whole dependency tree on every invocation.
        """
        try:
            return run_sealed(
                ["./run", *args],
                cwd=str(self.root),
                timeout=timeout,
                extra_env={"CVEBENCH_VERSION": self.version},
                home=operator_home(),
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.warning("CVE-Bench `run %s` exceeded %ss", " ".join(args), timeout)
            return None
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("CVE-Bench `run %s` failed: %s", " ".join(args), exc)
            return None

    def _wait_healthy(self) -> bool:
        """Poll the grader's health endpoint until the stack is serving.

        The grader answers 200 only after five consecutive healthy samples of
        the application, so this is a stronger readiness signal than a TCP
        connect to the published port — which Docker accepts before anything
        is listening inside the container.
        """
        url = f"http://127.0.0.1:{EVALUATOR_PORT}/health"
        deadline = time.monotonic() + self.ready_timeout
        while time.monotonic() < deadline:
            try:
                if httpx.get(url, timeout=2.0).status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
            time.sleep(1.0)
        return False

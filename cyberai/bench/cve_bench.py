"""
CVEBenchAdapter — loads CVE-Bench tasks into the BenchTask contract.

CVE-Bench (UIUC Kang Lab) evaluates agents on real web applications carrying
critical-severity CVEs. Its value to us is the part that is hardest to build
honestly: a grader that lives inside the target container and decides success
from canaries and secrets rather than from anything the attacker echoed back.
Eight criteria count as a solve — file access, RCE, database access or
modification, unauthorised admin login, privilege escalation, an outbound
request, and denial of service.

This module reads the upstream checkout without vendoring any of it:

    src/<version>/challenges/<CVE-ID>/
        eval.yml       task name, sandbox, variant prompts, metadata block
        compose.yml    the stack the upstream `run` script brings up
        solution/      reference exploit (present for some tasks)

Only the fields we consume are read, and unknown keys are ignored, so upstream
additions do not break the loader.

Two things the upstream harness fixes for us, both verified against the `run`
script rather than assumed:

  - `./run up <CVE>` publishes the primary application on host port 9090 and
    the evaluator on 9091, generated per task by
    `scripts/get_expose_services.py`. The in-container port varies per task
    (80, 1337, 8080, ...) and a few tasks expose a second service; the host
    port of the app under attack does not. Fixed ports also mean one task at a
    time, which the adapter states rather than pretending otherwise.
  - the verdict is a single JSON object from the evaluator, so grading needs no
    logic of ours and cannot drift from theirs.

A missing checkout yields an empty suite and a stated reason, never an
exception: the benchmark is an optional local dependency (Docker, uv, several
GB of images), and neither CI nor an install may depend on it.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

from cyberai.bench.runner import BenchAdapter, BenchTask

logger = logging.getLogger("cyberai.bench.cve_bench")

SUITE_NAME = "cve-bench"

# Where a checkout is expected when neither an argument nor CVEBENCH_DIR says.
DEFAULT_ROOT = Path.home() / "oscp" / "tools" / "cve-bench"

# Host ports the upstream `run up` publishes for every task.
APP_PORT = 9090
EVALUATOR_PORT = 9091

# The upstream dataset ships several severity tiers under src/.
DEFAULT_VERSION = "critical"

# The grader endpoint. Its answer is the whole success criterion.
_VERDICT_PATH = "/done"

# Variant that ships the reference exploit; never a task for the agent to run.
_SOLUTION_VARIANT = "solution"


def _split_urls(raw: Any) -> list[str]:
    """Upstream lists co-hosted services comma-separated in one field."""
    return [part.strip() for part in str(raw or "").split(",") if part.strip()]


class CVEBenchAdapter(BenchAdapter):
    """Loads CVE-Bench tasks from a local upstream checkout.

    Constructed with no arguments by the suite registry, so the checkout is
    discovered from `CVEBENCH_DIR` or the conventional path under ~/oscp/tools.
    """

    name = SUITE_NAME

    def __init__(
        self,
        root: Path | str | None = None,
        version: str = DEFAULT_VERSION,
    ) -> None:
        chosen = root if root is not None else os.environ.get("CVEBENCH_DIR") or DEFAULT_ROOT
        self.root = Path(chosen).expanduser()
        self.version = version
        self.challenges_dir = self.root / "src" / version / "challenges"

    # -- availability ---------------------------------------------------
    @property
    def unavailable_reason(self) -> str | None:
        """Why the suite cannot load, in words an operator can act on."""
        if not self.root.is_dir():
            return (
                f"no CVE-Bench checkout at {self.root}; clone "
                "uiuc-kang-lab/cve-bench or set CVEBENCH_DIR"
            )
        if not (self.root / "run").is_file():
            return f"{self.root} has no `run` script; not a CVE-Bench checkout"
        if not self.challenges_dir.is_dir():
            return f"no challenges for version '{self.version}' under {self.challenges_dir}"
        return None

    @property
    def available(self) -> bool:
        return self.unavailable_reason is None

    # -- loading --------------------------------------------------------
    def load_tasks(self) -> list[BenchTask]:
        """Return one BenchTask per challenge; empty when the checkout is absent."""
        reason = self.unavailable_reason
        if reason is not None:
            logger.info("CVE-Bench suite empty: %s", reason)
            return []

        tasks: list[BenchTask] = []
        for eval_yml in sorted(self.challenges_dir.glob("*/eval.yml")):
            task = self._load_one(eval_yml)
            if task is not None:
                tasks.append(task)
        if not tasks:
            logger.warning("CVE-Bench checkout at %s has no readable tasks", self.root)
        return tasks

    def get_task(self, task_id: str) -> BenchTask | None:
        """Resolve a single task by CVE id."""
        return next((t for t in self.load_tasks() if t.id == task_id), None)

    def _load_one(self, eval_yml: Path) -> BenchTask | None:
        """Parse one challenge; unreadable ones are skipped, not fatal."""
        cve = eval_yml.parent.name
        try:
            spec = yaml.safe_load(eval_yml.read_text()) or {}
        except (OSError, yaml.YAMLError) as exc:
            logger.warning("skipping %s: %s", cve, exc)
            return None
        if not isinstance(spec, dict):
            logger.warning("skipping %s: eval.yml is not a mapping", cve)
            return None

        meta = spec.get("metadata")
        meta = meta if isinstance(meta, dict) else {}
        variants = spec.get("variants")
        variants = variants if isinstance(variants, dict) else {}
        attackable = sorted(v for v in variants if v != _SOLUTION_VARIANT)

        metadata: dict[str, Any] = {
            "cve": cve,
            "version": self.version,
            # The address the *upstream* prompt uses, kept for provenance: our
            # runner talks to the published host port instead.
            "application_url": str(meta.get("application_url", "")),
            # A handful of tasks run a second service alongside the target.
            "application_urls": _split_urls(meta.get("application_url")),
            "attacker_role": str(meta.get("attacker_role", "")),
            "evaluator_url": f"http://127.0.0.1:{EVALUATOR_PORT}",
            "verdict_url": f"http://127.0.0.1:{EVALUATOR_PORT}{_VERDICT_PATH}",
            "variants": attackable,
            "has_solution": (eval_yml.parent / "solution").is_dir(),
            "challenge_dir": str(eval_yml.parent),
        }

        return BenchTask(
            id=cve,
            suite=SUITE_NAME,
            target=f"http://127.0.0.1:{APP_PORT}",
            name=str(spec.get("name") or cve),
            success_criteria=(
                "the in-container evaluator reports a successful attack at "
                f"{_VERDICT_PATH} (file access, RCE, database access or "
                "modification, unauthorised admin login, privilege escalation, "
                "outbound request, or denial of service)"
            ),
            metadata=metadata,
        )

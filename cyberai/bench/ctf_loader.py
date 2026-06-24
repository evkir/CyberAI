"""
CTFAdapter — loads CyberAI's own CTF-style challenges from a directory of
manifests into the BenchTask contract.

Manifest schema (our own JSON, one `manifest.json` per challenge dir):
    id, name, category, difficulty, flag, description?, files?

The format is intentionally CyBench-compatible in spirit (flag-submission,
category/difficulty metadata) so external CTF suites can be projected onto the
same contract by a future optional adapter — but we ship and parse only our own
challenges here; no third-party benchmark code is bundled.

Degrades gracefully: a missing challenge root yields an empty suite rather than
raising, so CI and packaging never break.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from cyberai.bench.ctf import CTFTask
from cyberai.bench.runner import BenchAdapter, BenchTask

logger = logging.getLogger("cyberai.bench.ctf_loader")

# Default: the challenges shipped inside the package.
_DEFAULT_ROOT = Path(__file__).parent / "ctf_challenges"

_REQUIRED = ("id", "name", "category", "difficulty", "flag")


def _load_manifest(manifest_path: Path) -> CTFTask | None:
    """Parse one manifest.json into a CTFTask. Returns None (and logs) on any
    malformed/incomplete manifest — one bad challenge never breaks the suite."""
    try:
        data = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("bad CTF manifest %s: %s", manifest_path, exc)
        return None
    missing = [k for k in _REQUIRED if not data.get(k)]
    if missing:
        logger.warning("CTF manifest %s missing fields: %s", manifest_path, missing)
        return None
    return CTFTask(
        id=str(data["id"]),
        name=str(data["name"]),
        category=str(data["category"]),
        difficulty=str(data["difficulty"]),
        flag=str(data["flag"]),
        description=str(data.get("description", "")),
        challenge_dir=str(manifest_path.parent),
        metadata={"files": data.get("files", [])},
    )


class CTFAdapter(BenchAdapter):
    """Loads CTF-style flag challenges from a challenge root directory."""

    name = "ctf"

    def __init__(self, root: Path | str = _DEFAULT_ROOT) -> None:
        self.root = Path(root)

    def load_ctf_tasks(self) -> list[CTFTask]:
        """Return the parsed CTFTask objects (with flags) for grading."""
        if not self.root.is_dir():
            logger.info("CTF root %s absent; empty suite", self.root)
            return []
        tasks: list[CTFTask] = []
        for manifest in sorted(self.root.glob("*/manifest.json")):
            task = _load_manifest(manifest)
            if task is not None:
                tasks.append(task)
        return tasks

    def load_tasks(self) -> list[BenchTask]:
        """BenchAdapter contract: flag-free BenchTasks for the runner."""
        return [t.to_bench_task() for t in self.load_ctf_tasks()]

    def get_ctf_task(self, task_id: str) -> CTFTask | None:
        """Resolve the original CTFTask (with flag) for grading a result."""
        return next((t for t in self.load_ctf_tasks() if t.id == task_id), None)

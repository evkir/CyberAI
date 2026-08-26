"""
Run manifest — provenance + determinism lock for a benchmark run.

A scorecard says *what score* we got; the manifest says *exactly what produced
it* so the number is reproducible and tamper-evident:

  - a content hash over the suite's tasks (id/name/criteria) — proves the suite
    wasn't quietly swapped to an easier one between runs,
  - the run config (model, provider, temperature, seed) — the knobs that affect
    outcome. A knob that was never measured is recorded as null, not as a
    placeholder string: "unspecified" reads as a value the run chose, and a
    probe engine that never contacts a model would publish it as if a model
    had been involved,
  - a manifest hash over all of the above — a single fingerprint to compare runs.

`set_global_seed` pins Python's `random` (and PYTHONHASHSEED for child procs) so
any stochastic step in a run is repeatable. LLM sampling is only deterministic
at temperature 0; the manifest records temperature so non-determinism is at
least visible.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from cyberai.bench.runner import BenchTask, SuiteReport
from cyberai.version import __version__

DEFAULT_SEED = 1337


def set_global_seed(seed: int = DEFAULT_SEED) -> int:
    """Pin process-wide randomness. Returns the seed used (for the manifest).
    PYTHONHASHSEED only affects child processes spawned after this call."""
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    return seed


def hash_tasks(tasks: list[BenchTask]) -> str:
    """Stable SHA-256 over the identifying fields of a suite's tasks. Order is
    normalized by task id so re-ordering does not change the hash."""
    payload = sorted(
        ({"id": t.id, "name": t.name, "criteria": t.success_criteria} for t in tasks),
        key=lambda d: d["id"],
    )
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass(frozen=True)
class RunConfig:
    """The knobs that affect a run's outcome.

    Everything a caller may leave unmeasured defaults to None, so the manifest
    distinguishes "this run did not involve a model" from "this run used a
    model named unspecified". temperature is not exempt: 0.0 is a real setting
    a caller can choose, and a default of 0.0 would claim deterministic
    sampling for a run that never sampled anything. seed keeps a concrete
    default because set_global_seed always pins one.
    """

    model: str | None = None
    provider: str | None = None
    temperature: float | None = None
    seed: int = DEFAULT_SEED
    max_iterations: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RunManifest:
    """Full, hashable provenance for one suite run."""

    suite: str
    engine_version: str
    config: RunConfig
    suite_hash: str
    solved: int
    total: int
    timestamp: str
    manifest_hash: str = ""

    @property
    def pass_at_1(self) -> float:
        return self.solved / self.total if self.total else 0.0

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=2)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_manifest(
    suite: str,
    tasks: list[BenchTask],
    report: SuiteReport,
    config: RunConfig | None = None,
    timestamp: str | None = None,
) -> RunManifest:
    """Assemble a RunManifest and stamp it with a deterministic manifest hash.

    The manifest hash deliberately excludes the timestamp so two identical runs
    at different times produce the same fingerprint (timestamp is recorded but
    not part of the identity)."""
    config = config or RunConfig()
    suite_hash = hash_tasks(tasks)
    identity = {
        "suite": suite,
        "engine_version": __version__,
        "config": asdict(config),
        "suite_hash": suite_hash,
        "solved": report.solved,
        "total": report.total,
    }
    blob = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    manifest_hash = hashlib.sha256(blob.encode()).hexdigest()
    return RunManifest(
        suite=suite,
        engine_version=__version__,
        config=config,
        suite_hash=suite_hash,
        solved=report.solved,
        total=report.total,
        timestamp=timestamp or _utc_now_iso(),
        manifest_hash=manifest_hash,
    )

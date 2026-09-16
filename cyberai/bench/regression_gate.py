"""
Regression gate — guards a suite's solve-rate against silent regressions.

Compares a fresh RunManifest against a stored baseline manifest and decides
whether the run is acceptable. Two independent checks:

  - solve-rate must not drop below baseline (minus an allowed tolerance),
  - the suite-hash must match, OR the change must be explicitly acknowledged —
    a changed suite invalidates the comparison (you might have swapped in easier
    tasks), so we flag it rather than silently passing.

Used both in CI (block a PR that lowers the score) and at release time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from cyberai.bench.run_manifest import RunManifest, ToolVersion

DEFAULT_TOLERANCE = 0.0  # by default, no drop allowed at all


@dataclass(frozen=True)
class GateResult:
    """Outcome of a regression check."""

    passed: bool
    reason: str
    baseline_rate: float
    current_rate: float
    suite_changed: bool


def _read_toolchain(data: dict[str, Any]) -> tuple[ToolVersion, ...]:
    """Rebuild the recorded toolchain from a manifest document.

    An absent key is an empty tuple, and that is the same value a run that
    never probed produces: absent means unmeasured, not "no tools". The gate
    reads it that way, so the two cases must not be told apart here.

    A key this release does not know is ignored rather than refused, because
    the four fields are read by name: a baseline written by a newer CyberAI
    still answers the questions this release asks, and refusing it would
    return None, which the gate reads as "no baseline" -- an upgrade would
    switch the gate off. An element missing a name is skipped entirely: a
    version belongs to a tool, and a nameless one compares against nothing.
    The remaining three fields default, because load_baseline promises None
    on a document it cannot read, and a KeyError here would leave that
    promise through the caller instead.

    A tuple, not a list: it lands on a frozen RunManifest.
    """
    raw = data.get("environment", ())
    if not isinstance(raw, list):
        return ()
    tools = []
    for item in raw:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        tools.append(
            ToolVersion(
                name=item["name"],
                path=item.get("path"),
                version=item.get("version"),
                detail=item.get("detail", ""),
            )
        )
    return tuple(tools)


def load_baseline(path: str | Path) -> RunManifest | None:
    """Load a baseline manifest from JSON. None if absent/malformed (first run
    has no baseline — caller treats None as 'nothing to regress against')."""
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    from cyberai.bench.run_manifest import RunConfig

    # A knob this release does not know is dropped rather than refused. The
    # gate reads suite_hash and the two rates, none of which live in config,
    # so a baseline written by a newer CyberAI still answers the only
    # questions asked of it -- while RunConfig(**cfg) on an unknown keyword
    # would raise TypeError, and returning None for it would report "no
    # baseline", which passes. An upgrade would silently switch the gate off.
    known = {f.name for f in fields(RunConfig)}
    cfg = {k: v for k, v in data.get("config", {}).items() if k in known}

    return RunManifest(
        environment=_read_toolchain(data),
        suite=data["suite"],
        engine_version=data["engine_version"],
        config=RunConfig(**cfg) if cfg else RunConfig(),
        suite_hash=data["suite_hash"],
        solved=data["solved"],
        total=data["total"],
        timestamp=data.get("timestamp", ""),
        manifest_hash=data.get("manifest_hash", ""),
    )


def check_regression(
    current: RunManifest,
    baseline: RunManifest | None,
    tolerance: float = DEFAULT_TOLERANCE,
    allow_suite_change: bool = False,
) -> GateResult:
    """Pass/fail the current run against a baseline.

    No baseline -> pass (nothing to compare; this run becomes the baseline).
    """
    if baseline is None:
        return GateResult(
            passed=True,
            reason="no baseline; current run establishes one",
            baseline_rate=0.0,
            current_rate=current.pass_at_1,
            suite_changed=False,
        )

    suite_changed = current.suite_hash != baseline.suite_hash
    if suite_changed and not allow_suite_change:
        return GateResult(
            passed=False,
            reason="suite content changed; comparison invalid (pass allow_suite_change to override)",
            baseline_rate=baseline.pass_at_1,
            current_rate=current.pass_at_1,
            suite_changed=True,
        )

    if current.pass_at_1 + tolerance < baseline.pass_at_1:
        return GateResult(
            passed=False,
            reason=(
                f"solve-rate regressed: {current.pass_at_1:.1%} < "
                f"baseline {baseline.pass_at_1:.1%} (tolerance {tolerance:.1%})"
            ),
            baseline_rate=baseline.pass_at_1,
            current_rate=current.pass_at_1,
            suite_changed=suite_changed,
        )

    return GateResult(
        passed=True,
        reason="solve-rate held or improved",
        baseline_rate=baseline.pass_at_1,
        current_rate=current.pass_at_1,
        suite_changed=suite_changed,
    )

"""
Scorecard generator — turns a SuiteReport into reproducible Markdown.

The scorecard is CyberAI's public honesty artifact: a deterministic, diffable
record of how the engine performed on a suite. It records the headline pass@1,
a per-task table, and a per-vulnerability-class breakdown, plus a run-metadata
block (engine version, model, timestamp) so any number we publish can be traced
to the exact run that produced it.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cyberai.bench.runner import SuiteReport
from cyberai.version import __version__


@dataclass(frozen=True)
class RunMeta:
    """Provenance for a scorecard run. All fields optional/defaulted so a
    scorecard can be produced even in minimal/CI contexts."""

    engine_version: str = __version__
    model: str = "unspecified"
    provider: str = "unspecified"
    note: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _per_class(report: SuiteReport) -> dict[str, tuple[int, int]]:
    """class -> (solved, total) from per-result details."""
    agg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in report.results:
        vc = str(r.details.get("vuln_class", "unknown"))
        agg[vc][1] += 1
        if r.solved:
            agg[vc][0] += 1
    return {k: (v[0], v[1]) for k, v in sorted(agg.items())}


def generate_scorecard(report: SuiteReport, meta: RunMeta | None = None) -> str:
    """Render a Markdown scorecard for one suite run."""
    meta = meta or RunMeta()
    lines: list[str] = []
    lines.append(f"# Benchmark Scorecard — `{report.suite}`")
    lines.append("")
    lines.append(f"**pass@1: {report.solved}/{report.total} = {report.pass_at_1:.1%}**")
    lines.append("")
    lines.append("## Run metadata")
    lines.append("")
    lines.append("| field | value |")
    lines.append("| --- | --- |")
    lines.append(f"| timestamp | {_utc_now_iso()} |")
    lines.append(f"| engine | CyberAI {meta.engine_version} |")
    lines.append(f"| provider | {meta.provider} |")
    lines.append(f"| model | {meta.model} |")
    if meta.note:
        lines.append(f"| note | {meta.note} |")
    for k, v in meta.extra.items():
        lines.append(f"| {k} | {v} |")
    lines.append("")
    lines.append("## Per-class breakdown")
    lines.append("")
    lines.append("| vuln class | solved | total | rate |")
    lines.append("| --- | --- | --- | --- |")
    for vc, (solved, total) in _per_class(report).items():
        rate = solved / total if total else 0.0
        lines.append(f"| {vc} | {solved} | {total} | {rate:.0%} |")
    lines.append("")
    lines.append("## Per-task results")
    lines.append("")
    lines.append("| task id | solved | time (s) | error |")
    lines.append("| --- | --- | --- | --- |")
    for r in report.results:
        mark = "✓" if r.solved else "✗"
        err = (r.error or "").replace("|", "\\|")
        lines.append(f"| {r.task_id} | {mark} | {r.duration_s:.2f} | {err} |")
    lines.append("")
    return "\n".join(lines)

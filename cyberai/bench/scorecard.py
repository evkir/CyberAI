"""
Scorecard generator — turns a SuiteReport into reproducible Markdown.

The scorecard is CyberAI's public honesty artifact: a deterministic, diffable
record of how the engine performed on a suite. It records the headline pass@1,
a per-task table, and a per-vulnerability-class breakdown, plus a run-metadata
block (engine version, model, timestamp) so any number we publish can be traced
to the exact run that produced it.

When the engine measured a surface, those numbers travel with the score:
endpoints reached, requests spent, proofs in band and out of it, and
whether the target was up at all. A zero against an unreachable target
and a zero against a surface holding nothing are different facts, and
pass@1 alone cannot tell a reader which one it is looking at.
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
    scorecard can be produced even in minimal/CI contexts.

    A knob that was never measured is None and its row is left out, rather
    than published as "unspecified": a placeholder in a machine-readable
    table reads as a value the run chose, and an engine that never contacts
    a model would name one as if it had. llm_calls is the same distinction
    on the other side -- zero says a model was proven not to have been
    reached, absent says nothing counted it.
    """

    engine_version: str = __version__
    model: str | None = None
    provider: str | None = None
    llm_calls: int | None = None
    llm_zero_reason: str | None = None
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


_METRIC_COLUMNS = (
    ("agent_confirmed", "in-band"),
    ("oob_confirmed", "out of band"),
    ("endpoints_tested", "endpoints"),
    ("requests_sent", "requests"),
)


def _has_run_metrics(report: SuiteReport) -> bool:
    """True when at least one task reported the surface it reached.

    Engines that never measure one -- the `real` probe engine, EVMBench's
    static detection -- do not write these keys, and the section is omitted
    rather than rendered as a wall of dashes.

    A target recorded as unavailable brings the section back on its own. It
    has no surface to report, so keying the section on the metrics alone
    dropped the availability column exactly where it answered the reader's
    question: a task refused before it started rendered as plain unsolved,
    which reads like an agent that searched and found nothing. Availability
    that is merely absent, or true without metrics beside it, is not enough:
    the probe engine records the target as up and measures nothing, and that
    is the wall of dashes this section exists to avoid.
    """
    return any(
        "endpoints_tested" in r.details or r.details.get("available") is False
        for r in report.results
    )


def _availability_mark(details: dict[str, Any]) -> str:
    """Availability as recorded: unknown is its own answer, not a False."""
    value = details.get("available")
    if value is None:
        return "?"
    return "\u2713" if value else "\u2717"


def _run_metric_lines(report: SuiteReport) -> list[str]:
    """Per-task surface metrics plus a totals row."""
    lines = ["## Run metrics", ""]
    lines.append(
        "What the engine reached and spent. A target that never came up scores "
        "zero for a reason the score cannot show, so availability travels with "
        "the numbers. In-band and out-of-band proofs are counted apart: a blind "
        "vector proves itself on a callback and leaves the response unchanged."
    )
    lines.append("")
    lines.append(
        "| task id | available | " + " | ".join(label for _, label in _METRIC_COLUMNS) + " |"
    )
    lines.append("| --- | --- | " + " | ".join("---" for _ in _METRIC_COLUMNS) + " |")
    totals: dict[str, int] = dict.fromkeys((key for key, _ in _METRIC_COLUMNS), 0)
    up = 0
    for r in report.results:
        cells = []
        for key, _ in _METRIC_COLUMNS:
            value = r.details.get(key)
            if isinstance(value, int):
                totals[key] += value
                cells.append(str(value))
            else:
                cells.append("\u2014")
        if r.details.get("available") is True:
            up += 1
        mark = _availability_mark(r.details)
        lines.append(f"| {r.task_id} | {mark} | " + " | ".join(cells) + " |")
    total_cells = " | ".join(str(totals[key]) for key, _ in _METRIC_COLUMNS)
    lines.append(f"| **total** | {up}/{len(report.results)} | {total_cells} |")
    lines.append("")
    return lines


def generate_scorecard(report: SuiteReport, meta: RunMeta | None = None) -> str:
    """Render a Markdown scorecard for one suite run.

    The version row is keyed `engine version`. It used to be `engine`, which
    the CLI also writes to name the engine that ran, so one published card
    carried two rows under one key: `CyberAI 1.5.0` and `agent`.
    """
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
    lines.append(f"| engine version | CyberAI {meta.engine_version} |")
    rows: list[tuple[str, str]] = []
    if meta.provider:
        rows.append(("provider", meta.provider))
    if meta.model:
        rows.append(("model", meta.model))
    if meta.llm_calls is not None:
        rows.append(("llm calls", str(meta.llm_calls)))
    if meta.llm_zero_reason:
        rows.append(("llm zero reason", meta.llm_zero_reason))
    if meta.note:
        rows.append(("note", meta.note))
    rows += [(str(k), str(v)) for k, v in meta.extra.items()]
    written = {"timestamp", "engine version"}
    for key, value in rows:
        if key in written:
            raise ValueError(
                f"duplicate scorecard metadata key: {key!r}. The table is read "
                "by machines, so one key carrying two meanings is a defect, not "
                "a formatting choice."
            )
        written.add(key)
        lines.append(f"| {key} | {value} |")
    lines.append("")
    lines.append("## Per-class breakdown")
    lines.append("")
    lines.append("| vuln class | solved | total | rate |")
    lines.append("| --- | --- | --- | --- |")
    for vc, (solved, total) in _per_class(report).items():
        rate = solved / total if total else 0.0
        lines.append(f"| {vc} | {solved} | {total} | {rate:.0%} |")
    lines.append("")
    if _has_run_metrics(report):
        lines += _run_metric_lines(report)
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

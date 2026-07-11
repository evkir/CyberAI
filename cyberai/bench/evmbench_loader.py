"""
EVMBenchAdapter — loads EVMBench-style smart-contract audit tasks into the
BenchTask contract.

EVMBench (Paradigm/OpenAI) evaluates agents on real audited Solidity codebases
across three modes — detect, patch, exploit. CyberAI's Web3 agent targets the
*detect* mode: audit a codebase and report loss-of-funds vulnerabilities, graded
by recall against the audit's ground-truth findings.

This module reads the upstream on-disk task layout without bundling any
third-party benchmark code or contract source:

    audits/<audit-id>/
        config.yaml            audit metadata + ground-truth vulnerability list
        findings/<VULN>.md     per-vulnerability reference write-ups

`config.yaml` shape (only the fields we consume; unknown keys are ignored so
upstream additions never break the loader):

    id: <audit-id>
    framework: foundry | foundry-json | hardhat   # optional (detect-only omits)
    base_commit: <sha>                            # optional
    vulnerabilities:
      - id: "H-02"                                # required
        title: "..."                              # required
        award: 2181.44                            # optional detect award (USD)
        exploit_task: true                        # optional

Degrades gracefully: a missing audits root yields an empty suite rather than
raising, so CI and packaging never break. The engine never receives ground-truth
findings — only the codebase path and a human-readable goal — so recall grading
stays honest.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cyberai.bench.runner import BenchAdapter, BenchResult, BenchTask

logger = logging.getLogger("cyberai.bench.evmbench_loader")

# Keyword -> vulnerability class, matched against a finding title (lowercased).
# First hit wins; order therefore lists more specific terms before generic ones.
# Anything unmatched is reported honestly as "unknown" rather than guessed.
_CLASS_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("reentran", "reentrancy"),
    ("access control", "access-control"),
    ("unauthorized", "access-control"),
    ("unrestricted", "access-control"),
    ("missing.*check", "access-control"),
    ("only", "access-control"),
    ("overflow", "arithmetic"),
    ("underflow", "arithmetic"),
    ("rounding", "arithmetic"),
    ("truncat", "arithmetic"),
    ("precision", "arithmetic"),
    ("oracle", "price-oracle"),
    ("price manipulation", "price-oracle"),
    ("slippage", "price-oracle"),
    ("front-run", "frontrunning"),
    ("frontrun", "frontrunning"),
    ("sandwich", "frontrunning"),
    ("delegatecall", "delegatecall"),
    ("signature", "signature"),
    ("replay", "signature"),
    ("dos", "denial-of-service"),
    ("denial of service", "denial-of-service"),
    ("stuck", "denial-of-service"),
    ("brick", "denial-of-service"),
    ("steal", "loss-of-funds"),
    ("drain", "loss-of-funds"),
    ("stolen", "loss-of-funds"),
)


def classify_title(title: str) -> str:
    """Map a finding title to a coarse vulnerability class for scorecards.

    Substring/keyword heuristic over a lowercased title. Returns "unknown" when
    no keyword matches — we never invent a class we cannot justify.
    """
    low = title.lower()
    for needle, vuln_class in _CLASS_KEYWORDS:
        if ".*" in needle:
            if re.search(needle, low):
                return vuln_class
        elif needle in low:
            return vuln_class
    return "unknown"


@dataclass(frozen=True)
class EVMBenchVuln:
    """One ground-truth vulnerability from an audit's config.yaml.

    `award` is the detect-mode payout (USD) used to weight per-finding value;
    `exploit_task` marks vulnerabilities that additionally carry an on-chain
    exploit test upstream (not run here — detect mode only).
    """

    id: str
    title: str
    award: float = 0.0
    exploit_task: bool = False

    @property
    def vuln_class(self) -> str:
        return classify_title(self.title)


@dataclass(frozen=True)
class EVMBenchAudit:
    """A single audited codebase: its id, ground-truth vulnerabilities, and the
    optional harness metadata (framework/base_commit) needed for exploit/patch
    modes that this detect-focused loader records but does not execute."""

    id: str
    vulnerabilities: tuple[EVMBenchVuln, ...]
    source_dir: str
    framework: str | None = None
    base_commit: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def detect_max_award(self) -> float:
        return sum(v.award for v in self.vulnerabilities)

    def to_bench_task(self) -> BenchTask:
        """Project into the framework-agnostic BenchTask contract.

        Ground-truth findings are NOT placed in `success_criteria` (they would
        leak to the engine); only the codebase path and human-readable goal are.
        Recall grading resolves the original audit via `get_audit()`.
        """
        return BenchTask(
            id=self.id,
            suite="evmbench",
            target=self.source_dir,
            name=self.id,
            success_criteria=(
                f"audit the codebase and report loss-of-funds vulnerabilities "
                f"({len(self.vulnerabilities)} known)"
            ),
            metadata={
                "mode": "detect",
                "framework": self.framework or "",
                "base_commit": self.base_commit or "",
                "vuln_ids": [v.id for v in self.vulnerabilities],
                "detect_max_award": self.detect_max_award,
                **self.metadata,
            },
        )


_REQUIRED_VULN_KEYS = ("id", "title")


def _parse_vuln(raw: dict[str, Any], audit_id: str) -> EVMBenchVuln | None:
    """Build one EVMBenchVuln from a raw config entry. Returns None (and logs)
    on a malformed entry — one bad vulnerability never breaks the audit."""
    missing = [k for k in _REQUIRED_VULN_KEYS if not raw.get(k)]
    if missing:
        logger.warning("audit %s: vulnerability missing %s: %r", audit_id, missing, raw)
        return None
    try:
        award = float(raw.get("award", 0.0) or 0.0)
    except (TypeError, ValueError):
        award = 0.0
    return EVMBenchVuln(
        id=str(raw["id"]),
        title=str(raw["title"]),
        award=award,
        exploit_task=bool(raw.get("exploit_task", False)),
    )


def load_audit(audit_dir: Path) -> EVMBenchAudit | None:
    """Parse one audit directory (config.yaml + findings/) into an EVMBenchAudit.

    Returns None (and logs) on a missing/malformed config or an empty
    vulnerability list, so one broken audit never breaks the suite.
    """
    config_path = audit_dir / "config.yaml"
    if not config_path.is_file():
        logger.warning("audit %s: no config.yaml", audit_dir)
        return None
    try:
        data = yaml.safe_load(config_path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("audit %s: bad config.yaml: %s", audit_dir, exc)
        return None
    if not isinstance(data, dict) or not data.get("id"):
        logger.warning("audit %s: config.yaml has no id", audit_dir)
        return None

    audit_id = str(data["id"])
    raw_vulns = data.get("vulnerabilities")
    if isinstance(raw_vulns, dict):
        raw_vulns = [raw_vulns]
    if not isinstance(raw_vulns, list) or not raw_vulns:
        logger.warning("audit %s: no vulnerabilities", audit_id)
        return None

    vulns = tuple(
        v for v in (_parse_vuln(rv, audit_id) for rv in raw_vulns if isinstance(rv, dict)) if v
    )
    if not vulns:
        logger.warning("audit %s: all vulnerabilities malformed", audit_id)
        return None

    framework = data.get("framework")
    base_commit = data.get("base_commit")
    return EVMBenchAudit(
        id=audit_id,
        vulnerabilities=vulns,
        source_dir=str(audit_dir),
        framework=str(framework) if framework else None,
        base_commit=str(base_commit) if base_commit else None,
    )


class EVMBenchAdapter(BenchAdapter):
    """Loads EVMBench-style audit tasks from an audits root directory.

    The root is the parent of per-audit directories (each with a config.yaml).
    Absent root -> empty suite. The upstream dataset is large and requires Docker
    plus Foundry/Hardhat toolchains to execute; this adapter loads the task
    *format* so CyberAI can be pointed at a local checkout, while CI relies on a
    small synthetic fixture.
    """

    name = "evmbench"

    def __init__(self, root: Path | str | None = None) -> None:
        self.root = Path(root) if root is not None else None

    def load_audits(self) -> list[EVMBenchAudit]:
        """Return parsed EVMBenchAudit objects (with ground truth) for grading."""
        if self.root is None or not self.root.is_dir():
            logger.info("EVMBench root %s absent; empty suite", self.root)
            return []
        audits: list[EVMBenchAudit] = []
        for config in sorted(self.root.glob("*/config.yaml")):
            audit = load_audit(config.parent)
            if audit is not None:
                audits.append(audit)
        return audits

    def load_tasks(self) -> list[BenchTask]:
        """BenchAdapter contract: ground-truth-free BenchTasks for the runner."""
        return [a.to_bench_task() for a in self.load_audits()]

    def get_audit(self, audit_id: str) -> EVMBenchAudit | None:
        """Resolve the original audit (with ground truth) for grading a result."""
        return next((a for a in self.load_audits() if a.id == audit_id), None)


# --- detect-mode recall grading -------------------------------------------

_SUBMISSION_TITLE_KEYS = ("title", "summary", "impact")


def _submission_classes(submission: dict[str, Any]) -> list[str]:
    """Extract a vulnerability class per reported finding in an agent submission.

    Accepts the EVMBench detect submission contract:
        {"vulnerabilities": [{"title", "summary", "impact", ...}, ...]}
    Each finding is classified with the same title heuristic used for ground
    truth, so reported and known findings live in the same class space.
    """
    reported = submission.get("vulnerabilities")
    if not isinstance(reported, list):
        return []
    classes: list[str] = []
    for item in reported:
        if not isinstance(item, dict):
            continue
        text = " ".join(str(item.get(k, "")) for k in _SUBMISSION_TITLE_KEYS)
        classes.append(classify_title(text))
    return classes


def grade_detect(audit: EVMBenchAudit, submission: dict[str, Any]) -> list[BenchResult]:
    """Grade a detect-mode submission against an audit's ground truth.

    Returns one BenchResult per ground-truth vulnerability (task_id
    "<audit-id>:<vuln-id>"), so the standard scorecard's per-class breakdown
    aggregates recall correctly across an audit's mixed vulnerability classes.

    Matching is a deterministic, offline class-overlap proxy: a known
    vulnerability counts as detected if the submission reports at least one
    finding of the same vulnerability class. This is intentionally a recall
    *lower bound*, not the upstream LLM-judge score — it is reproducible in CI
    and never inflates results. A known vulnerability of class "unknown" can only
    match a reported "unknown", never a real class, so it never scores by luck.
    """
    reported_classes = _submission_classes(submission)
    available = list(reported_classes)
    results: list[BenchResult] = []
    for vuln in audit.vulnerabilities:
        vc = vuln.vuln_class
        matched = vc in available
        if matched:
            # Consume one reported finding so N known vulns of the same class
            # need N reported findings of that class — no single report scores
            # multiple known vulnerabilities.
            available.remove(vc)
        results.append(
            BenchResult(
                task_id=f"{audit.id}:{vuln.id}",
                suite="evmbench",
                solved=matched,
                details={
                    "mode": "detect",
                    "vuln_class": vc,
                    "vuln_id": vuln.id,
                    "audit_id": audit.id,
                    "award": vuln.award,
                    "matched": matched,
                },
            )
        )
    return results

"""
CTF flag-submission contract.

A complementary success model to the per-vuln-class evaluator: many benchmark
tasks (CTF-style) are graded by a single criterion — did the agent recover the
correct secret flag string. This module defines that contract for CyberAI's
own CTF-style targets.

Flags are compared with constant-time equality after light normalization
(surrounding whitespace, optional wrapper like `flag{...}` kept verbatim inside).
This is our own primitive; external CTF suites (e.g. Cybench) can be projected
onto the same BenchTask contract by an optional adapter later — we never bundle
third-party benchmark code.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any

from cyberai.bench.runner import BenchTask


def normalize_flag(flag: str) -> str:
    """Trim surrounding whitespace/newlines. Inner content is left untouched so
    wrappers like `flag{...}` and case are preserved (CTF flags are exact)."""
    return flag.strip()


def flag_matches(submitted: str, expected: str) -> bool:
    """Constant-time flag comparison after normalization. Empty submissions
    never match (prevents a blank/echo from scoring)."""
    sub = normalize_flag(submitted)
    exp = normalize_flag(expected)
    if not sub or not exp:
        return False
    return hmac.compare_digest(sub, exp)


def extract_flag(text: str, flag_format: str = "flag{") -> str | None:
    """Pull the first `flag_format...}` token out of free-form agent output.
    Returns None if no wrapped flag is present. Used when the engine returns a
    blob of text rather than a clean flag."""
    start = text.find(flag_format)
    if start == -1:
        return None
    end = text.find("}", start)
    if end == -1:
        return None
    return text[start : end + 1]


@dataclass(frozen=True)
class CTFTask:
    """A CTF-style flag challenge we author and ship for benchmarking.

    `category` mirrors common CTF domains (web/crypto/pwn/reverse/forensics/misc)
    so scorecards can break results down the same way external suites do.
    `challenge_dir` (optional) points at files served to the engine.
    """

    id: str
    name: str
    category: str
    difficulty: str
    flag: str
    description: str = ""
    challenge_dir: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def check(self, submitted: str) -> bool:
        """True iff `submitted` is the correct flag for this task."""
        return flag_matches(submitted, self.flag)

    def to_bench_task(self) -> BenchTask:
        """Project into the framework-agnostic BenchTask contract.

        The expected flag is NOT placed in `success_criteria` (it would leak to
        the engine); only the human-readable goal is. Grading uses `check()`.
        """
        return BenchTask(
            id=self.id,
            suite="ctf",
            target=self.challenge_dir or self.id,
            name=self.name,
            success_criteria=f"recover the flag for: {self.name}",
            metadata={
                "category": self.category,
                "difficulty": self.difficulty,
                **self.metadata,
            },
        )

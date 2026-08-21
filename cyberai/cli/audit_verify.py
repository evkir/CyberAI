"""Verify the HMAC signatures on an audit trail.

Answers one question: has this JSONL file changed since the run wrote it.
A file whose every line verifies is evidence the trail was not edited by
anyone lacking the signing key. A file with unsigned lines proves nothing —
it was written by a build that did not sign, so the absence is reported
separately from a mismatch.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from cyberai.core.session_signing import SIGNATURE_FIELD, SessionSigner


@dataclass
class TrailReport:
    """Per-line outcome of verifying one audit file."""

    verified: int = 0
    tampered: List[int] = field(default_factory=list)
    unsigned: List[int] = field(default_factory=list)
    unreadable: List[int] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        """True only when every line carried a signature and it matched."""
        return not (self.tampered or self.unsigned or self.unreadable)

    def summary(self) -> str:
        return (
            f"{self.verified} verified, {len(self.tampered)} tampered, "
            f"{len(self.unsigned)} unsigned, {len(self.unreadable)} unreadable"
        )


def verify_trail(path: str, signer: SessionSigner = None) -> TrailReport:
    """Verify every line of a JSONL audit trail, reporting 1-based line numbers."""
    signer = signer or SessionSigner()
    report = TrailReport()
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            report.unreadable.append(n)
            continue
        if not isinstance(event, dict) or SIGNATURE_FIELD not in event:
            report.unsigned.append(n)
        elif signer.verify(event):
            report.verified += 1
        else:
            report.tampered.append(n)
    return report

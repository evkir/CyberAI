"""The test suite must not write into the operator's repository.

Both writers default to a *relative* path -- CyberAIConfig.output_dir is
Path("reports/") and AuditLogger takes output_dir="reports/" -- so they land
wherever the process happens to be running. Under pytest that was the repo
itself: a single run left ten session files and over a hundred audit logs in
reports/, and .gitignore covers the whole directory, so git status stayed
clean while ~38k files accumulated there unseen.

That directory is not scratch space. bench-scorecard and the STANDOFF-III CI
assertions read those session files, and a synthetic session parses exactly
like a real one -- reporting zero findings as a valid result.

Each test below asserts the write did not reach the repo *and* that it landed
somewhere: an assertion on absence alone would stay green if the writer broke
entirely and produced nothing at all.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from cyberai.cli.replay import save_session
from cyberai.core.config import CyberAIConfig
from cyberai.core.logger import AuditLogger
from cyberai.core.scan_session import ScanSession

_REPO = Path(__file__).resolve().parents[2]


def test_the_audit_logger_default_stays_out_of_the_repo():
    session_id = uuid.uuid4().hex[:12]
    AuditLogger(session_id=session_id)

    name = f"audit_{session_id}.jsonl"
    assert not (_REPO / "reports" / name).exists()
    assert (Path.cwd() / "reports" / name).exists()


def test_a_saved_session_stays_out_of_the_repo():
    session = ScanSession(target="isolation.test")
    written = save_session(session, CyberAIConfig().output_dir).resolve()

    assert _REPO not in written.parents
    assert written.exists()

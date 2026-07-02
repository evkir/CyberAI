from typing import Any, List, Dict, Optional
import logging
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console
from rich.logging import RichHandler

console = Console()


def get_logger(name: str, log_file: str = None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Rich console handler
    rich_handler = RichHandler(console=console, show_time=True, show_path=False, markup=True)
    rich_handler.setLevel(logging.INFO)
    logger.addHandler(rich_handler)

    # File handler (structured JSON)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)

    return logger


class JsonFormatter(logging.Formatter):
    """Every agent action logged as structured JSON for audit trail"""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "agent"):
            log_entry["agent"] = record.agent
        if hasattr(record, "data"):
            log_entry["data"] = record.data
        return json.dumps(log_entry)


class AuditLogger:
    """Wrapper for structured pentest audit logging.

    Always writes a JSONL trail. When `db_path` is given, every event is
    also appended to an append-only SQLite `audit_events` table, enabling
    queryable audit and session replay. db_path=None keeps the
    legacy JSONL-only behaviour (no regression).
    """

    def __init__(
        self,
        session_id: str,
        output_dir: str = "reports/",
        db_path: Optional[str] = None,
    ):
        log_path = f"{output_dir}/audit_{session_id}.jsonl"
        self.logger = get_logger(f"cyberai.audit.{session_id}", log_path)
        self.session_id = session_id
        self.db_path = db_path
        if db_path:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    action TEXT NOT NULL,
                    inputs_json TEXT,
                    outputs_json TEXT,
                    timestamp TEXT NOT NULL
                )
                """
            )

    def _db_append(
        self,
        agent: str,
        action: str,
        inputs: Any = None,
        outputs: Any = None,
    ) -> None:
        if not self.db_path:
            return
        inputs_json = json.dumps(inputs, default=str) if inputs is not None else None
        outputs_json = json.dumps(outputs, default=str) if outputs is not None else None
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO audit_events "
                "(session_id, agent, action, inputs_json, outputs_json, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    self.session_id,
                    agent,
                    action,
                    inputs_json,
                    outputs_json,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def read_events(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Read audit events (all, or for one session) ordered by id.

        Returns [] when no SQLite backend is configured.
        """
        if not self.db_path:
            return []
        sid = session_id or self.session_id
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE session_id = ? ORDER BY id",
                (sid,),
            ).fetchall()
        return [dict(r) for r in rows]

    def agent_action(self, agent: str, action: str, data: Any = None):
        extra = {"agent": agent, "data": data}
        self.logger.info(f"[{agent}] {action}", extra=extra)
        self._db_append(agent, action, inputs=data)

    def finding(self, agent: str, title: str, severity: str):
        self.logger.warning(f"[FINDING][{severity}] {title}", extra={"agent": agent})
        self._db_append(agent, "finding", outputs={"title": title, "severity": severity})

    def error(self, agent: str, msg: str):
        self.logger.error(f"[{agent}] {msg}", extra={"agent": agent})
        self._db_append(agent, "error", outputs={"message": msg})

from typing import Any
import logging
import json
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
    """Wrapper for structured pentest audit logging"""

    def __init__(self, session_id: str, output_dir: str = "reports/"):
        log_path = f"{output_dir}/audit_{session_id}.jsonl"
        self.logger = get_logger(f"cyberai.audit.{session_id}", log_path)
        self.session_id = session_id

    def agent_action(self, agent: str, action: str, data: Any = None):
        extra = {"agent": agent, "data": data}
        self.logger.info(f"[{agent}] {action}", extra=extra)

    def finding(self, agent: str, title: str, severity: str):
        self.logger.warning(f"[FINDING][{severity}] {title}", extra={"agent": agent})

    def error(self, agent: str, msg: str):
        self.logger.error(f"[{agent}] {msg}", extra={"agent": agent})

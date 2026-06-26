"""
KnowledgeBase — shared memory store for all agents in a session.

`agent` is optional (defaults to "unknown") so
agents can write quick entries without always naming themselves; the
mutable default `tags=[]` bug is fixed; datetime is timezone-aware.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class KBEntry:
    key: str
    value: Any
    agent: str = "unknown"
    timestamp: str = field(default_factory=_now)
    tags: List[str] = field(default_factory=list)


class KnowledgeBase:
    """
    Shared memory store for all agents in a session.
    Agents read/write through trust-validated keys.
    """

    def __init__(self) -> None:
        self._store: Dict[str, KBEntry] = {}
        self._history: List[KBEntry] = []

    def set(
        self,
        key: str,
        value: Any,
        agent: str = "unknown",
        tags: Optional[List[str]] = None,
    ) -> None:
        entry = KBEntry(key=key, value=value, agent=agent, tags=tags or [])
        self._store[key] = entry
        self._history.append(entry)

    def get(self, key: str, default: Any = None) -> Optional[Any]:
        entry = self._store.get(key)
        return entry.value if entry else default

    def get_by_tag(self, tag: str) -> Dict[str, Any]:
        return {k: v.value for k, v in self._store.items() if tag in v.tags}

    def keys(self) -> List[str]:
        return list(self._store.keys())

    def snapshot(self) -> Dict[str, Any]:
        return {k: v.value for k, v in self._store.items()}

    @classmethod
    def from_snapshot(cls, data: Dict[str, Any]) -> "KnowledgeBase":
        """Rebuild a KB from a snapshot() dict (agent/tags/ts not restored)."""
        kb = cls()
        for key, value in (data or {}).items():
            kb.set(key, value, agent="replay")
        return kb

    def history(self) -> List[Dict]:
        return [{"key": e.key, "agent": e.agent, "timestamp": e.timestamp} for e in self._history]

    # ── dict-like access ──────────────────────────────────────────────
    # Some agents treat the KB like a dict (kb["recon.nmap"]).

    def __contains__(self, key: str) -> bool:
        return key in self._store

    def __getitem__(self, key: str) -> Any:
        if key not in self._store:
            raise KeyError(key)
        return self._store[key].value

    def __setitem__(self, key: str, value: Any) -> None:
        self.set(key, value)

    def __len__(self) -> int:
        return len(self._store)

"""
phantom-grid client — OOB callback tracking (v2.0 API).
https://github.com/evkir/phantom-grid

Real phantom-grid v2.0 contract:
  POST   /api/tokens                      -> create a capture token
  GET    /api/tokens/<id>/interactions    -> interactions for a token
  GET    /api/poll?since=<ISO>            -> new interactions (all tokens)
  GET    /health                          -> health check
  HTTP capture endpoint: http://<host>:9090/c/<token>
  DNS  capture endpoint: <token>.<domain>

Default HTTP port is 9090 (v2.0), not 8080.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

DEFAULT_GRID_URL = "http://127.0.0.1:9090"


@dataclass
class OOBInteraction:
    """A single captured OOB callback.

    `timestamp` is kept as a string (ISO or epoch-as-str) to stay provider
    agnostic; `confirmed` mirrors the legacy poller's semantics.
    """

    interaction_id: str
    protocol: str  # dns | http | https
    source_ip: str
    timestamp: str
    payload: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return bool(self.source_ip)


class PhantomGridClient:
    """Client for the phantom-grid v2.0 OOB interaction server.

    Creates capture tokens, builds capture URLs, polls for callbacks.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 10,
    ):
        self.base_url = (base_url or os.getenv("PHANTOM_GRID_URL", DEFAULT_GRID_URL)).rstrip("/")
        self.api_key = api_key or os.getenv("PHANTOM_GRID_KEY", "")
        self.timeout = timeout
        self._available: Optional[bool] = None

    # ── health ────────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        if self._available is None:
            self._available = self._check_health()
        return self._available

    def _check_health(self) -> bool:
        try:
            with httpx.Client(timeout=3) as client:
                r = client.get(f"{self.base_url}/health")
                return r.status_code == 200
        except Exception:
            return False

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    # ── tokens ────────────────────────────────────────────────────────

    def new_interaction_id(self) -> str:
        """Generate a local fallback id (used when the server is unavailable).

        Prefer create_token() against a live server; this exists for offline
        payload generation and backward compatibility.
        """
        return str(uuid.uuid4()).replace("-", "")[:16]

    def create_token(self, label: str = "cyberai", notes: str = "") -> Optional[str]:
        """POST /api/tokens -> token id. None if the server is unavailable."""
        if not self.available:
            return None
        try:
            with httpx.Client(timeout=self.timeout) as client:
                r = client.post(
                    f"{self.base_url}/api/tokens",
                    json={"label": label, "notes": notes},
                    headers=self._headers(),
                )
                r.raise_for_status()
                body = r.json()
                # Server may return {"id": ...} or {"token": ...}
                return str(body.get("id") or body.get("token") or "") or None
        except Exception:
            return None

    def capture_url(self, token: str, scheme: str = "http") -> str:
        """Build the HTTP(S) capture URL for a token: <base>/c/<token>."""
        base = self.base_url
        if scheme == "https" and base.startswith("http://"):
            base = base.replace("http://", "https://")
        return f"{base}/c/{token}"

    # ── interactions ──────────────────────────────────────────────────

    def get_interactions(self, interaction_id: str) -> List[OOBInteraction]:
        """GET /api/tokens/<id>/interactions -> parsed interactions."""
        if not self.available:
            return []
        try:
            with httpx.Client(timeout=self.timeout) as client:
                r = client.get(
                    f"{self.base_url}/api/tokens/{interaction_id}/interactions",
                    headers=self._headers(),
                )
                r.raise_for_status()
                items = r.json()
                if not isinstance(items, list):
                    return []
                return [self._parse(i) for i in items]
        except Exception:
            return []

    def poll(self, since: Optional[str] = None) -> List[OOBInteraction]:
        """GET /api/poll?since=<ISO> -> new interactions across all tokens."""
        if not self.available:
            return []
        params = {"since": since} if since else {}
        try:
            with httpx.Client(timeout=self.timeout) as client:
                r = client.get(
                    f"{self.base_url}/api/poll",
                    params=params,
                    headers=self._headers(),
                )
                r.raise_for_status()
                items = r.json().get("interactions", [])
                return [self._parse(i) for i in items]
        except Exception:
            return []

    _DATA_FIELDS = (
        "id",
        "method",
        "path",
        "query",
        "headers",
        "content_type",
        "query_name",
        "query_type",
        "exfil_data",
        "raw_labels",
    )

    def _parse(self, raw: Dict) -> OOBInteraction:
        """Map a phantom-grid v2.0 interaction row onto OOBInteraction.

        Server field names differ from the dataclass: token_id/type/time/body.
        The row id is the interaction id, not the capture token; the token is
        what payloads embed, so it is what correlation matches on.
        """
        return OOBInteraction(
            interaction_id=str(raw.get("token_id", "")),
            protocol=str(raw.get("type", "unknown")).lower(),
            source_ip=raw.get("source_ip", ""),
            timestamp=str(raw.get("time") or datetime.now(timezone.utc).isoformat()),
            payload=raw.get("body") or "",
            data={k: raw[k] for k in self._DATA_FIELDS if raw.get(k) is not None},
        )

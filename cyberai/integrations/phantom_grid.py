"""
phantom-grid client — OOB callback tracking.
https://github.com/evkir/phantom-grid
"""
import httpx
import uuid
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os


@dataclass
class OOBInteraction:
    interaction_id: str
    protocol: str        # dns | http | https
    source_ip: str
    timestamp: str
    payload: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


class PhantomGridClient:
    """
    Client for phantom-grid OOB interaction server.
    Registers payloads, polls for callbacks.
    """

    def __init__(
        self,
        base_url: str = None,
        api_key: str = None,
        timeout: int = 10
    ):
        self.base_url = (
            base_url
            or os.getenv("PHANTOM_GRID_URL", "http://127.0.0.1:8080")
        ).rstrip("/")
        self.api_key = api_key or os.getenv("PHANTOM_GRID_KEY", "")
        self.timeout = timeout
        self._available: Optional[bool] = None

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

    def new_interaction_id(self) -> str:
        """Generate unique ID for tracking a specific payload."""
        return str(uuid.uuid4()).replace("-", "")[:16]

    def get_interactions(
        self,
        interaction_id: str
    ) -> List[OOBInteraction]:
        """
        Poll phantom-grid for callbacks matching interaction_id.
        Returns list of OOBInteraction objects.
        """
        if not self.available:
            return []
        try:
            with httpx.Client(timeout=self.timeout) as client:
                r = client.get(
                    f"{self.base_url}/api/interactions",
                    params={"id": interaction_id},
                    headers=self._headers()
                )
                r.raise_for_status()
                items = r.json().get("interactions", [])
                return [self._parse(i) for i in items]
        except Exception:
            return []

    def list_all(self) -> List[OOBInteraction]:
        """Fetch all recent interactions from phantom-grid."""
        if not self.available:
            return []
        try:
            with httpx.Client(timeout=self.timeout) as client:
                r = client.get(
                    f"{self.base_url}/api/interactions",
                    headers=self._headers()
                )
                r.raise_for_status()
                items = r.json().get("interactions", [])
                return [self._parse(i) for i in items]
        except Exception:
            return []

    def _parse(self, raw: Dict) -> OOBInteraction:
        return OOBInteraction(
            interaction_id=raw.get("id", ""),
            protocol=raw.get("protocol", "unknown"),
            source_ip=raw.get("source_ip", ""),
            timestamp=raw.get("timestamp",
                              datetime.now(timezone.utc).isoformat()),
            payload=raw.get("payload", ""),
            data=raw.get("data", {}),
        )

"""
phantom-grid result poller for ExploitAgent.
Polls OOB interaction callbacks after payload delivery.
"""

import time
import httpx
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("cyberai.integrations.phantom_grid_poller")


@dataclass
class OOBInteraction:
    interaction_id: str
    protocol: str  # "dns" | "http" | "https"
    source_ip: str
    timestamp: float
    payload: str = ""
    raw: dict = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return bool(self.source_ip)


class PhantomGridPoller:
    """
    Polls phantom-grid for OOB interaction callbacks.
    Used by ExploitAgent to confirm blind vulnerabilities.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        api_key: Optional[str] = None,
        poll_interval: float = 2.0,
        max_wait: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.poll_interval = poll_interval
        self.max_wait = max_wait

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["X-API-Key"] = self.api_key
        return h

    def get_interactions(self, interaction_id: str) -> list[OOBInteraction]:
        """Fetch all captured interactions for a given ID."""
        try:
            resp = httpx.get(
                f"{self.base_url}/api/interactions/{interaction_id}",
                headers=self._headers(),
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            return [self._parse(i) for i in data.get("interactions", [])]
        except httpx.HTTPError as e:
            logger.warning(f"phantom-grid poll failed: {e}")
            return []

    def wait_for_callback(self, interaction_id: str) -> Optional[OOBInteraction]:
        """
        Block until OOB callback received or max_wait exceeded.
        Returns first interaction or None on timeout.
        """
        elapsed = 0.0
        while elapsed < self.max_wait:
            interactions = self.get_interactions(interaction_id)
            if interactions:
                logger.info(
                    f"OOB callback received: {interaction_id} from {interactions[0].source_ip}"
                )
                return interactions[0]
            time.sleep(self.poll_interval)
            elapsed += self.poll_interval

        logger.warning(f"No OOB callback within {self.max_wait}s for {interaction_id}")
        return None

    def _parse(self, data: dict) -> OOBInteraction:
        return OOBInteraction(
            interaction_id=data.get("id", ""),
            protocol=data.get("protocol", "unknown"),
            source_ip=data.get("source_ip", ""),
            timestamp=data.get("timestamp", 0.0),
            payload=data.get("payload", ""),
            raw=data,
        )

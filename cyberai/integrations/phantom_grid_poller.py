"""
phantom-grid result poller — thin compatibility shim over PhantomGridClient.

Historically this module had its own client + OOBInteraction. It now delegates
to the single PhantomGridClient (v2.0 API) so there is one endpoint contract
and one OOBInteraction type. The public API (wait_for_callback,
get_interactions) is preserved for ssrf_workflow / xxe_workflow.
"""

from __future__ import annotations

import logging
import time
from typing import List, Optional

from cyberai.integrations.phantom_grid import OOBInteraction, PhantomGridClient

logger = logging.getLogger("cyberai.integrations.phantom_grid_poller")

# Re-export so existing `from ...phantom_grid_poller import OOBInteraction` works.
__all__ = ["OOBInteraction", "PhantomGridPoller"]


class PhantomGridPoller:
    """Polls phantom-grid for OOB callbacks. Delegates to PhantomGridClient."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:9090",
        api_key: Optional[str] = None,
        poll_interval: float = 2.0,
        max_wait: float = 30.0,
    ):
        self.poll_interval = poll_interval
        self.max_wait = max_wait
        self._client = PhantomGridClient(base_url=base_url, api_key=api_key)

    def get_interactions(self, interaction_id: str) -> List[OOBInteraction]:
        """Fetch all captured interactions for a given token/id."""
        return self._client.get_interactions(interaction_id)

    def wait_for_callback(self, interaction_id: str) -> Optional[OOBInteraction]:
        """Block until an OOB callback arrives or max_wait is exceeded."""
        elapsed = 0.0
        while elapsed < self.max_wait:
            interactions = self.get_interactions(interaction_id)
            if interactions:
                logger.info(
                    "OOB callback received: %s from %s",
                    interaction_id,
                    interactions[0].source_ip,
                )
                return interactions[0]
            time.sleep(self.poll_interval)
            elapsed += self.poll_interval
        logger.warning("No OOB callback within %.0fs for %s", self.max_wait, interaction_id)
        return None

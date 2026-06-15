"""Etherscan API client — fetch verified source, ABI, status (day 24).

Degrades gracefully when no API key is set (available=False), so the agent
can still analyze local .sol files without an internet/Etherscan dependency.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("cyberai.web3.etherscan")

DEFAULT_API = "https://api.etherscan.io/api"


@dataclass
class ContractSource:
    """Verified contract metadata from Etherscan."""

    address: str
    name: str = ""
    source_code: str = ""
    abi: str = ""
    compiler_version: str = ""
    verified: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)


class EtherscanClient:
    """Minimal Etherscan client for source/ABI retrieval."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_API,
        timeout: int = 15,
    ):
        self.api_key = api_key or os.getenv("ETHERSCAN_API_KEY", "")
        self.base_url = base_url
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def get_source(self, address: str) -> Optional[ContractSource]:
        """Fetch verified source for a contract address. None if unavailable."""
        if not self.available:
            logger.warning("no ETHERSCAN_API_KEY — skipping remote source fetch")
            return None
        try:
            with httpx.Client(timeout=self.timeout) as client:
                r = client.get(
                    self.base_url,
                    params={
                        "module": "contract",
                        "action": "getsourcecode",
                        "address": address,
                        "apikey": self.api_key,
                    },
                )
                r.raise_for_status()
                body = r.json()
        except Exception as exc:  # noqa: BLE001 — never hard-fail
            logger.warning("etherscan fetch failed: %s", exc)
            return None

        results: List[Dict[str, Any]] = body.get("result", []) or []
        if not results or not isinstance(results, list):
            return None
        item = results[0]
        source = item.get("SourceCode", "") or ""
        return ContractSource(
            address=address,
            name=item.get("ContractName", ""),
            source_code=source,
            abi=item.get("ABI", ""),
            compiler_version=item.get("CompilerVersion", ""),
            verified=bool(source) and item.get("ABI") != "Contract source code not verified",
            raw=item,
        )

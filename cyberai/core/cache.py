"""
Simple file-based JSON cache for NVD API responses.
Avoids hammering the API and respects rate limits.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional

DEFAULT_CACHE_DIR = Path.home() / ".cyberai" / "cache"
DEFAULT_TTL = 3600 * 24  # 24 hours


class FileCache:
    def __init__(
        self,
        cache_dir: Path = DEFAULT_CACHE_DIR,
        ttl: int = DEFAULT_TTL,
    ):
        self.cache_dir = Path(cache_dir)
        self.ttl = ttl
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _key_path(self, key: str) -> Path:
        hashed = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self.cache_dir / f"{hashed}.json"

    def get(self, key: str) -> Optional[Any]:
        path = self._key_path(key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            if time.time() - data["ts"] > self.ttl:
                path.unlink(missing_ok=True)
                return None
            return data["value"]
        except Exception:
            return None

    def set(self, key: str, value: Any) -> None:
        path = self._key_path(key)
        try:
            path.write_text(json.dumps({"ts": time.time(), "value": value}))
        except Exception:
            pass

    def delete(self, key: str) -> None:
        self._key_path(key).unlink(missing_ok=True)

    def clear(self) -> int:
        count = 0
        for f in self.cache_dir.glob("*.json"):
            f.unlink(missing_ok=True)
            count += 1
        return count

    def stats(self) -> dict:
        files = list(self.cache_dir.glob("*.json"))
        expired = 0
        for f in files:
            try:
                data = json.loads(f.read_text())
                if time.time() - data["ts"] > self.ttl:
                    expired += 1
            except Exception:
                expired += 1
        return {
            "total": len(files),
            "expired": expired,
            "valid": len(files) - expired,
            "cache_dir": str(self.cache_dir),
        }

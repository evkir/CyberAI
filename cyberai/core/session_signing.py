"""Tamper-evident signing for audit-trail events.

Each JSONL line written by AuditLogger carries a `sig` field: an HMAC-SHA256
over the canonical form of that same line with `sig` removed. Editing any
field of a recorded event invalidates its signature.

The key comes from CYBERAI_SESSION_SECRET. When that variable is unset a
published fallback is used, and the signature then detects accidental
corruption only — anyone who has read this file can forge a line. Set the
variable per engagement for the guarantee to be worth anything.

Verification has a consumer: `cyberai audit-verify <file>`.
"""

import hashlib
import hmac
import json
import os

FALLBACK_SECRET = "dev-secret-change-in-prod"
SIGNATURE_FIELD = "sig"


def session_secret() -> str:
    """Read the signing key at call time, not at import time.

    Reading it at import would freeze whatever the environment held when the
    module was first touched, which is not necessarily what the operator set
    for the run.
    """
    return os.getenv("CYBERAI_SESSION_SECRET", FALLBACK_SECRET)


class SessionSigner:
    """Signs and verifies one audit event, represented as a dict."""

    def __init__(self, secret: str = None):
        self._secret = secret

    @property
    def secret(self) -> str:
        return self._secret if self._secret is not None else session_secret()

    @staticmethod
    def _canonical(event: dict) -> bytes:
        """Serialise an event for signing, excluding the signature itself.

        sort_keys makes the byte string independent of dict ordering, so a
        reader that parses and re-serialises a line still verifies.
        """
        body = {k: v for k, v in event.items() if k != SIGNATURE_FIELD}
        return json.dumps(body, sort_keys=True, default=str).encode()

    def sign(self, event: dict) -> str:
        """Return the hex signature for an event."""
        return hmac.new(self.secret.encode(), self._canonical(event), hashlib.sha256).hexdigest()

    def verify(self, event: dict) -> bool:
        """True when the event carries a signature matching its contents."""
        recorded = event.get(SIGNATURE_FIELD)
        if not isinstance(recorded, str):
            return False
        return hmac.compare_digest(self.sign(event), recorded)

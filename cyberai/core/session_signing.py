"""
Tamper-evident session audit trail.
Each session event is HMAC-signed — any modification is detectable.
"""

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import List

SESSION_SECRET = os.getenv("CYBERAI_SESSION_SECRET", "dev-secret-change-in-prod")


@dataclass
class AuditEvent:
    timestamp: float
    agent: str
    action: str
    target: str
    result_summary: str
    signature: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "agent": self.agent,
            "action": self.action,
            "target": self.target,
            "result_summary": self.result_summary,
        }


class SessionSigner:
    """Signs and verifies audit events using HMAC-SHA256"""

    def __init__(self, secret: str = SESSION_SECRET):
        self.secret = secret.encode()

    def sign_event(self, event: AuditEvent) -> AuditEvent:
        payload = json.dumps(event.to_dict(), sort_keys=True).encode()
        sig = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
        event.signature = sig
        return event

    def verify_event(self, event: AuditEvent) -> bool:
        payload = json.dumps(event.to_dict(), sort_keys=True).encode()
        expected = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, event.signature)

    def verify_trail(self, events: List[AuditEvent]) -> List[bool]:
        return [self.verify_event(e) for e in events]


class AuditTrail:
    """Tamper-evident log of all agent actions in a session"""

    def __init__(self):
        self.signer = SessionSigner()
        self.events: List[AuditEvent] = []

    def log(self, agent: str, action: str, target: str, result: str):
        event = AuditEvent(
            timestamp=time.time(),
            agent=agent,
            action=action,
            target=target,
            result_summary=result[:500],  # Truncate large outputs
        )
        self.events.append(self.signer.sign_event(event))

    def verify_integrity(self) -> bool:
        """Returns True if audit trail has not been tampered with"""
        results = self.signer.verify_trail(self.events)
        return all(results)

    def get_report(self) -> List[dict]:
        return [{**e.to_dict(), "valid": self.signer.verify_event(e)} for e in self.events]

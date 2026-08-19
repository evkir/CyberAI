from typing import Dict, List, Optional

from .injection_detector import scan_messages
from .input_sanitizer import redact_sensitive, sanitize_llm_input, validate_json_output


class SecurityError(Exception):
    """Raised when a security violation is detected"""

    pass


class LLMGuard:
    """
    Security middleware for LLM calls.
    Wraps LLMClient with injection detection + input sanitization.

    Usage:
        guard = LLMGuard(llm_client, strict=True)
        response = guard.call(messages, system=system_prompt)
    """

    def __init__(self, llm_client, strict: bool = False):
        self.client = llm_client
        self.strict = strict  # If True, block on detection. Else, warn + sanitize.
        self.blocked_count = 0
        self.sanitized_count = 0

    def call(
        self,
        messages: List[Dict],
        system: Optional[str] = None,
        expected_json_keys: Optional[List[str]] = None,
    ) -> str:
        # 1. Scan for injections
        scan = scan_messages(messages)

        if not scan["clean"]:
            self.blocked_count += 1
            details = scan["details"]
            summary = f"Injection detected in {scan['injections_found']} message(s)"

            if self.strict:
                raise SecurityError(f"{summary}: {[d['matches'] for d in details]}")
            else:
                # Warn but continue with sanitized input
                print(f"[LLMGuard] WARNING: {summary} — sanitizing input")

        # 2. Sanitize inputs
        clean_messages = sanitize_llm_input(messages)
        if clean_messages != messages:
            self.sanitized_count += 1

        # 3. Call LLM
        raw_response = self.client.call(clean_messages, system=system)

        # 4. Redact sensitive data from response before returning
        safe_response = redact_sensitive(raw_response)

        # 5. Validate JSON if expected
        if expected_json_keys:
            result = validate_json_output(safe_response, expected_json_keys)
            if not result["valid"]:
                print(f"[LLMGuard] WARNING: Invalid JSON output — {result['error']}")

        return safe_response

    def stats(self) -> Dict[str, int]:
        return {
            "blocked": self.blocked_count,
            "sanitized": self.sanitized_count,
        }

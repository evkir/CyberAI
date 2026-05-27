import re
import json
from typing import Any, Dict, List

# Max sizes to prevent context stuffing
MAX_TARGET_LENGTH = 253
MAX_INPUT_LENGTH = 10_000
MAX_FIELD_LENGTH = 2_000
MAX_BANNER_LENGTH = 500

def sanitize_target(target: str) -> str:
    """
    Sanitize pentest target — must be valid hostname/IP.
    Strips dangerous characters.
    """
    # Allow only valid hostname/IP chars
    cleaned = re.sub(r"[^\w\.\-:]", "", target)
    return cleaned[:MAX_TARGET_LENGTH]

def sanitize_text(text: str, max_length: int = MAX_FIELD_LENGTH) -> str:
    """
    Sanitize free-form text input.
    Removes control chars, limits length.
    """
    # Remove null bytes and control characters
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Remove potential template injection markers
    cleaned = re.sub(r"\{\{|\}\}", "", cleaned)
    cleaned = re.sub(r"<\|im_(start|end)\|>", "", cleaned)
    return cleaned[:max_length]

def sanitize_banner(banner: str) -> str:
    """
    Neutralise a service banner before it enters LLM context.

    Service banners are attacker-controllable (a host can put anything in
    its SSH/HTTP banner). Truncate to MAX_BANNER_LENGTH, strip ANSI escape
    sequences and bidi-control characters, reuse sanitize_text for control
    chars, then wrap in an explicit untrusted marker so the LLM treats the
    content as data, never as instructions.
    """
    if not isinstance(banner, str):
        return ""
    # Strip ANSI escape sequences (e.g. \x1b[31m)
    text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", banner)
    # Strip Unicode bidi-control characters (Trojan-Source style smuggling)
    text = re.sub(r"[\u202a-\u202e\u2066-\u2069]", "", text)
    # Reuse the standard control-char / template scrubber
    text = sanitize_text(text, MAX_BANNER_LENGTH).strip()
    return f"[UNTRUSTED INPUT] {text} [/UNTRUSTED INPUT]"


def sanitize_llm_input(messages: List[Dict]) -> List[Dict]:
    """
    Sanitize messages before sending to LLM.
    Strips dangerous patterns from user-controlled content.
    """
    sanitized = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")

        # Only sanitize user/tool messages — not system prompts
        if role in ("user", "tool", "function"):
            content = sanitize_text(content, MAX_INPUT_LENGTH)

        sanitized.append({"role": role, "content": content})
    return sanitized

def validate_json_output(raw: str, expected_keys: List[str] = None) -> Dict[str, Any]:
    """
    Validate and parse LLM JSON output.
    Prevents malformed JSON from crashing the pipeline.
    """
    try:
        # Strip markdown fences
        clean = re.sub(r"```(?:json)?|```", "", raw).strip()
        data = json.loads(clean)

        if expected_keys:
            missing = [k for k in expected_keys if k not in data]
            if missing:
                return {
                    "valid": False,
                    "error": f"Missing keys: {missing}",
                    "data": data,
                }

        return {"valid": True, "data": data}
    except json.JSONDecodeError as e:
        return {"valid": False, "error": str(e), "data": {}}

def redact_sensitive(text: str) -> str:
    """Redact API keys, tokens, passwords from logs"""
    patterns = [
        (r"sk-[a-zA-Z0-9]{20,}", "sk-***REDACTED***"),
        (r"Bearer [a-zA-Z0-9\-_\.]{20,}", "Bearer ***REDACTED***"),
        (r"password['\"]?\s*[:=]\s*['\"]?[\w\!\@\#\$]{4,}", "password=***REDACTED***"),
        (r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[\w\-]{8,}", "api_key=***REDACTED***"),
        (r"token['\"]?\s*[:=]\s*['\"]?[\w\-\.]{8,}", "token=***REDACTED***"),
    ]
    result = text
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result

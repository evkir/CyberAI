import json
import re
from typing import Any, Dict, List, Optional

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
    # Nothing survived the scrub, so there is nothing to mark. Returning the
    # bare marker here would hand callers a 37-char truthy string for a port
    # that answered with nothing, whitespace, or pure ANSI noise, making a
    # closed port indistinguishable from a live service: behavioral_probe
    # tests the grab result for truthiness before recording it and measures
    # len() for tarpit latency. No data, no marker.
    if not text:
        return ""
    return f"[UNTRUSTED INPUT] {text} [/UNTRUSTED INPUT]"


def block_parts(content: List[Any]) -> List[tuple[int, str]]:
    """Index and text of every readable block in a block-list message.

    The anthropic tool path builds a message whose content is a list of typed
    blocks, and the text a tool returned sits under the block's own
    ``content`` key. A block with no string there -- an image, a shape this
    product does not build -- yields nothing and travels untouched: passing an
    unknown shape through unread is honest, rewriting a guess at it is not.
    """
    parts: List[tuple[int, str]] = []
    for index, block in enumerate(content):
        if isinstance(block, dict) and isinstance(block.get("content"), str):
            parts.append((index, block["content"]))
    return parts


def text_parts(content: Any) -> List[tuple[int | None, str]]:
    """Every attacker-reachable string in one message, and where it sits.

    A string message is a single part at index None; a block list defers to
    block_parts. Message shape is this module's knowledge and the guard is its
    consumer, so both layers read the same definition rather than each
    carrying its own idea of where the text lives.
    """
    if isinstance(content, str):
        return [(None, content)]
    if not isinstance(content, list):
        return []
    return [(index, text) for index, text in block_parts(content)]


def _sanitize_blocks(content: List[Any]) -> List[Any]:
    """Scrub the text inside each readable block, leaving the shape alone."""
    cleaned = list(content)
    for index, text in block_parts(content):
        cleaned[index] = {**cleaned[index], "content": sanitize_text(text, MAX_INPUT_LENGTH)}
    return cleaned


def sanitize_llm_input(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sanitize messages before sending to LLM.
    Strips dangerous patterns from user-controlled content.
    """
    sanitized = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")

        # Only sanitize user/tool messages -- not system prompts.
        # Content is not always a string: the anthropic tool path builds
        # messages as a list of typed blocks. That branch used to pass
        # through unchanged, so on that provider the ANSI escapes, control
        # characters, template markers and length cap never applied to tool
        # output at all. The scrub now reaches into the block and leaves the
        # surrounding shape untouched.
        if role in ("user", "tool", "function"):
            if isinstance(content, str):
                content = sanitize_text(content, MAX_INPUT_LENGTH)
            elif isinstance(content, list):
                content = _sanitize_blocks(content)

        sanitized.append({**msg, "role": role, "content": content})
    return sanitized


def validate_json_output(raw: str, expected_keys: Optional[List[str]] = None) -> Dict[str, Any]:
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

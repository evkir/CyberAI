import re
import unicodedata
from typing import Any, Dict, List

# Characters that render as a Latin letter but are not one. Written as escape
# sequences rather than as themselves: these are attack data, not text, and a
# reader scanning this file should see the codepoint. The repository holds no
# non-ASCII source characters and an architecture test keeps it that way.
#
# Only unambiguous look-alikes are here. A character with no single Latin
# twin is left alone: mapping it would corrupt more text than it uncovers.
CONFUSABLE_TO_LATIN = {
    0x0430: "a",
    0x0435: "e",
    0x043E: "o",
    0x0440: "p",
    0x0441: "c",
    0x0445: "x",
    0x0443: "y",
    0x0456: "i",
    0x0458: "j",
    0x04BB: "h",
    0x0433: "r",
    0x0410: "A",
    0x0412: "B",
    0x0415: "E",
    0x041A: "K",
    0x041C: "M",
    0x041D: "H",
    0x041E: "O",
    0x0420: "P",
    0x0421: "C",
    0x0422: "T",
    0x0425: "X",
    0x0405: "S",
    0x0406: "I",
    0x03B1: "a",
    0x03BF: "o",
    0x03C1: "p",
    0x03C5: "u",
    0x03BD: "v",
    0x0391: "A",
    0x0392: "B",
    0x0395: "E",
    0x0396: "Z",
    0x0397: "H",
    0x0399: "I",
    0x039A: "K",
    0x039C: "M",
    0x039D: "N",
    0x039F: "O",
    0x03A1: "P",
    0x03A4: "T",
    0x03A7: "X",
}

# Zero-width characters, deleted rather than mapped. They carry no glyph, so
# a payload can be sliced between them and read normally on screen while
# matching nothing.
ZERO_WIDTH = (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)

_NORMALISE_TABLE = {**CONFUSABLE_TO_LATIN, **dict.fromkeys(ZERO_WIDTH, None)}


def normalise_for_matching(text: str) -> str:
    """Fold look-alike characters so the patterns see what a reader sees.

    Three passes. NFKC collapses compatibility forms, which is what catches
    fullwidth Latin; it does not touch Cyrillic or Greek, because those are
    different letters rather than variants of the same one. Zero-width
    characters are then deleted, and the remaining confusables are mapped.

    The result is used for matching only and is never sent anywhere. The
    guard scores the raw message and sanitises the copy it transmits, and
    that order is what keeps two corpus injections visible; normalising on
    the way out would repeat the mistake in a new place.

    Measured on the tracked corpus: four injections become visible and no
    benign sample changes score. The mapping does rewrite legitimate
    Cyrillic text into Latin nonsense -- a Russian word comes out unreadable
    -- which costs nothing here because the patterns are English and nonsense
    matches none of them, but it is the reason this function's output must
    not reach a model or a report.
    """
    folded = unicodedata.normalize("NFKC", text)
    return folded.translate(_NORMALISE_TABLE)


# Known prompt injection patterns
INJECTION_PATTERNS = [
    # Role hijacking
    (r"ignore.{0,30}instructions?", "role_hijack"),
    (r"disregard (?:all |your |the |previous |prior |above )*instructions?", "role_hijack"),
    (r"forget (everything|all|your instructions)", "role_hijack"),
    (r"you are now (a |an )?(?!assistant|helpful)", "role_hijack"),
    (r"act as (a |an )?(?!assistant|helpful|security)", "role_hijack"),
    (r"new (role|persona|personality|instructions?)", "role_hijack"),
    # Jailbreak attempts
    (r"jailbreak", "jailbreak"),
    (r"dan (mode|prompt)", "jailbreak"),
    (r"developer mode", "jailbreak"),
    (r"sudo (mode|prompt|access)", "jailbreak"),
    (r"bypass (?:all |any |the |your )*(?:safety|filter|restriction|guideline)s?", "jailbreak"),
    (r"disable (safety|filter|restriction)", "jailbreak"),
    # Data exfil via prompt
    (r"(?:print|reveal|show)(?: me)? (?:your |the |full |entire |system )*prompt", "exfil"),
    (r"what (?:are|were|is|was) (?:your |the |original |initial |system )*instructions?", "exfil"),
    (r"repeat (everything|all) (above|before)", "exfil"),
    # Indirect injection via external content
    (r"<\s*script", "xss_attempt"),
    (r"<!--.*?-->", "html_injection"),
    (r"\{\{.*?\}\}", "template_injection"),
    (r"\$\{.*?\}", "template_injection"),
    # Context manipulation
    # Anchored to a line start: this is a chat role prefix, not a substring.
    # Unanchored it fired on the tail of a hostname before its port number,
    # so masec.ai:443 and api.system:8443 scored as context manipulation.
    (r"(?m)^\s*(assistant|ai|system)\s*:", "context_manipulation"),
    (r"\[system\]", "context_manipulation"),
    (r"<\|im_start\|>", "context_manipulation"),
    (r"<\|im_end\|>", "context_manipulation"),
    (r"system prompt", "context_manipulation"),
    (r"previous (context|conversation|message)", "context_manipulation"),
    # Encoded payloads
    (r"base64[\s,]*(decoded?|encoded?)?[\s]*payload", "encoded_payload"),
    (r"decode (this|the following|base64)", "encoded_payload"),
    (r"(from_|atob|b64decode|base64\.b64)", "encoded_payload"),
    # Unicode / escape-sequence smuggling
    (r"\\u[0-9a-fA-F]{4}", "unicode_escape"),
    (r"\\x[0-9a-fA-F]{2}", "unicode_escape"),
    (r"[\u202a-\u202e\u2066-\u2069]", "unicode_escape"),
]

COMPILED_PATTERNS = [
    (re.compile(pat, re.IGNORECASE | re.DOTALL), label) for pat, label in INJECTION_PATTERNS
]


def detect_injection(text: str) -> Dict[str, Any]:
    """Scan text for prompt injection patterns.

    Matching runs against a normalised copy so that a payload written with
    Cyrillic look-alikes, fullwidth Latin or zero-width separators is scored
    as what it reads as. ``input_length`` stays the length of the text that
    arrived: the caller asked about that string, not about the folded one.
    """
    candidate = normalise_for_matching(text)
    matches = []
    for pattern, label in COMPILED_PATTERNS:
        found = pattern.findall(candidate)
        if found:
            matches.append(
                {
                    "type": label,
                    "pattern": pattern.pattern,
                    "matches": found[:3],  # Cap at 3 examples
                }
            )

    risk_score = min(len(matches) * 25, 100)
    is_injection = risk_score >= 25

    return {
        "is_injection": is_injection,
        "risk_score": risk_score,
        "matches": matches,
        "input_length": len(text),
    }


def scan_messages(messages: List[Dict]) -> Dict[str, Any]:
    """Scan a list of LLM messages for injection attempts"""
    all_results = []
    for i, msg in enumerate(messages):
        content = msg.get("content", "")
        if isinstance(content, str):
            result = detect_injection(content)
            if result["is_injection"]:
                all_results.append(
                    {
                        "message_index": i,
                        "role": msg.get("role", "unknown"),
                        **result,
                    }
                )

    return {
        "clean": len(all_results) == 0,
        "injections_found": len(all_results),
        "details": all_results,
    }

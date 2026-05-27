import re
from typing import Dict, Any, List

# Known prompt injection patterns
INJECTION_PATTERNS = [
    # Role hijacking
    (r"ignore.{0,30}instructions?", "role_hijack"),
    (r"disregard (all |your |previous )?instructions?", "role_hijack"),
    (r"forget (everything|all|your instructions)", "role_hijack"),
    (r"you are now (a |an )?(?!assistant|helpful)", "role_hijack"),
    (r"act as (a |an )?(?!assistant|helpful|security)", "role_hijack"),
    (r"new (role|persona|personality|instructions?)", "role_hijack"),

    # Jailbreak attempts
    (r"jailbreak", "jailbreak"),
    (r"dan (mode|prompt)", "jailbreak"),
    (r"developer mode", "jailbreak"),
    (r"sudo (mode|prompt|access)", "jailbreak"),
    (r"bypass (safety|filter|restriction|guideline)", "jailbreak"),
    (r"disable (safety|filter|restriction)", "jailbreak"),

    # Data exfil via prompt
    (r"print (your |the )?(system |full )?prompt", "exfil"),
    (r"reveal (your |the )?(system |full )?prompt", "exfil"),
    (r"show (me )?(your |the )?(system |full )?prompt", "exfil"),
    (r"what (are|were) your instructions", "exfil"),
    (r"repeat (everything|all) (above|before)", "exfil"),

    # Indirect injection via external content
    (r"<\s*script", "xss_attempt"),
    (r"<!--.*?-->", "html_injection"),
    (r"\{\{.*?\}\}", "template_injection"),
    (r"\$\{.*?\}", "template_injection"),

    # Context manipulation
    (r"(assistant|ai|system)\s*:", "context_manipulation"),
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
    (re.compile(pat, re.IGNORECASE | re.DOTALL), label)
    for pat, label in INJECTION_PATTERNS
]

def detect_injection(text: str) -> Dict[str, Any]:
    """
    Scan text for prompt injection patterns.
    Returns detection result with matches and risk score.
    """
    matches = []
    for pattern, label in COMPILED_PATTERNS:
        found = pattern.findall(text)
        if found:
            matches.append({
                "type": label,
                "pattern": pattern.pattern,
                "matches": found[:3],  # Cap at 3 examples
            })

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
                all_results.append({
                    "message_index": i,
                    "role": msg.get("role", "unknown"),
                    **result,
                })

    return {
        "clean": len(all_results) == 0,
        "injections_found": len(all_results),
        "details": all_results,
    }

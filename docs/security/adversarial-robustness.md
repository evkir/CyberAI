# Adversarial Robustness — CyberAI

## Threat Model

CyberAI processes untrusted external data (scan results, CVE descriptions,
web app responses) and feeds it into LLM agent context.
This creates a prompt injection attack surface.

## Mitigations Implemented

### 1. Input Sanitization Layer
All external data passes through `InputSanitizer` before reaching agent context.
Blocks known injection patterns: "ignore previous instructions", "act as", etc.
Hard length limit: 10,000 characters.

### 2. Structured Output Parsing
Agents never receive raw LLM output. Responses are parsed against
a schema — unstructured free-text cannot execute arbitrary actions.

### 3. Trust Boundary Enforcement
Each agent writes only to its designated KB namespace.
Orchestrator is the only agent with cross-namespace write access.

### 4. Session Audit Trail
Every agent action is HMAC-signed. Tampered audit logs are detectable.

### 5. Scope Validation Gate
All targets validated against authorized scope before any tool execution.
Out-of-scope targets return early — never reach tool execution.

## Known Limitations

- Pattern-based injection detection is bypassable with obfuscation
- HMAC secret must be rotated per engagement
- Rate limiter is per-session, not per-IP

## Future Work

- Semantic injection detection (LLM-based classifier)
- Cryptographic session binding to operator identity
- Read-only agent mode for passive recon

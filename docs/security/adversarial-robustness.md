# Adversarial Robustness — CyberAI

**Last verified against the code:** 2026-08-21. Every claim below names the
mechanism that implements it. Claims that could not be traced to a call site
were moved to Known Limitations rather than softened.

## Threat Model

CyberAI processes untrusted external data (scan results, CVE descriptions,
web app responses) and feeds it into LLM agent context.
This creates a prompt injection attack surface.

## Mitigations Implemented

### 1. Injection detection at every phase boundary
Each phase's output is serialised and scanned by `detect_injection` before it
propagates, in both the synchronous and the asynchronous pipeline. A hit does
not stop the run: it becomes a MEDIUM finding and appears in the report.
This layer marks untrusted content; it does not filter it.

### 2. Input sanitisation at two tool entry points
`sanitize_target` normalises the nmap target before the command line is built.
The `sanitize_input` decorator caps strings at 10,000 characters and blocks six
known injection patterns; it guards the TLS tool. This is per-tool hardening,
not a pipeline-wide layer.

### 3. Structured output parsing in the report phase
The report agent and its judge validate model output against a Pydantic schema,
so malformed output is rejected rather than consumed. Agents in other phases
consume model output without a schema.

### 4. Scope gate before the exploit phase
`validate_exploit_scope` runs before any exploit tool executes. A target outside
the authorized scope aborts the phase. When no scope is supplied the run
proceeds and records a warning — absence of scope is not treated as denial.
Recon and intel are not gated by this check.

### 5. Signed audit trail
Every line of `reports/audit_*.jsonl` carries an HMAC-SHA256 signature over
the rest of that line. Editing any recorded field invalidates it.
`cyberai audit-verify <file>` checks a trail line by line and exits non-zero
on any failure, so it can gate a pipeline.

The key is read from `CYBERAI_SESSION_SECRET` at the time of signing. When
that variable is unset a fallback published in this repository is used, and
the signature then detects accidental corruption only: anyone who has read
the source can forge a line. Set the variable per engagement.

## Known Limitations

- Pattern-based injection detection is bypassable with obfuscation.
- Two distinct `InputSanitizer` classes exist, in `core/safety.py` and in
  `core/security/`. Only the first one is reachable from a tool.
- `sanitize_banner` has no caller. Banners reach LLM context injection-scanned
  but not sanitised.
- Agent KB namespace permissions are declared in `AgentTrustBoundary` but never
  enforced: no agent write path validates its namespace.
- A signature proves the trail was not edited after the fact. It does not
  prove the run recorded everything: an event never logged leaves no trace.
- The SQLite audit backend is never constructed by the CLI or the orchestrator.
  Only the JSONL trail is written.
- The rate limiter is per-session, not per-IP.

## Future Work

- Either enforce KB namespace boundaries or remove the unused machinery.
- Semantic injection detection (LLM-based classifier).
- Read-only agent mode for passive recon.

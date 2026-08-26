# Adversarial Robustness — CyberAI

**Last verified against the code:** 2026-08-24. Every claim below names the
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

### 2. Input sanitisation at the tool entry points
`sanitize_target` normalises the nmap target before the command line is built.
The `sanitize_input` decorator inspects every string argument with
`detect_injection` and refuses the call when it fires; it guards the TLS tool.
Refusal, not repair: an argument it rewrote would send the tool at a target
nobody asked for and return the result as if it described the real one.
`sanitize_banner` wraps what a service says about itself before it is stored,
at both call sites that read one. This is per-tool hardening, not a
pipeline-wide layer.

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
- One detector answers for the whole project. `core/safety.py` used to carry a
  second one, six patterns against the canonical thirty-three; it now reports
  the canonical verdict and holds no patterns of its own.
- A single pattern hit blocks a tool argument. The threshold is not tuned
  against a corpus, so the cost of a false positive is a refused scan.
- Banners are wrapped as untrusted before storage, and the recon and intel
  phases contact no model, so no banner reaches a model from those phases. A
  wrapped banner does reach the report, which is what the marker is for.
- Agent KB namespace permissions are neither declared nor enforced. Any agent
  can write any key: the KB validates nothing about the writer.
- A signature proves the trail was not edited after the fact. It does not
  prove the run recorded everything: an event never logged leaves no trace.
- The SQLite audit backend is never constructed by the CLI or the orchestrator.
  Only the JSONL trail is written.
- The rate limiter is per-session, not per-IP.

## Future Work

- Enforce KB namespace boundaries, or state plainly that the KB is shared.
- Semantic injection detection (LLM-based classifier).
- Read-only agent mode for passive recon.

# Adversarial Robustness — CyberAI

**Last verified against the code:** 2026-08-27. Every claim below names the
mechanism that implements it. Claims that could not be traced to a call site
were moved to Known Limitations rather than softened. Figures come from
`examples/detector-eval/baseline.md`, which is written by a command and never
by hand.

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

## Measured coverage

The detector is scored against a corpus tracked in this repository, 48
injections across fifteen techniques and 45 samples of real output captured
from real tools. Reproduce with:

    cyberai detector eval --corpus tests/corpus

At the production threshold of 50, measured 2026-08-28 on CyberAI 1.6.0:
recall 33.3%, precision 76.2%, false positives 11.1%. At the detector's own
`is_injection` cut of 25: recall 58.3%, false positives 17.8%.

Matching runs against a normalised copy of the text. NFKC folding, deletion
of zero-width characters, and a table of Cyrillic and Greek letters that
render as Latin ones. That copy is used for scoring and is never sent
anywhere: the guard transmits the sanitised original, and normalising on the
way out would blind the detector the way scoring the sanitised copy already
did once. The fold costs nothing on this corpus and carries two more
injections across the threshold than the same patterns reach without it.

Six patterns were rewritten on 2026-08-28. Each had a single optional
qualifier group -- `disregard (all |your |previous )?instructions?` and its
kind -- which takes one alternative and then demands its object, so
"disregard all previous instructions" matched nothing. A repeating group
matches them. Recall moved by four points and no benign sample changed
score, which is the honest size of the win: the phrasings a published
bypass list would have used were already covered by other patterns.

The overall recall figure is still the least useful number in that
paragraph. Six injection subclasses score below the threshold on every
sample they hold: encoded payloads, exfiltration phrasing, MCP tool
metadata, five non-English languages, paraphrase that avoids the keywords,
and social pressure. A list of English regular expressions cannot reach any
of them, which is the case for a layer that is not a list of regular
expressions rather than for more entries in this one.

Two false positives are worth naming because they are ours. Ordinary
`nmap -sV` output scores 50 and reaches the guard, on an XML comment and a
hex escape, with nothing hostile present; the XML output format does the
same. The product flags its own scanner.

## Known Limitations

- Pattern-based injection detection is bypassable with obfuscation. This is
  measured, not assumed: base64 encoding scores zero on every sample in the
  corpus. Homoglyph substitution is now folded before matching, and one of
  three samples reaches the threshold rather than none, so the fold narrows
  the bypass without closing it.
- One detector answers for the whole project. `core/safety.py` used to carry a
  second one, six patterns against the canonical thirty-three; it now reports
  the canonical verdict and holds no patterns of its own.
- A single pattern hit blocks a tool argument, at the `sanitize_input`
  decorator's one call site. That path uses the detector's own cut of 25 and
  not the guard's configurable threshold, so the two halves of the boundary
  answer at different sensitivities. The cost of a false positive there is a
  refused scan.
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
- Semantic injection detection (LLM-based classifier). The seven blind
  subclasses above are the argument for it and the corpus is the instrument
  that will say whether it helped.
- Read-only agent mode for passive recon.

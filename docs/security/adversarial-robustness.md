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

The detector is scored against a corpus tracked in this repository, 49
injections across fifteen techniques and 45 samples of real output captured
from real tools. Reproduce with:

    cyberai detector eval --corpus tests/corpus

At the production threshold of 50, measured 2026-08-31 on CyberAI 1.6.0:
recall 59.2%, precision 100.0%, false positives 0.0%. The detector's own
`is_injection` cut of 25 gives the same three figures, because no sample in
either class scores between 25 and 50. That gap is a property of the
weights rather than a coincidence: a directive category is worth 50 and any
two structural ones are worth 20, so scores cluster away from the middle.

A false-positive rate of zero is a statement about 45 captured samples, not
about every tool that exists, and it should be read as the narrower claim
it is: across that capture the categories carrying an instruction fire on
nothing, and every false positive the old scoring produced came from a
category describing a text format.

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

The larger move on the same day was to the score itself. It was
`len(matches) * 25`, which counted patterns rather than techniques: a
category described in two patterns reached the threshold on its own, and
three near-duplicate exfil patterns outweighed a genuine role swap. The
score is now the sum of per-category weights over the distinct categories
that matched. Categories carrying an instruction to a model -- role
hijacking, jailbreak, prompt exfiltration, forged turn boundaries -- are
worth 50 each; categories describing a text format -- XML comments,
template markers, hex escapes, script tags -- are worth 10, so any two of
them together stay below both cuts.

The cost is recorded with the gain. One corpus injection is built from a
template marker and nothing else; it scores 10 now and is no longer
detected. That is the trade the measurement argues for: one crafted sample
against every stacktrace, HTML body and nmap comment in the benign half.

The overall recall figure is still the least useful number in that
paragraph. Three injection subclasses score below the threshold on every
sample they hold: five non-English languages, paraphrase that avoids the
keywords, and social pressure. A list of English regular
expressions cannot reach any of them, which is the case for a layer that is
not a list of regular expressions rather than for more entries in this one.

It was six. Exfiltration phrasing and MCP tool metadata left the list when
the weights changed, and neither left because a pattern was added: their
samples already matched one directive category and scored 25, which the
threshold of 50 discarded. Two whole techniques were invisible for the
arithmetic's sake rather than for want of a rule.

Encoded payloads left it on 2026-08-31, and that one did take a rule: a
base64 blob is now decoded and the decoded text is scanned. The subclass is
no longer blind and is not solved either -- two of its three samples still
score below the threshold, and one of those, despite its filename, carries
no base64 at all.

Until 2026-08-28 the false positives worth naming were ours. Ordinary
`nmap -sV` output scored 50 and reached the guard, on an XML comment and a
hex escape, with nothing hostile present; the XML output format did the
same. The product flagged its own scanner. Both categories are structural
and the same samples now score 20: still seen, no longer acted on. That is
the intended shape -- the detector keeps reporting what it matched, and the
score decides what any of it is worth.

## The second layer

Four techniques scored exactly zero on every sample at every threshold
tried when this layer was added: paraphrase, non-English instructions,
social pressure and encoding. Encoding has since left that list at the
pattern layer; the other three have not. Zero is not a threshold problem. A local model is asked about the same text
instead, under `CYBERAI_DETECTOR_L2`, and the two layers compose as a
maximum. Reproduce without a GPU with:

    cyberai detector eval --corpus tests/corpus --l2-replay \
      examples/detector-eval/l2-verdicts.json

At the production threshold the pair measures recall 98.0%, precision
100.0% and false positives 0.0%, against 59.2% recall for the patterns
alone. No technique in the corpus scores zero any more. One sample escapes
both layers: it is filed under the encoded subclass and holds no base64,
its payload is ROT13, and neither layer reads that.

The layers turn out to be complementary rather than corroborating. Of the
five injections the model misses, four are ones the patterns take: three at
exactly the threshold and one at 100. That is the argument for composing them rather than
replacing one with the other, and it is also why the composition is a
maximum and not a sum: two suspicions that each fall short are not evidence
twice over.

The model cannot lower a verdict the patterns reached, and it is asked only
where they have not already decided -- on the corpus that skips 29 of 94
samples, changing nothing. Its answer arrives through constrained decoding
and is read as data. If it does not arrive at all the layer has no opinion,
which is a different fact from a benign one and never becomes an exception:
an absent model must not take down a call the patterns had already scored.

Off by default, because the price is measured. About 2.4s per untrusted
message on the machine these figures were taken on, and ollama holds one
model at a time: where the session model differs from the classifier's, the
guard pays two model switches on top, roughly 6s each once the weights are
in the page cache. Those two numbers are hardware, not product, and will
differ elsewhere. The recall figures will not.

The verdicts a live run obtained are committed beside the report, so the
published figure is reproducible on a machine with no GPU at all. A
recording carries the fingerprint of the prompt it was taken under and
refuses to load beneath a different one, with a non-zero exit: an
unreachable model is a fact about a machine, but a recording answering a
question the code no longer asks is a fact about this repository.

## Known Limitations

- Pattern-based injection detection is bypassable with obfuscation. This is
  measured, not assumed: base64 encoding scores zero on every sample in the
  corpus. Homoglyph substitution is folded before matching and all three of
  those samples now clear the threshold, which closes that bypass on the
  corpus without closing it in general -- the fold maps the confusables it
  knows about.
- A structural signal alone is never a verdict, by construction. A payload
  assembled entirely from template markers, HTML comments or hex escapes
  scores at most 20 whatever it says. This is the deliberate half of the
  weighting and the half an attacker can aim at.
- One detector answers for the whole project. `core/safety.py` used to carry a
  second one, six patterns against the canonical thirty-one; it now reports
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
- Semantic injection detection (LLM-based classifier). The three blind
  subclasses above are the argument for it and the corpus is the instrument
  that will say whether it helped.
- Read-only agent mode for passive recon.

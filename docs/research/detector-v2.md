# Detector v2 — Prompt Injection at the Trust Boundary

CyberAI reads attacker-controlled text by design. Service banners, HTTP
bodies, nuclei findings and MCP tool descriptions all reach a language model,
and any of them can carry an instruction. This document records what the
detector does about that, what was measured, and what was not.

Every figure here comes from a committed report that a command reproduces.
Nothing in this file is typed by hand.

## L1 — pattern layer

31 patterns in 10 categories. The score is the sum of per-category weights
over the *distinct* categories that matched, capped at 100:

| weight | categories |
| --- | --- |
| 50 (directive) | role_hijack, jailbreak, exfil, context_manipulation, bidi_override |
| 10 (structural) | html_injection, template_injection, unicode_escape, xss_attempt, encoded_payload |

At the production threshold of 50, one directive category acts and two
structural artefacts do not. This replaced a score of `len(matches) * 25`,
which counted patterns rather than categories: seven categories held more
than one pattern, so a single category could reach the threshold alone while
the documentation claimed two had to agree.

Measured on the tracked corpus of 49 injections and 45 benign samples:

| layer | recall | precision | false positives |
| --- | --- | --- | --- |
| L1 | 57.1% | 100.0% | 0.0% |
| L1+L2 | 95.9% | 100.0% | 0.0% |

The benign half is real tool output — nmap service scans, nuclei JSON, MCP
tool descriptions written in the imperative, Java stack traces carrying
`${}`. A detector that flags those is not usable in this product, which is
why precision is reported next to recall and not instead of it.

## L2 — local classifier

A local model over Ollama answers one question about one piece of text.
Composition is `max(L1, L2)`: the second layer is worth exactly one directive
category and cannot lower a verdict the first layer already reached. It runs
only when L1 scored below the threshold, which skips 28 of 94 samples and
changes no verdict.

It is off unless `CYBERAI_DETECTOR_L2=1`. Measured on the development
machine the layer costs about 2.4s per untrusted message, and Ollama holds
one model at a time, so a session whose model differs from the classifier's
also pays two model switches. That is defensible for one scan report and not
for a loop.

Complementarity is the reason for `max` rather than replacement: three of the
five samples L2 misses are taken by L1 at exactly 50.

Two injections still escape both layers, both plain base64 with no
surrounding discussion of encoding. The encoded_payload patterns match talk
*about* base64 rather than base64 itself. Named, not hidden.

## L3 — isolation of tool output

The plan called for spotlighting and datamarking: wrap tool output so the
model reads it as data. Measurement pointed somewhere else first.

`TrustGuard.inspect` skipped every message whose content was not a string.
The anthropic tool path builds a message whose content is a list of typed
blocks, so on that provider tool output was never scored, never marked and
never redacted, whatever the policy said. A corpus sample scoring 100 through
the detector left the boundary reporting no score at all, and the verdict
claimed one message inspected while the loop had skipped it. The scrub that
strips ANSI escapes, control characters and template markers did not reach
inside the block either.

Both layers now read the same definition of where text sits in a message.
Blocks are scored one at a time and only the block that cleared the threshold
is marked, so one live banner does not drag nine clean results behind the
same label.

The metric for this layer is coverage of delivery points, not recall. It does
not move the numbers above, and it is not supposed to: a marked message is
still a detected-or-not message. What it changes is the set of paths on which
detection happens at all.

## What is not measured

**Attack success rate.** The honest test of a marking layer is whether the
model obeys the instruction with and without it. That measurement is not in
this document because it is not currently reproducible: the Ollama request
path sends neither temperature nor seed, and one input has been observed
producing two different verdicts in succession. A number from a run that
cannot be repeated is not a measurement.

**Anything outside the corpus.** Recall is recall against 49 samples chosen
by the author. It is a floor for what the detector catches and says nothing
about techniques nobody wrote a sample for.

## Reproducing

L1 only, no GPU required:

```bash
cyberai detector eval --corpus tests/corpus --threshold 50
```

Both layers, replaying the recorded verdicts rather than calling a model:

```bash
cyberai detector eval --corpus tests/corpus \
  --l2-replay examples/detector-eval/l2-verdicts.json
```

The recorded verdicts carry a fingerprint of the classifier prompt and refuse
to load under a different one. Committed reports live in
`examples/detector-eval/` and are regenerated by these commands, never edited.

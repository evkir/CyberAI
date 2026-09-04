# Detector v2 — Prompt Injection at the Trust Boundary

CyberAI reads attacker-controlled text by design. Service banners, HTTP
bodies, nuclei findings and MCP tool descriptions all reach a language model,
and any of them can carry an instruction. This document records what the
detector does about that, what was measured, and what was not.

Every figure here comes from a committed report that a command reproduces.
Nothing in this file is typed by hand.

## L1 — pattern layer

33 patterns in 10 categories. The score is the sum of per-category weights
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

Measured on the tracked corpus of 51 injections and 45 benign samples:

| layer | recall | precision | false positives |
| --- | --- | --- | --- |
| L1 | 62.7% | 100.0% | 0.0% |
| L1+L2 | 98.0% | 100.0% | 0.0% |

The benign half is real tool output — nmap service scans, nuclei JSON, MCP
tool descriptions written in the imperative, Java stack traces carrying
`${}`. A detector that flags those is not usable in this product, which is
why precision is reported next to recall and not instead of it.

## L2 — local classifier

A local model over Ollama answers one question about one piece of text.
Composition is `max(L1, L2)`: the second layer is worth exactly one directive
category and cannot lower a verdict the first layer already reached. It runs
only when L1 scored below the threshold, which skips 32 of 96 samples and
changes no verdict.

It is off unless `CYBERAI_DETECTOR_L2=1`. Measured on the development
machine the layer costs about 2.4s per untrusted message, and Ollama holds
one model at a time, so a session whose model differs from the classifier's
also pays two model switches. That is defensible for one scan report and not
for a loop.

Complementarity is the reason for `max` rather than replacement: four of the
five samples L2 misses are taken by L1, three at exactly 50 and one at 100.

One injection still escapes both layers, and the reason is not the one this
document gave until 2026-08-31. The encoded_payload patterns did match talk
*about* base64 rather than base64 itself, and that is fixed: a blob whose
bytes decode to text is decoded and the text is scanned, which is what took
one sample out of the pattern layer's blind set. The sample that remains is
filed under the encoded subclass and contains no base64. Its payload is
ROT13, which nothing here reads. The label was wrong, not only the pattern.

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
model obeys the instruction with and without it. That measurement is still
not in this document. What has changed is the reason: until 31.08.2026 it
could not be taken at all, because the Ollama request path sent neither
temperature nor seed and one input was observed producing two different
verdicts in succession. That path now carries both (see Determinism below),
so the measurement has become possible and has not yet been made. A number
from a run that cannot be repeated is not a measurement; the absence of a
number is not evidence either way.

**Anything outside the corpus.** Recall is recall against 51 samples chosen
by the author. It is a floor for what the detector catches and says nothing
about techniques nobody wrote a sample for.

## Determinism

The ollama request carries `num_ctx`, `temperature` and `seed`. The first two
are always sent; the seed is sent only when the session pinned one, because
an unpinned seed is a different answer from a seed of zero and the runtime
samples freely when nobody asks.

Measured on the product path, `qwen2.5-coder:14b`, one prompt, eight calls:

| Request | Distinct answers |
|---|---|
| Before, `options` carried `num_ctx` alone | 8 of 8 |
| After, with temperature and seed pinned | 1 of 8 |

The figure is a live GPU run and is not reproducible in CI. What CI holds
instead is the shape: the option keys named above are read out of the client
and compared against this section, and against the L2 classifier, which
builds the same request independently.

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

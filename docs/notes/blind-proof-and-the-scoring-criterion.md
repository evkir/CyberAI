# A confirmed blind SSRF scored as a failure

The local benchmark suite has four targets: SQL injection, command injection,
path traversal, and a blind SSRF. Two engines run against them. `real` fires
fixed per-class probes and answers whether the targets and the harness are
sound. `agent` runs the actual pipeline -- recon discovers the surface,
exploit attacks it -- knowing nothing about a target beyond its URL.

The probe engine scored 4/4. The agent engine scored 3/4. The single
disagreement was on the blind SSRF target, and the harness recorded it the
way a harness usually should: probe proved it, agent missed it.

## The agent had not missed it

The audit log of that run (`reports/audit_*.jsonl`) records
`params_oob_confirmed=1` with `oob_channel="live"`. The callback had landed.
The parameter was confirmed. The exploit agent had raised a finding at
severity HIGH with confidence 1.0.

The verdict was computed elsewhere:

```python
@property
def solved(self) -> bool:
    """A target counts as solved only when a proof held on the wire."""
    return self.confirmed > 0
```

`confirmed` counts payloads whose proof held against the response body. A
blind vector produces no such proof by construction: the target answers
identically whether or not the injection worked. That is what makes it
blind, and it is why its declared success signal -- written down in the
suite's own task table -- is a callback carrying the run nonce.

So the criterion was narrower than the suite it scored.

## Why this class of bug is worth naming

This is not a flaky test and not a model failure. It is a false negative by
construction: no agent, however good, could ever solve that target under that
criterion. Every blind class behaves the same way -- blind SSRF, blind SQLi,
command injection with no output channel, anything whose proof is a side
effect rather than a response.

The failure mode has a nasty shape. The better the out-of-band machinery
gets, the more results it silently discards, because a stronger blind-vector
capability produces more confirmations that the scorer refuses to read. And
the symptom points away from the cause: what surfaced was an engine
disagreement, which reads as a pipeline gap.

## The fix, and the part worth more than the fix

The change is small -- carry the count across and let either kind of proof
decide:

```python
oob_confirmed: int = 0

@property
def solved(self) -> bool:
    return self.confirmed > 0 or self.oob_confirmed > 0
```

The tests are the part that took the thought. Each new assertion was
mutation-tested, and a mutation has to change the meaning rather than the
form: dropping the `or` clause fails both new tests, while pinning
`oob_confirmed` to 0 fails only the test that checks the field is carried
across from the report. Two mutants, two distinct death certificates -- if
both mutants had killed the same set of tests, one of the tests would have
been redundant.

The transfer test asserts three things and not one: that `oob_confirmed`
arrived, that `requests_sent` arrived with it, and only then that `solved`
is true. A verdict is not the only thing a mutant can get wrong -- a scorer
that reaches the right answer while reporting a different cost is not the
same scorer -- so the boolean is never pinned on its own.

## Measurement

CyberAI 1.5.0, four-task local suite, 2026-08-13:

| run | result |
| --- | --- |
| `--engine real` | 4/4 |
| `CYBERAI_USE_OOB=1 --engine agent` | 4/4, no disagreement |
| `--engine agent`, flag off | 3/4, disagreement recorded |

The third row is the negative control. The out-of-band path is off by
default because a parameter that is not vulnerable costs the collector's
full wait before it says so, so the flag is published alongside the number
rather than folded into it.

## What I got wrong on the way

Before finding this I had a confident wrong hypothesis: that the callback
was going nowhere because the collector URL defaults to
`http://127.0.0.1:9090`, which is loopback and unreachable from inside a
container. That was wrong. The exploit agent replaces the host with the
Docker bridge gateway, keeping the scheme and the port. Its docstring
describes exactly that, and records that the behaviour was measured against
a local blind-SSRF target.

I had reached the conclusion from a default value without reading the code
that consumes it. Grep the consumers of a symbol before concluding anything
about behaviour -- reading the producer tells you what a value is, not what
happens to it.

## The general form

If a success criterion reads a counter, check what that counter counts. Mine
was named for the question I thought I was asking and answered a narrower
one. The suite declared, in writing, that one of its targets is scored by a
callback; the scorer never read that column.

Source: <https://github.com/evkir/CyberAI>, commit `9255327`. Suite and
method: `docs/benchmarks/local-suite.md`.

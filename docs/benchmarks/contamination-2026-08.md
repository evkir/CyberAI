# Benchmark contamination, August 2026

The local suite scored 4/4 on both engines for months. Part of that score was
self-referential: the exploitation engine held a literal from a target this
project wrote, so at least one proof measured recognition rather than
exploitation. This page records what was wrong, what changed, and what the
numbers did.

## What was contaminated

`cyberai/agents/exploit/web_payloads.py` carried a module constant holding the
exact flag `cyberai/bench/apps/path_traversal.py` plants outside its web root,
and the SQL-injection proof accepted the JSON body our own bench login prints
on success. Both shipped to PyPI inside the exploitation engine, so every user
received an engine that recognised strings from this repository's CTF apps.

The second form is the instructive one. It carried no flag at all: the proof
looked for a status field that our bench login returns and that Juice Shop
also returns from an untouched product listing. A grep for `FLAG{` finds the
first and never the second.

## What changed

| Before | After |
|---|---|
| Traversal proof matched a planted flag literal | Structural match on the shape of a file the target should not serve |
| SQLi proof accepted our login's success body | Auth bypass proven by the 401 to 200 transition, not by any string |
| Nothing prevented a recurrence | `tests/architecture/test_no_bench_leak.py` runs every production proof against every string constant the bench apps are built from |

The guard asserts two things. The textual half forbids a flag literal outside
`cyberai/bench/`. The behavioural half is what caught the harder case: it
requires that no shipped proof is satisfied by any literal our targets are
built from. A grep cannot express the second.

## What the numbers did

Both engines still score 4/4. The honest expectation before the run was a
drop -- one traversal payload was removed and the SQLi proof became stricter --
and the drop did not happen. The targets remain solvable by proofs that know
nothing about them.

The cost of solving them fell:

| Task | Requests, published 2026-08-17 | Requests, 2026-08-26 | In-band proofs |
|---|---|---|---|
| local-sqli-login | 12 | 5 | 2, unchanged |
| local-cmdi-ping | 3 | 3 | 1, unchanged |
| local-path-traversal | 3 | 3 | 1, unchanged |
| local-ssrf-fetch | 10 | 10 | 0 in band, 1 out of band |
| **total** | **28** | **21** | **4 in band, 1 out of band** |

The whole difference is one task. A proof that no longer accepts a string this
project plants settles the parameter earlier than one that did, so the walk
stops sooner and spends less.

That saving belongs to the decontamination work, not to the run that published
these cards: the same task measured on `main` before the provenance changes
also spends 5. The published card predated the decontamination merge and had
never been regenerated -- which is its own finding, and the reason the cards
are now regenerated in the same branch that changes anything they report.

## What the score does not say

The agent engine reaches no model. `ReconAgent` and `ExploitAgent` are
constructed with two positional arguments on this path, so the client
parameter keeps its `None` default and no call can be made. The card records
this directly: `llm calls: 0`, `llm zero reason: engine_uses_no_model`.

So 4/4 is the score of a deterministic exploit corpus cross-checked by an
independent probe. It is not a measurement of model-driven exploitation, and
reading it as one would overstate what runs here. The metadata block exists so
a reader does not have to take that on trust.

The probe engine's card carries no call row at all. It builds no agents and
counts nothing, and a zero there would claim a measurement nobody took.

## Reproducing

```bash
cyberai bench run --suite local --engine agent \
  --scorecard examples/local-bench/scorecard-agent.md
```

Measured 2026-08-26, seed 1337, zero-day mode, all four targets up, the blind
target confirmed through a live out-of-band collector. See
[reproducibility.md](reproducibility.md) for what a run pins and what it still
does not measure.

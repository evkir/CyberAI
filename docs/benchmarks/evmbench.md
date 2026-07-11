# EVMBench (Web3 Discovery)

EVMBench is a public benchmark from Paradigm and OpenAI that measures how well
agents can **detect**, **patch**, and **exploit** vulnerabilities in real
audited Solidity codebases — 120 curated loss-of-funds vulnerabilities drawn
from 40 Code4rena and Sherlock audits. CyberAI's Web3 agent targets the
**detect** mode: audit a codebase and report loss-of-funds issues, scored by
recall against each audit's ground-truth findings.

No third-party benchmark code or contract source is bundled in this repo. The
adapter reads the upstream on-disk task layout from a local checkout you point
it at; CI runs against a small synthetic fixture instead.

## The three modes

| mode | task | upstream grading |
| --- | --- | --- |
| **detect** | audit a repo, report vulnerabilities | LLM judge, recall over 120 known vulns |
| **patch** | fix vulnerable code without breaking tests | original tests pass, exploit tests fail |
| **exploit** | craft transactions that change on-chain state | deterministic balance/state delta |

The upstream finding is that **discovery, not repair or transaction
construction, is the bottleneck** — which is exactly why detect is the mode we
lead with.

## What CyberAI does here

The adapter (`cyberai/bench/evmbench_loader.py`) reads the upstream task format:                        audits/<audit-id>/
config.yaml            audit id, framework, base_commit, ground-truth vulns
findings/<VULN>.md      per-vulnerability reference write-ups                                           `config.yaml` is parsed into an `EVMBenchAudit` (id + framework/base_commit) and
a list of `EVMBenchVuln` (id, title, detect award, exploit-task flag). Each audit
projects into a `BenchTask` carrying only the codebase path and a
human-readable goal — the ground-truth findings are **never** placed where the
engine could read them, so recall grading stays honest.

### Detect grading (deterministic recall proxy)

`grade_detect(audit, submission)` scores an agent's detect submission — the
EVMBench detect contract:

```json
{"vulnerabilities": [{"title": "...", "summary": "...", "impact": "..."}]}
```

It emits one result per ground-truth vulnerability (`<audit-id>:<vuln-id>`), so
the standard scorecard's per-class breakdown aggregates recall correctly across
an audit's mixed vulnerability classes.

Matching is a **deterministic class-overlap proxy**: a known vulnerability
counts as detected when the submission reports at least one finding of the same
vulnerability class (reentrancy, access-control, arithmetic, price-oracle, …),
where class is a keyword heuristic over the finding title. This is a design
choice with an explicit tradeoff:

- **Pro** — fully reproducible offline and in CI; no model call in the grader,
  so a published number never drifts with a judge model.
- **Con** — it is a recall *lower bound*, coarser than the upstream LLM judge.
  Two different reentrancy bugs both map to `reentrancy`, so class overlap can
  over-credit; the per-finding consume rule (N known vulns of a class need N
  reported findings of that class) limits that, but the proxy is not the
  upstream score and is not presented as one.

A known vulnerability whose title yields class `unknown` can only be matched by
a reported `unknown`, never by a real class — it never scores by luck.

## Running it

The full 120-task dataset requires Docker plus Foundry/Hardhat toolchains and
the upstream ground-truth checkout, so it does not run in the standard gate.
Point the adapter at a local checkout for a real run:

```python
from pathlib import Path
from cyberai.bench.evmbench_loader import EVMBenchAdapter

adapter = EVMBenchAdapter(Path("~/evmbench/audits").expanduser())
tasks = adapter.load_tasks()
```

CI exercises the loader and grader against a synthetic two-vulnerability audit
fixture (`tests/bench/fixtures/evmbench/`) so the format contract is regression-
tested without any external dependency.

## Current result

| metric | value |
| --- | --- |
| detect recall | **not yet measured** |
| grader | deterministic class-overlap proxy |
| live engine | wired in a later milestone |

No detect number is published yet: the live engine runner that produces
submissions is wired in a later milestone, and the deterministic grader only
reports recall once real submissions exist. As with every CyberAI benchmark, the
number goes up only when the engine earns it — never by fabricating success.

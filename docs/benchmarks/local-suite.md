# Local Suite Benchmark

CyberAI measures its own engine against a small, fully self-contained suite of
deliberately-vulnerable targets that we author and serve ourselves. No
third-party benchmark is required to reproduce these numbers.

## Why a local suite

Public AI-pentest claims are easy to inflate and hard to verify. The local
suite exists so every number we publish is:

- **Reproducible** — targets ship in this repo (`cyberai/bench/apps/`), built
  into throwaway containers by `cyberai/bench/docker_builder.py`.
- **Binary** — a target counts as solved only when an unambiguous success
  signal is present (a flag, output only a shell could produce, out-of-web-root file
  contents). No heuristic "looks exploited".
- **Traceable** — each run emits a Markdown scorecard with engine version,
  provider, model, and timestamp.

External suites (e.g. CVE-Bench) plug into the same `BenchTask` contract as
optional adapters, used for public-leaderboard parity — never as a dependency
of the product.

## Targets

| id | class | CWE | success signal |
| --- | --- | --- | --- |
| `local-sqli-login` | SQL injection | CWE-89 | auth-bypass flag returned by `/login` |
| `local-cmdi-ping` | command injection | CWE-78 | shell-evaluated arithmetic in output |
| `local-path-traversal` | path traversal | CWE-22 | flag from an out-of-web-root file |

## Running it

```bash
cyberai bench list
cyberai bench run --suite local --scorecard docs/benchmarks/scorecards/local.md
```

## Current result

| metric | value |
| --- | --- |
| pass@1 | **3/3 (100.0%)** |
| engine | live probes against containerised targets (`--engine real`) |
| measured | 2026-07-24, CyberAI 1.4.0 |

## What this number is, and what it is not

We author the targets, the probes, and the success signals. That makes the
result reproducible, and it also means the number is a **self-test, not a
comparison**. Stated plainly so nobody has to infer it from the source:

- **Self-authored suite.** 3/3 says our three targets are exploitable and our
  three probes detect it. It says nothing about how CyberAI compares to any
  other tool. Cross-tool claims need a third-party suite, and we do not make
  them here.
- **`--engine real` measures the probes, not the agent.** The probes are fixed
  exploit checks; the orchestrator, the agents, and the LLM take no part in
  this run. Read it as a harness-and-target check. Agent-driven measurement is
  a separate engine mode.
- **A solve must be earned.** Each probe looks for a signal that is absent from
  its own request — arithmetic only a shell can evaluate, a flag stored only
  inside an out-of-web-root file. A target that echoes request input back
  cannot register as exploited. `tests/unit/test_bench_negative_control.py`
  runs every probe against hardened targets and requires all of them to fail.
- **Small denominator.** Three tasks means one task moves the rate by 33
  points. The suite grows as classes are added, and the honest reading of any
  single figure has to account for that.

The number moves only when the engine earns it. This page is updated from a
measured run, never by hand.

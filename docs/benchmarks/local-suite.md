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
  signal is present (a flag, an injected command marker, out-of-web-root file
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
| `local-cmdi-ping` | command injection | CWE-78 | injected command marker in output |
| `local-path-traversal` | path traversal | CWE-22 | out-of-web-root file contents read |

## Running it

```bash
cyberai bench list
cyberai bench run --suite local --scorecard docs/benchmarks/scorecards/local.md
```

## Current result

| metric | value |
| --- | --- |
| pass@1 | **0/3 (0.0%)** |
| engine | placeholder runner (live engine not yet wired) |

The headline is intentionally **0/3**: the live engine runner is wired in a
later milestone. Until then the harness reports every task as unsolved rather
than fabricating success — the number only goes up when the engine actually
earns it. This page will be updated with each measured run.

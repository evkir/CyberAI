# Benchmark Scorecard — `local`

**pass@1: 4/4 = 100.0%**

## Run metadata

| field | value |
| --- | --- |
| timestamp | 2026-08-26T04:44:00Z |
| engine version | CyberAI 1.5.0 |
| llm calls | 0 |
| llm zero reason | engine_uses_no_model |
| note | cyberai bench run |
| engine | agent |
| suite | local |
| seed | 1337 |
| mode | zero-day |

## Per-class breakdown

| vuln class | solved | total | rate |
| --- | --- | --- | --- |
| command_injection | 1 | 1 | 100% |
| path_traversal | 1 | 1 | 100% |
| sqli | 1 | 1 | 100% |
| ssrf | 1 | 1 | 100% |

## Run metrics

What the engine reached and spent. A target that never came up scores zero for a reason the score cannot show, so availability travels with the numbers. In-band and out-of-band proofs are counted apart: a blind vector proves itself on a callback and leaves the response unchanged.

| task id | available | in-band | out of band | endpoints | requests |
| --- | --- | --- | --- | --- | --- |
| local-sqli-login | ✓ | 2 | 0 | 1 | 5 |
| local-cmdi-ping | ✓ | 1 | 0 | 1 | 3 |
| local-path-traversal | ✓ | 1 | 0 | 1 | 3 |
| local-ssrf-fetch | ✓ | 0 | 1 | 1 | 10 |
| **total** | 4/4 | 4 | 1 | 4 | 21 |

## Per-task results

| task id | solved | time (s) | error |
| --- | --- | --- | --- |
| local-sqli-login | ✓ | 11.48 |  |
| local-cmdi-ping | ✓ | 11.47 |  |
| local-path-traversal | ✓ | 11.50 |  |
| local-ssrf-fetch | ✓ | 12.23 |  |

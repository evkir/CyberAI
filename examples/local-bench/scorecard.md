# Benchmark Scorecard — `local`

**pass@1: 4/4 = 100.0%**

## Run metadata

| field | value |
| --- | --- |
| timestamp | 2026-08-26T04:45:30Z |
| engine version | CyberAI 1.5.0 |
| note | cyberai bench run |
| engine | real |
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

## Per-task results

| task id | solved | time (s) | error |
| --- | --- | --- | --- |
| local-sqli-login | ✓ | 11.34 |  |
| local-cmdi-ping | ✓ | 11.31 |  |
| local-path-traversal | ✓ | 11.34 |  |
| local-ssrf-fetch | ✓ | 11.89 |  |

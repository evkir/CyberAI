# Benchmark Scorecard — `local`

**pass@1: 3/3 = 100.0%**

## Run metadata

| field | value |
| --- | --- |
| timestamp | 2026-07-23T15:35:57Z |
| engine | CyberAI 1.3.0 |
| provider | unspecified |
| model | unspecified |
| note | cyberai bench run |
| engine | real |
| suite | local |

## Per-class breakdown

| vuln class | solved | total | rate |
| --- | --- | --- | --- |
| command_injection | 1 | 1 | 100% |
| path_traversal | 1 | 1 | 100% |
| sqli | 1 | 1 | 100% |

## Per-task results

| task id | solved | time (s) | error |
| --- | --- | --- | --- |
| local-sqli-login | ✓ | 11.29 |  |
| local-cmdi-ping | ✓ | 11.32 |  |
| local-path-traversal | ✓ | 11.31 |  |

# Examples — reproducible runs

Real output from CyberAI, committed as-is. Every artifact here is reproducible
with a single command on any machine with Docker.

## `local-bench/scorecard.md`

CyberAI's engine measured against our own local vulnerable suite — three
classic classes with binary, unambiguous success signals:

| target | class | CWE | proof of exploitation |
| --- | --- | --- | --- |
| `local-sqli-login` | SQL injection | CWE-89 | auth-bypass flag returned in the response |
| `local-cmdi-ping` | command injection | CWE-78 | injected marker appears in command output |
| `local-path-traversal` | path traversal | CWE-22 | out-of-web-root secret file contents read |

Each target runs in a throwaway container; a finding counts as solved only when
the live probe gets the proof back — no heuristics, no partial credit.

### Reproduce

```bash
pip install -e .
cyberai bench run --suite local --engine real --scorecard reports/scorecard.md
```

Docker is required (targets are containerized). Without it the suite degrades
gracefully and reports targets as unavailable rather than failing.

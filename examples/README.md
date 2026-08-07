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

## `juice-shop/`

A full pipeline run against OWASP Juice Shop in Docker — recon, HTTP-surface
walk, exploitation, and the model's reading of what came back. Committed
exactly as produced, including the parts that found nothing.

| what | result |
| --- | --- |
| endpoints discovered | 14 |
| endpoints tested | 13 (one skipped as destructive) |
| requests sent | 236 |
| confirmed | 1 — SQL injection, CWE-89 |
| proof | database parse error returned for `q='` on `/rest/products/search` |

The other 12 endpoints did not yield a confirmed finding: 15 parameters were
inert, and 10 answered 401/403. Those are not clean results — an endpoint that
rejects you is a different fact from one that ignores you, and the run says so
rather than counting silence as safety.

The analysis section is the local model reading that report: what was proven,
what the unauthorized parameters imply, and where to look next. It runs on
Ollama with no cloud call, and the run costs nothing.

### Reproduce

```bash
docker run -d --rm --name juiceshop -p 3000:3000 bkimminich/juice-shop
cyberai scan http://127.0.0.1:3000 --scope 127.0.0.1 \
  --provider ollama --model qwen2.5-coder:14b
```

Without `--provider`, the pipeline runs rule-based and the report omits the
analysis section — everything else is identical.

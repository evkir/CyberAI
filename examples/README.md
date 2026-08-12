# Examples — reproducible runs

Real output from CyberAI, committed as-is. Every artifact here is reproducible
with a single command on any machine with Docker.

## `local-bench/scorecard.md`

CyberAI's engine measured against our own local vulnerable suite — four
classes with binary, unambiguous success signals:

| target | class | CWE | proof of exploitation |
| --- | --- | --- | --- |
| `local-sqli-login` | SQL injection | CWE-89 | auth-bypass flag returned in the response |
| `local-cmdi-ping` | command injection | CWE-78 | injected marker appears in command output |
| `local-path-traversal` | path traversal | CWE-22 | out-of-web-root secret file contents read |
| `local-ssrf-fetch` | blind SSRF | CWE-918 | collector recorded a callback carrying the run nonce |

Each target runs in a throwaway container; a finding counts as solved only when
the live probe gets the proof back — no heuristics, no partial credit.

### Reproduce

```bash
pip install -e .
cyberai bench run --suite local --engine real --scorecard reports/scorecard.md
```

Docker is required (targets are containerized). Without it the suite degrades
gracefully and reports targets as unavailable rather than failing.

`local-ssrf-fetch` additionally needs the collector running, because a blind
vector has no other way to be proven — see `blind-ssrf/` below for how to start
it. Without the collector that one target reports unsolved and the suite scores
3/4, which is a fact about the run rather than about the engine.

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

## `blind-ssrf/`

A blind SSRF run against our own local target, kept because it is the one case
the response cannot answer. The fetch endpoint returns the same body, status
and length whichever way the request goes, so nothing in the reply separates a
vector that fired from a parameter nothing reads.

| what | result |
| --- | --- |
| endpoints discovered | 1 |
| requests sent | 10 |
| confirmed by response | 0 |
| confirmed out of band | 1 — SSRF, CWE-918, parameter `url` |
| proof | the target opened an HTTP connection to a collector we control |

The summary line reads `Confirmed: 0 (1 more out of band)` for that reason: the
target answered nothing, and it still did something. Both numbers are in the
report because they are different classes of evidence, and a run that collapses
them tells the reader less than it knows.

The collector is phantom-grid, reached at the Docker bridge gateway. A
container cannot call back to a loopback address — it reaches its own — so the
address is read at run time rather than named.

### Reproduce

```bash
git clone --depth 1 https://github.com/evkir/phantom-grid /tmp/phantom-grid
(cd /tmp/phantom-grid && python3 server/server.py) &

docker run -d --rm --name cyberai-bench-local-ssrf-fetch -p 8804:8804 \
  -v "$PWD/cyberai/bench/apps:/apps:ro" -w /apps \
  python:3.12-slim python /apps/ssrf_fetch.py 8804

cyberai scan http://127.0.0.1:8804 --scope 127.0.0.0/8 --oob \
  --provider ollama --model qwen2.5-coder:14b
```

Without `--oob` the parameter is reported as inert: the walk sees the same
identical responses and has nothing else to go on.

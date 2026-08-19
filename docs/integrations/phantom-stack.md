# Phantom Stack Integration

## Tools
| Tool          | Role                        |
|---------------|-----------------------------|
| phantom-grid  | OOB callbacks DNS/HTTP      |
| phantom-intel | CVE intel via NVD API 2.0   |
| reality-probe | Front fitness (not wired)   |

## phantom-grid
The grid is a Python/Flask service. There is no `package.json` and no
`server.js` — an earlier version of this page described a Node runtime that
does not exist in the repository.

```bash
git clone https://github.com/evkir/phantom-grid
pip install -r phantom-grid/server/requirements.txt
cd phantom-grid && python3 server/server.py
```

HTTP capture listens on **9090** by default (`HTTP_PORT`); `docker-compose.yml`
also maps 9443 and 53/udp for the DNS capture path. Verify before use:

```bash
curl -s http://127.0.0.1:9090/health
# {"db":true,"status":"ok"}
```

```python
from cyberai.integrations.phantom_grid_poller import PhantomGridPoller
poller = PhantomGridPoller(base_url="http://127.0.0.1:9090", max_wait=30.0)
```

See `docs/exploit/oob-exploitation-workflow.md` for the token flow.

## reality-probe

Not wired into the pipeline. The service rates a domain's fitness as a
Reality/XTLS front — it handshakes with verification disabled, so it never
reports certificate validity or expiry, and its score measures usability as
a front rather than TLS security. CyberAI's TLS phase needs the opposite,
and now runs its own handshake in `cyberai/agents/recon/tls_probe.py`.

Kept here because the service is useful on its own terms:

```bash
git clone https://github.com/evkir/reality-probe
cd reality-probe && pip install -r requirements.txt
python3 reality_probe.py   # listens on 7890, no flags
```

It is an async API: `POST /api/probe` with a `domains` field (newline-
separated string) starts a background run and returns immediately; results
come from polling `GET /api/status`. A run holds a global lock, released by
`POST /api/stop`. Omitting `domains` scans 1225 built-in domains and holds
that lock for roughly two minutes.

## Architecture

```text
CyberAI
  ReconAgent   -> tls_probe      (TLS, in-tree)
  IntelAgent   -> phantom-intel  (CVE)
  ExploitAgent -> phantom-grid   (OOB)
```

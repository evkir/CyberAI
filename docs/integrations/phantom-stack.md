# Phantom Stack Integration

## Tools
| Tool          | Role                        |
|---------------|-----------------------------|
| phantom-grid  | OOB callbacks DNS/HTTP      |
| phantom-intel | CVE intel via NVD API 2.0   |
| reality-probe | TLS analyzer                |

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
git clone https://github.com/evkir/reality-probe
cd reality-probe && pip install -r requirements.txt && python app.py --port 5000

from cyberai.integrations.reality_probe_client import RealityProbeClient
result = RealityProbeClient().probe("target.htb")
print(result.score)

## Architecture
CyberAI
  ReconAgent   -> reality-probe  (TLS)
  IntelAgent   -> phantom-intel  (CVE)
  ExploitAgent -> phantom-grid   (OOB)

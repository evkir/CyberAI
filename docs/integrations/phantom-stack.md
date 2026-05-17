# Phantom Stack Integration

## Tools
| Tool          | Role                        |
|---------------|-----------------------------|
| phantom-grid  | OOB callbacks DNS/HTTP      |
| phantom-intel | CVE intel via NVD API 2.0   |
| reality-probe | TLS analyzer                |

## phantom-grid
git clone https://github.com/evkir/phantom-grid
cd phantom-grid && npm install && node server.js --port 8080

from cyberai.integrations.phantom_grid_poller import PhantomGridPoller
poller = PhantomGridPoller(base_url="http://127.0.0.1:8080", max_wait=30.0)

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

# Live Recon CI

The **Live Recon** workflow proves CyberAI's recon phase runs end-to-end against
a real, authorized target on a schedule — a visible, reproducible pulse.

## What it does

Nightly (03:00 UTC) and on demand (`workflow_dispatch`):

```bash
cyberai scan scanme.nmap.org --recon-only --max-rps 50
```

- **`--recon-only`** — only the recon phase (nmap, WHOIS, DNS, subdomains). No
  intel, exploit, or report phase touches the external host.
- **`--max-rps 50`** — caps the nmap scan rate (`--max-rate`) to stay polite.
- The recon report is uploaded as a build artifact (30-day retention).

No secrets are used: recon is tool-driven and needs no LLM/API key.

## Why this is legal

`scanme.nmap.org` is operated by the Nmap project and is **explicitly authorized
for scan testing**. We stay within that invitation:

- **Recon only** — port/banner discovery, never exploitation.
- **Rate-limited** — `--max-rps` keeps traffic gentle.
- No credentials, no writes, no target modification.

HTB / OSCP labs are **never** scanned in public CI (ToS + credential/flag leak
risk); those stay local, and any writeups are sanitized.

## Live-run badge

The job publishes a shields endpoint JSON to a dedicated `badges` branch (keeps
`main` history clean):

```json
{"schemaVersion":1,"label":"live recon","message":"passing · 2026-07-23","color":"brightgreen"}
```

The README badge reads it via `img.shields.io/endpoint`, showing the last run's
status and date.

## Reproduce locally

```bash
sudo apt-get install -y nmap
pip install -e .
cyberai scan scanme.nmap.org --recon-only --max-rps 50
```

The recon report lands in `reports/`.

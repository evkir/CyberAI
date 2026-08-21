# CyberAI v1.0.0

First stable release of CyberAI — AI-native multi-agent pentest platform.

## Highlights

- Full async pipeline: recon → intel → exploit → report
- phantom stack integration: phantom-grid + phantom-intel + reality-probe
- Safety-first: scope validation, input sanitization, trust boundaries
- REST API + HTML dashboard
- CLI with --dry-run, --scope, --output
- 160+ tests, Python 3.11/3.12, CI green

## Quick Start

```bash
pip install -e .
cyberai scan 10.10.10.1 --scope 10.10.10.0/24 --dry-run
```

## Links

- Docs: docs/
- API Reference: docs/api/agents.md
- Contributing: CONTRIBUTING.md

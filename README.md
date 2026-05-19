<div align="center">


![CI](https://github.com/evkir/CyberAI/actions/workflows/ci.yml/badge.svg) ![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue) ![License](https://img.shields.io/badge/license-MIT-green)

# 🤖 CyberAI

**AI-powered pentest orchestration platform**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)
![LLM](https://img.shields.io/badge/LLM-OpenAI%20%7C%20Anthropic-blueviolet?style=flat-square)

> Built by someone who red-teams AI, not just with it.

</div>

---

## What is CyberAI?

CyberAI is a multi-agent orchestration layer for offensive security workflows.
It connects the **phantom toolchain** — OOB detection, CVE intelligence, TLS analysis —
and routes findings through an AI pipeline that surfaces actionable attack paths.

This is not a chatbot wrapper for pentesters.
It's an agentic system where specialized AI agents handle recon, correlation,
and reporting autonomously — while you focus on what matters: exploitation.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                        CyberAI Core                      │
│                                                          │
│   ┌──────────────────┐       ┌────────────────────────┐  │
│   │   Orchestrator   │──────▶│      Agent Pool        │  │
│   │      Agent       │       │  ┌─────────────────┐   │  │
│   └──────────────────┘       │  │  Recon Agent    │   │  │
│           │                  │  │  Intel Agent    │   │  │
│           │                  │  │  Exploit Agent  │   │  │
│           │                  │  │  Report Agent   │   │  │
│           │                  │  └─────────────────┘   │  │
│           │                  └────────────────────────┘  │
│           ▼                                              │
│   ┌──────────────────────────────────────────────────┐   │
│   │                  Phantom Stack                   │   │
│   │        phantom-grid  ·  phantom-intel            │   │
│   │                  reality-probe                   │   │
│   └──────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
```

### Agent responsibilities

| Agent | Role |
|-------|------|
| **Orchestrator** | Routes tasks, manages agent lifecycle, aggregates results |
| **Recon** | Target enumeration — DNS, WHOIS, subdomains, open ports |
| **Intel** | CVE lookups, CVSS scoring, exploit availability |
| **Exploit** | CVE → PoC mapping, attack surface analysis |
| **Report** | Findings aggregation → structured Markdown / PDF output |

---

## Security design

Multi-agent security is a first-class concern, not an afterthought:

- **Agent trust boundaries** — each agent operates with minimal necessary permissions
- **Input validation** — all external data sanitized before entering the LLM context
- **Prompt injection resistance** — structured prompts, output parsing, no raw passthrough
- **Audit trail** — every agent action logged with full inputs and outputs

> The irony of building an AI pentest tool while studying AI attack surfaces
> is intentional. Adversarial thinking is a design input.

---

## Project structure

```
CyberAI/
├── cyberai/
│   ├── core/               # Orchestrator, config, LLM client
│   ├── agents/
│   │   ├── recon/          # Target enumeration pipeline
│   │   ├── intel/          # CVE intelligence feed
│   │   ├── exploit/        # CVE → PoC mapping
│   │   └── report/         # Report generation
│   ├── integrations/       # Phantom stack connectors
│   └── utils/              # Shared helpers
├── templates/              # Jinja2 report templates
├── tests/
│   ├── unit/
│   └── integration/
├── config.example.yml
├── .env.example
├── requirements.txt
└── setup.py
```

---

## Quick start

**1. Clone and install**
```bash
git clone https://github.com/evkir/CyberAI.git
cd CyberAI
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

**2. Configure**
```bash
cp config.example.yml config.yml
cp .env.example .env
# Edit .env — add your OPENAI_API_KEY or ANTHROPIC_API_KEY
```

**3. Run**
```bash
python -m cyberai --help
```

---

## Configuration

```yaml
# config.yml
llm:
  provider: openai       # openai | anthropic
  model: gpt-4o
  max_tokens: 4096
  temperature: 0.2

phantom:
  grid_url: http://127.0.0.1:8080
  intel_db: ~/.phantom/intel.db

output_dir: reports/
verbose: false
timeout: 60
```

---

## Roadmap

```
[x] Project structure & scaffolding
[x] Config system (.env + YAML)
[ ] LLM client abstraction (OpenAI / Anthropic)
[ ] Orchestrator agent core loop
[ ] Recon agent — DNS, WHOIS, subdomain enum
[ ] phantom-intel integration — CVE context injection
[ ] phantom-grid integration — OOB result correlation
[ ] Exploit suggestion agent — CVE → PoC mapping
[ ] Report generation — Markdown + PDF output
[ ] Multi-agent safety protocol layer
[ ] CLI interface (click)
```

---

## Related tools

| Tool | Role |
|------|------|
| [phantom-grid](https://github.com/evkir/phantom-grid) | OOB interaction capture & analysis |
| [phantom-intel](https://github.com/evkir/phantom-intel) | CVE intelligence feed |
| [reality-probe](https://github.com/evkir/reality-probe) | TLS analysis & config auditing |

---

## Requirements

- Python 3.10+
- OpenAI API key **or** Anthropic API key
- phantom-grid (optional, for OOB correlation)

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
<sub>Part of the <a href="https://github.com/evkir">evkir</a> security toolchain.</sub>
</div>

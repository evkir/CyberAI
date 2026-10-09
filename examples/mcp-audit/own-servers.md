# MCP Audit Card - CyberAI's own servers

| field | value |
| --- | --- |
| timestamp | 2026-10-09T06:52:47Z |
| engine version | CyberAI 1.7.0 |
| llm calls | 0 |
| llm zero reason | the scan agent calls no model |
| transport | stdio |

## Target: the fixture that carries server instructions

```
python3 -m cyberai mcp-scan "python3 tests/fixtures/mcp_instructions_server.py" --report
```

## MCP Red-Team Report - `python3 tests/fixtures/mcp_instructions_server.py`

- transport: stdio
- connected: True
- protocol revision: 2025-11-25
- tools probed: 0

## Severity summary

- CRITICAL: 0
- HIGH: 1
- MEDIUM: 0
- LOW: 0
- INFO: 0

## Authorization metadata

- not applicable: stdio has no network origin

## OWASP MCP Top 10 / MITRE ATLAS mapping

| Stage | OWASP MCP Top 10 | MITRE ATLAS | Severity | Signals |
| --- | --- | --- | --- | --- |
| tool-poisoning | MCP03:2025 Tool Poisoning | AML.T0110 AI Agent Tool Poisoning | INFO | 0 |
| over-privilege | MCP02:2025 Privilege Escalation via Scope Creep | AML.T0086 Exfiltration via AI Agent Tool Invocation | INFO | 0 |
| trust-propagation | MCP06:2025 Intent Flow Subversion | AML.T0051 LLM Prompt Injection | INFO | 0 |
| attestation | MCP07:2025 Insufficient Authentication & Authorization | - | INFO | 0 |
| server-instructions | MCP06:2025 Intent Flow Subversion | AML.T0051 LLM Prompt Injection | HIGH | 1 |
| exposure | MCP07:2025 Insufficient Authentication & Authorization | AML.T0040 AI Model Inference API Access | INFO | 0 |

> MCP06 is titled "Intent Flow Subversion" in the OWASP index and
> "Prompt Injection via Contextual Payloads" in the README (beta drift).

---

## MCP Red-Team Scorecard - `python3 tests/fixtures/mcp_instructions_server.py`

- transport: stdio
- connected: True
- tools probed: 0

## STRIDE

| Category | Severity | Signals | Source |
| --- | --- | --- | --- |
| Spoofing | INFO | 0 | unauthenticated endpoint / self-asserted identity (attestation) |
| Tampering | INFO | 0 | poisoned / mutable tool metadata (poisoning) |
| Repudiation | INFO | 0 | MCP does not sign or attest invocations; not observable from a scan |
| Information disclosure | INFO | 0 | over-privileged exfil capability combinations (over-privilege/exposure) |
| Denial of service | INFO | 0 | network reachability / rebinding surface (exposure) |
| Elevation of privilege | HIGH | 1 | cross-server shadowing / confused-deputy + unauth invoke, server instructions summoning an unadvertised tool (trust/attestation/instructions) |

---

## Target: this project's own MCP server

```
python3 -m cyberai mcp-scan "python3 -m cyberai.mcp.server" --report
```

What earned the flag:

- `mcp_scan` -- CRITICAL, capabilities exec, net. exec capability paired with net forms a full command-and-I/O primitive. Read from name, description, inputSchema: exec from `command`; net from `endpoint`, `http`, `url`.

## MCP Red-Team Report - `python3 -m cyberai.mcp.server`

- transport: stdio
- connected: True
- protocol revision: 2025-11-25
- tools probed: 8

## Severity summary

- CRITICAL: 1
- HIGH: 0
- MEDIUM: 0
- LOW: 0
- INFO: 0

## Authorization metadata

- not applicable: stdio has no network origin

## OWASP MCP Top 10 / MITRE ATLAS mapping

| Stage | OWASP MCP Top 10 | MITRE ATLAS | Severity | Signals |
| --- | --- | --- | --- | --- |
| tool-poisoning | MCP03:2025 Tool Poisoning | AML.T0110 AI Agent Tool Poisoning | INFO | 0 |
| over-privilege | MCP02:2025 Privilege Escalation via Scope Creep | AML.T0086 Exfiltration via AI Agent Tool Invocation | CRITICAL | 1 |
| trust-propagation | MCP06:2025 Intent Flow Subversion | AML.T0051 LLM Prompt Injection | INFO | 0 |
| attestation | MCP07:2025 Insufficient Authentication & Authorization | - | INFO | 0 |
| server-instructions | MCP06:2025 Intent Flow Subversion | AML.T0051 LLM Prompt Injection | INFO | 0 |
| exposure | MCP07:2025 Insufficient Authentication & Authorization | AML.T0040 AI Model Inference API Access | INFO | 0 |

### Flagged items

- over-privilege: mcp_scan

> MCP06 is titled "Intent Flow Subversion" in the OWASP index and
> "Prompt Injection via Contextual Payloads" in the README (beta drift).

---

## MCP Red-Team Scorecard - `python3 -m cyberai.mcp.server`

- transport: stdio
- connected: True
- tools probed: 8

## STRIDE

| Category | Severity | Signals | Source |
| --- | --- | --- | --- |
| Spoofing | INFO | 0 | unauthenticated endpoint / self-asserted identity (attestation) |
| Tampering | INFO | 0 | poisoned / mutable tool metadata (poisoning) |
| Repudiation | INFO | 0 | MCP does not sign or attest invocations; not observable from a scan |
| Information disclosure | CRITICAL | 1 | over-privileged exfil capability combinations (over-privilege/exposure) |
| Denial of service | INFO | 0 | network reachability / rebinding surface (exposure) |
| Elevation of privilege | INFO | 0 | cross-server shadowing / confused-deputy + unauth invoke, server instructions summoning an unadvertised tool (trust/attestation/instructions) |

---

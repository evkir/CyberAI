# MCP / LLM offensive red-team

CyberAI treats Model Context Protocol (MCP) servers and LLM/RAG endpoints as
*targets*, not as configuration to audit. The `cyberai mcp-scan` command
connects to an endpoint discovered during a pentest, inventories its capability
surface, and runs a set of red-team analyses that map onto the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and
[MITRE ATLAS](https://atlas.mitre.org/).

## Offensive angle vs defensive scanners

Defensive MCP scanners (for example mcp-scan / Snyk, Cisco's mcp-scanner,
MCPwn, ghostprobe) statically inspect the MCP servers *you* have installed and
flag misconfigurations in your own supply chain. That is a config-review posture.

CyberAI comes from the other side. During an engagement it:

1. Discovers an MCP server or an LLM/RAG endpoint exposed by the target
   (a support chatbot, a RAG API, an agent backend).
2. Connects as an anonymous client and inventories the advertised tools,
   prompts, and resources.
3. Analyzes that surface for attacker-usable weaknesses.
4. Optionally confirms exploitation out-of-band (OOB callback) so a finding is
   reported only when a real signal comes back — not on a heuristic match.

The two postures are complementary; the offensive layer is what an external
attacker actually sees, and it is still thin ground across the tooling
landscape.

## What it checks

| Stage | What it looks for | OWASP MCP Top 10 | MITRE ATLAS |
| --- | --- | --- | --- |
| tool-poisoning | Hidden instructions, unicode tricks, base64, hidden HTML in tool metadata | MCP03:2025 Tool Poisoning | AML.T0110 AI Agent Tool Poisoning |
| over-privilege | Tools that touch fs/net/exec beyond their declared purpose | MCP02:2025 Privilege Escalation via Scope Creep | AML.T0086 Exfiltration via AI Agent Tool Invocation |
| trust-propagation | Steering / shadowing of sibling tools, cross-server name collisions | MCP06:2025 Intent Flow Subversion | AML.T0051 LLM Prompt Injection |
| attestation | Anonymous acceptance, self-asserted identity, no message auth | MCP07:2025 Insufficient Authentication & Authorization | - |
| exposure | Remote reachability, DNS-rebinding surface, dangerous capabilities | MCP07:2025 Insufficient Authentication & Authorization | AML.T0040 AI Model Inference API Access |
| mst-fuzzing | Low-level malformed / protocol fuzzing (optional, see below) | MCP05:2025 Command Injection & Execution | AML.T0110 AI Agent Tool Poisoning |

MCP06 is titled *Intent Flow Subversion* in the OWASP index and *Prompt
Injection via Contextual Payloads* in the project README; the taxonomy is in
beta and both names refer to the same category.

## Usage

Inventory a target (transport is inferred from the endpoint):

```bash
cyberai mcp-scan http://target.example.com:9090/mcp
cyberai mcp-scan "stdio://python3 ./their_server.py" --transport stdio
```

Emit a red-team report instead of the plain inventory:

```bash
# human-readable Markdown, with OWASP MCP / ATLAS mapping and a STRIDE scorecard
cyberai mcp-scan http://target.example.com/mcp --report

# machine-readable structured report
cyberai mcp-scan http://target.example.com/mcp --report-json
```

Every flagged tool becomes a finding on the scan session, so the analysis also
surfaces in the unified report and dashboard.

## Low-level fuzzing with MST (optional)

For protocol-level malformed-traffic fuzzing, CyberAI can bridge to
[MST (mas-sentry-toolkit)](https://github.com/evkir/mas-sentry-toolkit), a
separate MASec Lab tool. MST is invoked as an external process, never imported,
so it stays a fully optional dependency; when `mas-sentry` is not installed the
feature is skipped and the scan proceeds normally.

```bash
# lab / localhost target: no extra confirmation needed
cyberai mcp-scan "stdio://python3 ./lab_server.py" --mst --report

# non-lab target: fuzzing is gated behind an explicit scope confirmation
cyberai mcp-scan http://target.example.com/mcp --mst --confirm-scope --report
```

Non-lab targets are fuzzed only when scope is confirmed, either via
`--confirm-scope` or a session that already carries an authorized scope.

## Responsible use

Only scan MCP servers and LLM endpoints you are explicitly authorized to test.
The offensive checks connect to and interact with the target; the MST bridge
additionally sends malformed traffic. Keep destructive fuzzing to lab targets
or to engagements with a signed scope.

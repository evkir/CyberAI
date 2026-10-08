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

Step 3 is where this command stops. Every verdict it reports is a static
inference over metadata the server volunteered: the probe completes a
handshake, lists what is advertised, and calls nothing. Out-of-band
confirmation is how CyberAI proves blind findings on the network side, and
it is not wired to this path -- `mcp-scan` has no OOB option, and the
red-team fuzzer runs from planned injection subtasks rather than from an
MCP endpoint. A reader who expects a confirmed exploit here would be
expecting another command's work.

The two postures are complementary; the offensive layer is what an external
attacker actually sees, and it is still thin ground across the tooling
landscape.

## What it checks

| Stage | What it looks for | OWASP MCP Top 10 | MITRE ATLAS |
| --- | --- | --- | --- |
| tool-poisoning | Hidden instructions, unicode tricks, base64, hidden HTML, executable icon carriers in tool metadata | MCP03:2025 Tool Poisoning | AML.T0110 AI Agent Tool Poisoning |
| over-privilege | Tools that touch fs/net/exec beyond their declared purpose | MCP02:2025 Privilege Escalation via Scope Creep | AML.T0086 Exfiltration via AI Agent Tool Invocation |
| trust-propagation | Steering / shadowing of sibling tools, cross-server name collisions | MCP06:2025 Intent Flow Subversion | AML.T0051 LLM Prompt Injection |
| server-instructions | Steering text in the initialize reply: an unconditional directive naming a tool the server does not advertise, and the poisoning matchers over the same text | MCP06:2025 Intent Flow Subversion | AML.T0051 LLM Prompt Injection |
| attestation | Anonymous acceptance, self-asserted identity, no message auth, the capability set the server declares | MCP07:2025 Insufficient Authentication & Authorization | - |
| exposure | Remote reachability, DNS-rebinding surface, dangerous capabilities | MCP07:2025 Insufficient Authentication & Authorization | AML.T0040 AI Model Inference API Access |
| authorization-metadata | RFC 9728 protected-resource metadata: the 401 challenge, the pointer it carries, the issuer, dynamic client registration, client-id metadata documents, the `iss` parameter | MCP01:2025 Token Mismanagement & Secret Exposure | - |
| mst-fuzzing | Low-level malformed / protocol fuzzing (optional, see below) | MCP05:2025 Command Injection & Execution | AML.T0110 AI Agent Tool Poisoning |

MCP06 is titled *Intent Flow Subversion* in the OWASP index and *Prompt
Injection via Contextual Payloads* in the project README; the taxonomy is in
beta and both names refer to the same category.

## Coverage against the MCP Security Top 25

The table above says what the stages do. This one says what they do *not*,
measured against an external list rather than our own. The reference is
Adversa AI's "MCP Security: Top 25 MCP Vulnerabilities" -- a vendor ranking,
not a standard, and its own pages carry two different dates for the same
revision; it is used here because it is the only published enumeration of
this ground at that granularity.

Verdicts were produced by running the scanner against the fixture stands in
`tests/fixtures/`, not by reading the source. "Partial" means a signal is
produced from static metadata where the class is defined by behaviour a
scan cannot observe.

| # | Class | Verdict | What the scan actually does |
| --- | --- | --- | --- |
| 1 | Prompt Injection | partial | Ten detector categories over eight metadata channels. Server `instructions` are probed but reach no stage. |
| 2 | Command Injection | no | Needs a tool call; the probe invokes nothing. |
| 3 | Tool Poisoning (TPA) | yes | Nine MCP patterns plus the generic detector, over every advertised channel. |
| 4 | Remote Code Execution | no | Confirmation requires execution, which is out of scope for a read-only probe. |
| 5 | Unauthenticated Access | yes | An anonymous session that completes is reported HIGH. |
| 6 | Confused Deputy (OAuth Proxy) | partial | Authorization metadata is read; token delegation is not observable. |
| 7 | MCP Configuration Poisoning | no | Client-side class; the scanner has no client config under audit. |
| 8 | Token/Credential Theft | partial | Credential-harvest metadata is scored; stored or logged secrets are not reachable. |
| 9 | Token Passthrough | no | Requires watching the server call a backend. |
| 10 | Path Traversal | no | Needs a tool call with a crafted path. |
| 11 | Full Schema Poisoning | partial | `inputSchema` and `outputSchema` text is scanned; structural manipulation is not modelled. |
| 12 | Tool Name Spoofing | partial | Confusable and zero-width detection runs on names; no registry of legitimate names to compare against. |
| 13 | Localhost Bypass (NeighborJack) | yes | Bind host is parsed and a non-loopback bind is reported. |
| 14 | Rug Pull Attack | no | Requires comparing one scan against a later one; no baseline is stored. |
| 15 | Advanced Tool Poisoning (ATPA) | no | Defined by tool output at runtime, which the probe never collects. |
| 16 | Session Management Flaws | no | The probe opens one session and makes no assertion about its lifecycle. |
| 17 | Tool Shadowing | yes | Steering phrases plus sibling references, and name collisions against a supplied registry. |
| 18 | Resource Content Poisoning | no | Resources are inventoried by name; their content is never fetched. |
| 19 | Privilege Abuse/Overbroad Permissions | yes | Six capability classes scored for dangerous combinations. |
| 20 | Cross-Repository Data Theft | no | Token scope is not visible to an anonymous client. |
| 21 | SQL Injection | no | Needs a tool call. |
| 22 | Context Bleeding | no | Requires two sessions and a comparison; not implemented. |
| 23 | Configuration File Exposure | no | Client-side filesystem class, outside what an endpoint scan sees. |
| 24 | Preference Manipulation (MPMA) | no | Defined over repeated interactions; a single scan cannot observe it. |
| 25 | Cross-Tenant Data Exposure | no | Requires authenticated access as two tenants. |

Eight of twenty-five are covered or partly covered. The classes marked "no"
split into two groups: those needing a tool call or a second observation,
which a read-only inventory cannot reach by construction, and those that
belong to the client rather than to the endpoint. Neither group is a gap the
scanner is close to closing, and saying so is the point of the table.

### Icons, and the two directions of URL-mode elicitation

Revision 2025-11-25 added `icons` to tools, prompts, resources and the server's
own identity. It is text a client shows beside a tool's name before any call,
which makes it the same channel as `description` and it is scanned as one.

Two categories score it, and both are about the carrier rather than the
reference. An icon served from a CDN is how the field is meant to be used, and
the scanner reads flattened metadata, so it cannot tell the server's own origin
from anyone else's: a rule on "the source is remote" would flag the ordinary
case. What is scored is content a client executes or renders as markup --
`javascript:`, `vbscript:`, `data:text/html`, `data:image/svg`, a declared
`image/svg+xml`, or an `.svg` name. A PNG data URI is inline and is not
flagged; inline is not the property, executable is.

URL-mode elicitation is not a property of the scanned server at all, and the
scanner has no category for it. `ServerCapabilities` has no elicitation field:
the client declares willingness to open a URL, and a server asks for one with
error `-32042` in reply to a tool call. A probe that inventories a surface
calls nothing, so there is nothing to observe. The exposure runs the other
way -- a scanner that advertises the capability has agreed to follow the links
of the endpoint it is scanning -- and the probe therefore advertises no
elicitation at all. The SDK builds form and URL mode from a single callback
with no separate switch, so that is held by a test rather than by care.

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

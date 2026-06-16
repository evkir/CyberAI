# CyberAI MCP Server — Integration Guide

The CyberAI MCP server exposes reconnaissance and threat-intel capabilities as
[Model Context Protocol](https://modelcontextprotocol.io) tools, so MCP clients
such as Claude Desktop and Cursor can drive CyberAI directly.

## Available tools

| Tool | Purpose | Required args |
|------|---------|---------------|
| `nmap_scan` | Port-scan a host with nmap | `target` |
| `dns_enum` | Resolve DNS records | `target` |
| `whois_lookup` | WHOIS registration lookup | `target` |
| `subdomain_enum` | Enumerate subdomains | `target` |
| `cve_search` | Search NVD by keyword | `keyword` |
| `cve_detail` | Fetch one CVE by id | `cve_id` |
| `epss_score` | EPSS exploitation scores | `cve_ids` |

## Prerequisites

- Python 3.11+ with CyberAI installed (`pip install -e .` from the repo root).
- `nmap` on `PATH` for `nmap_scan`.
- `NVD_API_KEY` in the environment for higher NVD rate limits (optional).

## Running the server

The server speaks MCP over stdio:

```bash
python -m cyberai.mcp.server
```

It does not print anything on its own — it waits for an MCP client to connect
over stdin/stdout. To run a quick local smoke test, use the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector python -m cyberai.mcp.server
```

## Claude Desktop

Edit the Claude Desktop config file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Add a `cyberai` entry under `mcpServers`:

```json
{
  "mcpServers": {
    "cyberai": {
      "command": "python",
      "args": ["-m", "cyberai.mcp.server"],
      "env": {
        "NVD_API_KEY": "your-key-here"
      }
    }
  }
}
```

Restart Claude Desktop. The CyberAI tools appear in the tool picker; you can ask
Claude to run a scan or look up a CVE, and it will call the tools.

## Cursor

Cursor reads MCP servers from `~/.cursor/mcp.json` (global) or
`.cursor/mcp.json` (per-project):

```json
{
  "mcpServers": {
    "cyberai": {
      "command": "python",
      "args": ["-m", "cyberai.mcp.server"]
    }
  }
}
```

Use an absolute path to the Python interpreter from the CyberAI environment if
`python` on `PATH` is not the right one, e.g.
`/home/you/repo/CyberAI/.venv/bin/python`.

## Scope and safety

These tools run real reconnaissance against whatever target the client supplies.
Only point them at systems you are authorized to test. `nmap_scan` enforces a
flag whitelist; the other tools perform read-only lookups.

## Troubleshooting

- **No tools appear** — confirm the server starts without import errors:
  `python -c "import cyberai.mcp.server"`.
- **`nmap_scan` returns an error** — ensure `nmap` is installed and on `PATH`.
- **NVD rate-limit errors** — set `NVD_API_KEY`; without it NVD allows far fewer
  requests per minute.

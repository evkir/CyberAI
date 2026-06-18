# Agent API Reference

All pipeline agents share the `BaseAgent` contract. The orchestrator constructs
each agent with explicit dependencies and calls `run()`:

```python
agent = ReconAgent(config, session, llm, audit)
result = agent.run(target, context=None)  # -> dict; data also written to session.kb
```

- `config` — `CyberAIConfig` (feature flags, budget, output_dir)
- `session` — `ScanSession`; agents read/write findings and `session.kb`
- `llm` — `LLMClient` (may be `None` for deterministic / dry-run paths)
- `audit` — `AuditLogger`; every action is recorded

`run()` returns a status dict and persists structured data into `session.kb`
under the agent's key. Agents never mutate each other directly — the knowledge
base is the single source of truth between phases.

---

## ReconAgent

`cyberai/agents/recon/agent.py`

- **Input:** `target` (host / domain / IP)
- **Output dict + kb key `recon`:** open ports, DNS records, WHOIS, subdomains
- **Tools:** `nmap_scan` (flag-whitelisted), `dns_lookup`, `whois_lookup`,
  `subdomain_enum`
- **Edge cases:**
  - nmap flags are validated against a whitelist; unknown flags are rejected
    before subprocess (no shell, argv list).
  - Results are cached by `target + flags` hash (TTL); failed scans (rc != 0)
    are not cached.
  - Async variant (`AsyncReconAgent`) gathers DNS + subdomain enumeration
    concurrently; nmap/TLS stay on executor (blocking subprocess).

## IntelAgent

`cyberai/agents/intel/agent.py`

- **Input:** `target` + recon data from `session.kb`
- **Output dict + kb key `intel`:** ranked CVEs with CVSS, EPSS, exploit factor
- **Tools:** `cve_search` (NVD), `epss_score`
- **Edge cases:**
  - NVD rate-limited (50/30s with API key, 5/30s without); 429/503 →
    exponential backoff, max 3 retries.
  - EPSS HTTP failure → silent `0.0`, pipeline survives `api.first.org` outage.
  - Composite score boosts EPSS non-linearly (EPSS > 0.5 → 🔥, > 0.2 → ⚠).

## ExploitAgent

`cyberai/agents/exploit/agent.py`

- **Input:** `target` + intel data from `session.kb`
- **Output dict + kb key `exploit`:** attack paths, PoC mappings, OOB findings
- **Tools:** `build_chain`, `map_poc`; optional nuclei / OOB workflows
- **Flags:** `use_native_tools` (LLM-driven chain via native tool calling),
  `use_nuclei` (nuclei engine + OOB wiring)
- **Edge cases:**
  - OOB workflows (SSRF/XXE) confirm blind vulns via phantom-grid callbacks —
    see [../exploit/oob-exploitation-workflow.md](../exploit/oob-exploitation-workflow.md).
  - Native tool args carry identifiers (`cve_id`/`target`), not full CVE dicts;
    real data is resolved agent-side (anti-hallucination, fewer tokens).
  - Falls back to the deterministic path if the model never calls `build_chain`.
  - searchsploit / nuclei absent → graceful (`available = False`), not fatal.

## ReportAgent

`cyberai/agents/report/agent.py`

- **Input:** `target` + full `session.kb`
- **Output dict + kb key `report`:** Markdown report path; optional H1 export
- **Tools:** deterministic renderer; optional LLM summary + judge
- **Flags:** `use_llm_summary` (structured LLM summary), `use_judge`
  (LLM-as-judge validation)
- **Edge cases:**
  - Deterministic report never fails on LLM error (fail-safe try/except).
  - Judge validates each claim against kb evidence; score < 0.7 triggers a
    regeneration with feedback. Hallucinated CVEs (not in kb) are caught.
  - HackerOne export follows the H1 template (title / severity / steps /
    impact / recommendation).

## SmartContractAgent (Web3)

`cyberai/agents/web3/agent.py`

- **Standalone** — not part of the network pipeline; a contract is not a
  network target.
- **Input:** `target` = local `.sol` path **or** contract address
- **Output dict + kb key `web3`:** findings, `highest_severity`,
  `slither_available`; for addresses, `source_meta` from Etherscan
- **Tools:** `slither_scan`, `fetch_source` (Etherscan)
- **Edge cases:**
  - Local `.sol` is the primary path; Etherscan is graceful without an API key.
  - Slither absent → `available = False`, findings empty, no crash.
  - Detectors map to Immunefi tiers (reentrancy-eth / arbitrary-send /
    suicidal / delegatecall → Critical); unknown detectors fall back to
    impact × confidence.
  - See [../web3/web3-audit.md](../web3/web3-audit.md).

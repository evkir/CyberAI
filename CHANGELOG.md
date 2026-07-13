# Changelog

All notable changes to CyberAI are documented here.

## [1.3.0] - 2026-07-13
### Week 3: Web3 Discovery Agent

Turns the Slither wrapper into a full discovery chain for smart contracts.
The hard part of an audit is finding the bug, so the agent stacks static,
symbolic, and on-chain analysis and confirms exploits out-of-band on a
mainnet fork — a finding is only *confirmed* when the fork shows real profit.

### Added
- **aderyn wrapper + cross-validation** — a second static engine (Cyfrin
  aderyn); findings both Slither and aderyn report are promoted to high
  confidence. Graceful when the binary is absent.
- **halmos symbolic runner** — invariant candidates synthesized from the
  ABI, symbolic counterexamples rendered as findings.
- **Foundry on-chain PoC** — anvil mainnet-fork harness; a generated
  exploit is replayed on the fork and only reported when state changed
  (measured `profit_wei`), removing false positives.
- **Access-control agent** — owner/role/modifier graph, missing-auth,
  unprotected-init and delegatecall detectors, privilege-escalation paths.
- **EVMBench detect adapter** — Web3 benchmark harness wired into the
  bench runner, with an honest per-vulnerability recall proxy.
- **Immunefi export** — each finding rendered as an Immunefi submission
  (VSCS v2.3 severity, funds-at-risk, PoC) via `cyberai web3 audit
  <target> --immunefi`.
- **LLM-judge validation for Web3 findings** — reuses the report judge to
  cross-check an audit narrative against raw detector evidence, flagging
  hallucinated claims. Graceful when no LLM is available.

### Docs
- `docs/benchmarks/evmbench.md` — EVMBench methodology and honest numbers.
- `docs/workflows/web3-discovery.md` — full walkthrough from `.sol` to an
  Immunefi submission.

## [1.2.0] - 2026-07-03
### Week 2: MCP / LLM Offensive Red-Team

Turns Model Context Protocol servers and LLM/RAG endpoints into scan
targets: CyberAI now attacks a target's MCP surface from the outside and
maps every finding onto the OWASP MCP Top 10 and MITRE ATLAS.

### Added
- **MCP client probe + `MCPScanAgent`** — connect to a target MCP
  endpoint (stdio / SSE / streamable-HTTP), inventory tools/prompts/
  resources, and drive the red-team analyses from a standalone agent.
- **`cyberai mcp-scan`** — offensive scan CLI with `--report` (OWASP-MCP
  / MITRE-ATLAS Markdown report), `--report-json`, and `--mst`/
  `--confirm-scope` for optional low-level fuzzing.
- **Tool-poisoning detector** — static analysis of tool metadata for
  hidden instructions, unicode tricks, base64, and hidden HTML.
- **Over-privilege audit** — capability-surface mapping and heuristics
  for tools that reach beyond their declared scope.
- **Exposure check** — remote reachability, DNS-rebinding surface, and
  dangerous-capability detection (CVE-2025-49596 class).
- **Attestation + trust-propagation** — anonymous-acceptance and
  self-asserted identity checks, cross-server shadowing/steering
  detection, and a STRIDE scorecard per target.
- **Live injection fuzzer** — payload corpus for MCP tool-responses and
  web LLM/RAG endpoints, confirmed out-of-band via phantom-grid callbacks.
- **MST bridge** — optional subprocess integration with
  mas-sentry-toolkit for protocol-level malformed-traffic fuzzing;
  degrades gracefully when absent.
- **MCP red-team report** — representation layer mapping scan stages to
  OWASP MCP Top 10 and MITRE ATLAS, plus `mcp_scan` exposed as an MCP tool
  so the server can scan other MCP servers.

### Docs
- `docs/redteam/mcp-scanning.md` — offensive vs defensive framing and a
  full `mcp-scan` walkthrough.

## [1.1.0] - 2026-06-27
### Week 1: Proof & Benchmark Harness

Reproducible benchmark harness and the first honest, public-facing numbers.
Establishes the regression polygon every later week measures against.

### Added
- **Benchmark harness** — `BenchTask`/`BenchResult`/`BenchAdapter`/`SuiteReport`
  contract with a pluggable `TaskRunner`; external suites attach as optional
  adapters, never as dependencies.
- **Local vulnerable-target suite** — self-authored SQLi/CMDi/path-traversal
  Flask apps under `cyberai/bench/apps/`, served in throwaway containers by an
  ephemeral Docker builder (graceful without Docker).
- **Honest evaluator + live probes** — binary per-class success checks plus
  `probe_sqli`/`probe_cmdi`/`probe_traversal`; a task is solved only on an
  unambiguous signal from a responding target.
- **Real engine-runner** — `cyberai bench run --engine real` runs live probes
  against the local suite; default `--engine placeholder` reports all-unsolved
  so a scorecard never overstates capability.
- **Scorecard + reproducibility** — Markdown scorecard with engine/provider/
  model/timestamp provenance, deterministic run manifest with tamper-evident
  hashing, per-run cost/token budget, and a regression gate that fails if
  solve-rate drops or the suite is swapped.
- **Per-phase model router** (flag-gated) — caches one LLM client per phase
  model sharing a single cost tracker; fast/strong role defaults with a
  `phase_models` override map.
- **Air-gapped local path** — `egress_guard` enforces a local-only endpoint
  (Ollama/localhost or a private vLLM `base_url`) and asserts no egress; honest
  `Air-Gapped Ready` badge, not an absolute zero-leak claim.
- **CTF/flag-submit adapter** and a self-contained CTF mini-suite.
- **Public docs** — `docs/benchmarks/local-suite.md` and a README Benchmarks
  section with the methodology and current numbers.

### Notes
- The Docker builder currently serves a bare base image, so a real run reports
  unsolved today; once each app ships a Dockerfile the same probes flip to
  solved with no runner change. Honest by design.

## [1.0.0] - 2026-06-20
### Production Release
A non-working skeleton is now a production-ready
AI-native multi-agent pentest platform. CLI, web dashboard and MCP server all
operational; ~120 commits across five phases. This release tags the cumulative
result of weeks 1-4 plus the polish sprint.

### Highlights by phase
- **Week 1 — Reanimation:** unified `ScanSession`, `BaseAgent` contract,
  rewritten orchestrator, all 4 agents migrated, end-to-end `--dry-run`
  pipeline with smoke coverage.
- **Week 2 — Hardening:** Pydantic result schemas, prompt-injection defense at
  phase boundaries, command-injection-safe nmap with caching, EPSS enrichment,
  NVD API key + rate limiting, datetime/pyproject modernization, real e2e tests.
- **Week 3 — Acceleration:** async pipeline (`AsyncOrchestrator`), cost tracking
  with budget caps, Anthropic prompt caching, native LLM tool calling,
  structured outputs, SQLite audit log + session replay.
- **Week 4 — Differentiation:** OOB-driven exploitation (phantom-grid v2.0),
  Nuclei exploit engine, Web3 audit track (Slither + Immunefi severity),
  MCP server, LLM-as-Judge report validation, bug-bounty scope import,
  FastAPI dashboard with SSE live progress.
- **Polish:** full documentation sprint (README, agent API reference, OOB and
  Web3 workflow guides), PyPI trusted publishing on tag.

### Added
- `release.yml` workflow: PyPI trusted publishing triggered on `v*` tags.

### Changed
- Version bumped to 1.0.0 — first stable release.

## [0.5.0] - 2026-06-18
### Differentiated Platform — Week 4
Week 4 gives CyberAI its unique edge: out-of-band-driven exploitation, a
Web3 audit track, an MCP server, report self-validation, bug-bounty scope
import, and a web dashboard.

### Added
- OOB-driven exploitation: phantom-grid v2.0 client (token-flow), payload
  library v2 (7 categories), `OOBWorkflow` + `ExploitAgentOOB` correlating
  injected payloads against live callbacks.
- Nuclei exploit engine: subprocess wrapper with JSONL parsing, searchsploit
  integration (graceful), CVE→OOB heuristic for JNDI/SSRF templates.
- Web3 track: standalone `SmartContractAgent`, Slither wrapper, Immunefi
  severity classifier (per-check table + impact×confidence fallback).
- MCP server: official `mcp` SDK, recon + intel tools exposed as MCP tools
  with JSON Schema and graceful dispatch (Claude Desktop / Cursor docs).
- LLM-as-Judge: `judge_report` cross-checks report claims against KB
  evidence, `JudgeVerdict`, feedback-driven retry, per-finding confidence.
- Bug-bounty scope import: HackerOne / Bugcrowd JSON → in/out scope with
  exclusion-aware matching (`!host` overrides allow-wildcards).
- Web dashboard: FastAPI backend reading sessions from disk, SSE live phase
  progress, single-file htmx + alpinejs UI (no build step).

### Changed
- Web backend migrated from dead Flask stubs to FastAPI; sessions are now
  read from disk (single source of truth shared with `cyberai replay`).

## [0.4.0] - 2026-06-12

### Accelerated & Observable — Week 3

Week 3 turns the working pipeline into a fast, cost-aware and auditable one.

### Added
- Async pipeline: `AsyncOrchestrator`, async DNS / subdomain enum, batched
  async CVE lookups with a sync-vs-async no-regression benchmark gate.
- Cost tracking: `CostTracker` + `TokenUsage`, per-model pricing, CLI cost
  summary, `BudgetExceeded` hard cap via `max_cost_usd`.
- Anthropic prompt caching (`cache_control`) with cache-aware pricing.
- Native LLM tool calling: Tool→OpenAI/Anthropic spec converters, `call_tools`
  returning structured `LLMResponse`, provider-aware tool-result threading.
- Structured outputs: `structured_call` (OpenAI `json_schema` / Anthropic
  forced tool), Pydantic `ReportSection`, HackerOne-compatible export.
- Observability: SQLite-backed audit log, full session export/import
  (`to_json` / `from_json`), and `cyberai replay <session_id>`.

## [0.3.0] - 2026-06-02

### Hardening — Week 2 complete

Type safety and real-world integration. Agents now produce typed
pydantic models, the pipeline defends against prompt injection at phase
boundaries, and CVE prioritization is enriched with live exploit-in-the-
wild data from EPSS.

### Added
- Pydantic schemas for Recon/Intel/Exploit results (`core/types.py`).
- Prompt-injection detector at phase boundaries (33 patterns, severity
  classification, banner sanitization with UNTRUSTED markers).
- nmap flag whitelist and target sanitization; FileCache (1h TTL) for
  successful scans.
- EPSS client (api.first.org) with per-CVE 24h cache; CVE scorer
  rebalanced (EPSS weight 0.10 → 0.25, non-linear boost above 0.5).
- NVD API key support: header-based auth, 50 req/30s when present,
  exponential backoff on 429/503.
- Unified rate limiter with per-API presets (NVD, EPSS, OpenAI,
  Anthropic, phantom-grid).
- Real e2e tests against scanme.nmap.org and the NVD API, gated by
  `@pytest.mark.slow` and run nightly only.
- `pyproject.toml` (PEP 621, hatchling backend) replaces `setup.py`.
- Upper-bound pins on all 13 runtime dependencies.
- `ruff format --check` and `mypy --strict` (initial scope:
  `cyberai/core/types.py`) added to CI.

### Changed
- Minimum Python bumped 3.10 → 3.11.
- `datetime.utcnow()` replaced with timezone-aware `datetime.now(tz)`
  throughout the codebase.

### Fixed
- Dead `nmap_wrapper` removed; flag injection vector closed.

## [0.2.0] - 2026-05-25

### Reanimation — Week 1 complete

Skeleton-to-working pipeline. CyberAI runs end-to-end: `cyberai scan
<target> --dry-run` walks all 4 phases and completes cleanly.

### Added
- Unified `ScanSession` state object shared across all components.
- `BaseAgent` contract — consistent agent lifecycle and API.
- End-to-end smoke tests for the `scan` CLI covering all 4 phases.

### Changed
- Orchestrator rewritten against the new agent contract.
- All 4 agents (recon, intel, exploit, report) migrated to `BaseAgent`.
- `--dry-run` walks the full pipeline with no network calls or API key.

### Fixed
- All 8 known issues resolved (KI-1 through KI-8).

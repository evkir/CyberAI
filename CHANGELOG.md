# Changelog

All notable changes to CyberAI are documented here.

## [1.0.0] - 2026-06-20
### Production Release — STANDOFF complete
The 30-day STANDOFF is done: a non-working skeleton is now a production-ready
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

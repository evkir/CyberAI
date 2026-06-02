# Changelog

All notable changes to CyberAI are documented here.

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

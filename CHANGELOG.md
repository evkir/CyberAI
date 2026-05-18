# Changelog

## [1.0.0] — 2026-05-17

### Added

**Core**
- AsyncPipeline — parallel recon, sequential intel/exploit/report
- AsyncBaseAgent — run_tool() + run_tools_parallel() via asyncio
- PipelineRecovery — HARD STOP recon, SOFT FAIL intel/exploit/report
- SessionSigning — HMAC-SHA256 tamper-evident audit trail
- AgentTimeoutManager — per-agent configurable timeouts
- Safety decorators — @sanitize_input, @require_scope, @enforce_trust_boundary

**Agents**
- AsyncReconAgent — parallel nmap + DNS + TLS via asyncio.gather()
- AsyncIntelAgent — CVE enrichment via NVD API 2.0
- AsyncExploitAgent — SSRF + blind XXE + attack chain builder
- ReportAgent — Markdown, HTML, JSON output

**Integrations**
- phantom-grid poller — OOB DNS/HTTP callback confirmation
- reality-probe client — TLS score, cert expiry, weak cipher detection
- TLS CVE mapper — issue → CVE context for IntelAgent

**Safety**
- InputSanitizer — prompt injection detection + length limiting
- AgentTrustBoundary — per-agent KB write permissions
- ScopeValidator — CIDR + domain scope enforcement

**CLI**
- cyberai scan — --scope, --dry-run, --output, --verbose
- Rich progress bars and spinners
- Dry-run plan table

**Web API**
- Flask REST API — POST /api/session, GET /api/session/<id>
- Report serving — GET /api/report/<filename>
- HTML dashboard — dark theme, auto-refresh 5s

**Hardening**
- Exponential backoff with jitter for NVD API rate limiting
- Graceful nmap timeout — partial results, pipeline continues
- Type aliases centralised in cyberai/core/types.py

**Tests**
- 160+ tests across unit and integration suites
- Python 3.11 + 3.12 matrix CI
- ruff lint on every push

### Stats
- 128 commits
- 30 days
- CI green throughout

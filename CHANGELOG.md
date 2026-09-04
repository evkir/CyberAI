# Changelog

All notable changes to CyberAI are documented here.

## [1.6.0] - 2026-09-04

### Changed

- **Badges are written by scripts, not by hand.** The test count and the
  typing ratio are produced by `scripts/tests_badge.py` and
  `scripts/mypy_badge.py` from a collection and a checker run. A number typed
  into a document is a number that drifts; both had.

- **The confusable table is checked against Unicode.** Forty-two codepoints
  claim to imitate Latin letters, and every gate on them followed the table's
  own values -- mutating one entry from "a" to "e" left the whole repository
  green. UTS #39 answers the question independently, and all forty-two agree
  with it once both sides are folded through the same data. Four entries stay
  ambiguous because Unicode itself refuses to separate capital I from small l
  and one, or capital O from zero; the test names them rather than hiding
  them.

- **The coverage upload authenticates.** It ran unauthenticated and was
  configured not to fail, so a report that never arrived produced no status,
  no comment and no red -- a check that decided nothing. It now uses OIDC from
  the job's own identity and fails the job when the upload does.

- **Typing scope: seven modules to ninety-one.** `mypy --strict` was reading
  seven modules while ninety-one passed it untouched; the scope was a leftover
  from switching the checker on, not a decision. It now lists the measured set,
  the badge states the ratio rather than a path list, and
  `docs/architecture/typing-scope.md` names the 79 modules left out and the 300
  errors in them. The checker itself is bounded, so the set stays reproducible.

- **Development status: Alpha to Beta.** The classifier said Alpha while the
  package carried a wired trust boundary, decontaminated benchmark proofs, an
  architecture-tested README and 2200-odd tests. Beta claims the interfaces
  are stable enough to build against and that the failure modes are known and
  written down -- not that the tool is finished.

- **Licence: MIT to Apache-2.0.** Releases up to and including v1.5.0 were
  published under the MIT License and remain available under those terms
  permanently, on both GitHub and PyPI; the change is not retroactive and
  withdraws nothing already granted. From v1.6.0 onward the project is
  distributed under the Apache License, Version 2.0. Apache adds an explicit
  patent grant and a termination clause on patent litigation, which matter
  for a repository that carries original protocol research, and it clears the
  policy blocks that keep copyleft tooling out of enterprise security teams.
  The `LICENSE` file holds the canonical Apache text unmodified; the copyright
  line moved to `NOTICE`.

### Fixed

- **Benchmark contamination.** The exploitation engine held a literal from a
  target this project wrote, and the SQL-injection proof accepted the success
  body our own bench login prints — so part of a published 4/4 measured
  recognition rather than exploitation, and shipped to PyPI inside the engine.
  Both proofs are now structural: a traversal reads a shape the target should
  not serve, an auth bypass is proven by the 401 to 200 transition. An
  architecture test runs every shipped proof against every string the bench
  apps are built from, which is what caught the case a grep could not see.
  Both scorecards were regenerated against live targets: still 4/4, at 21
  requests instead of 28. Full account in
  `docs/benchmarks/contamination-2026-08.md`.
- **Scorecard provenance.** `provider` and `model` defaulted to the string
  `unspecified` and the CLI passed neither, so every published card named a
  value the run had chosen. The rows are omitted when nothing was measured.
  The version row was keyed `engine`, which the CLI also writes to name the
  engine that ran, giving one card two rows under one key; it is now
  `engine version`, and a second writer reaching an occupied key raises.
- **Cause of a zero call count.** A run whose code path constructs no LLM
  client was reported as `no_api_key_for_openai`, pointing the reader at a
  credential that would change nothing. The path now answers for itself, above
  the credential causes.

### Added

- **A prompt-injection detector that publishes what it misses.** Two layers
  and a committed corpus of 96 samples -- 51 injections, 45 benign -- with the
  measurement reproduced by a command rather than typed: `cyberai detector
  eval --corpus tests/corpus`. The pattern layer, 33 expressions across 10
  weighted categories, scores 62.7% recall at 100.0% precision with a 0.0%
  false-positive rate, and three subclasses -- multilingual, paraphrase,
  social -- score nothing at all. Naming them is the point: an overall recall
  figure suggests the misses are spread thinly across techniques, and they are
  not. Adding a local model as a second layer takes recall to 98.0% with the
  false-positive rate unchanged.

- **Recorded verdicts, so the second layer's figure survives without a GPU.**
  `--l2-record` keeps what the model answered and `--l2-replay` scores from
  it, refusing a recording taken under a different model, prompt or seed
  rather than publishing a stale number quietly. Recordings merge, so adding
  one sample to the corpus costs one question instead of the whole corpus.

- **A gate on publication.** main carried nine required checks and the tag
  that publishes to PyPI carried none: the release workflow fired on `v*`,
  built and uploaded without asking whether that commit had ever gone green.
  It now refuses unless every job the CI workflow defines finished
  successfully on the commit being tagged, with the job list read out of the
  workflow rather than written down beside it.

- **`cyberai status` answers for the toolchain**, alongside provider, output,
  trust boundary, sampling, air-gap and credentials, and the README line
  describing the command is checked against the fields the panel prints.

- **Contributor License Agreement** (`CLA.md`), adapted from the Apache ICLA
  v2.0 with a relicensing clause, so future commercial components can ship
  without collecting consent from each contributor one at a time. Signatures
  are collected in the pull request description; a template was added under
  `.github/`. No CLA bot: the widely deployed action was archived upstream in
  March 2026 and the surviving fork is explicitly not a community successor.
- **`docs/licensing.md`** — why CyberAI is Apache while mas-sentry-toolkit is
  AGPL, what the CLA grants, and the planned transfer of rights to MASec Lab
  LLC once it is registered.

## [1.5.0] - 2026-08-12

### The HTTP surface, and the vectors a response cannot prove

The platform walked networks and read CVEs; a bespoke web application has
neither. This work gives it the other half: discovering the HTTP surface a
target actually exposes, attacking it under real credentials, and — for the
class where every reply is identical — proving execution from outside the
target instead of guessing from the response.

### Added
- **Out-of-band confirmation on the product path** — parameters that look
  inert are re-tested through a collector we control. A blind vector and a
  parameter nothing reads produce the same response; only an observed
  callback separates them. The verdict reaches Markdown, HTML and JSON, and
  a run records whether a channel existed at all, so zero confirmations no
  longer read the same way whether the target was clean or the collector was
  dead. Behind `--oob`; a run without it is unchanged.
- **HTTP surface discovery and exploitation** — recon reads API specs and JS
  bundles for the routes an application assembles rather than declares, and
  probes them for parameters no documentation names. The exploit phase walks
  what it finds, independent of CVE data.
- **Credentials and destructive endpoints** — `--auth` carries headers into
  every request of the walk, and `--allow-destructive` opens DELETE/PUT/PATCH
  endpoints that are otherwise recorded and skipped.
- **Object-level authorization** — the walk asks whether an identifier
  addresses a real object and whether anyone may address it, and names both
  the enumerable identifiers and the missing per-object check.
- **A blind SSRF target in the local suite** — a fourth class whose success
  signal is a callback rather than a response, with the evaluator criterion
  to score it. The suite runs 4/4.
- **The model on web targets** — an executive section written over the
  HTTP-surface report, plus red-team results for the LLM channels recon
  found, rendered in Markdown, HTML and JSON.
- **LLM usage in the session** — token counts, cost and the reason a run made
  no call at all.

### Fixed
- **Endpoints that never existed** — a target answering its application shell
  for every absent path made every guessed route look real. Those are
  fingerprinted and dropped, and the ones that remain are named.
- **Findings the report did not carry** — the web phase, the AI analysis and
  the executive section each reached the JSON export or the renderer and
  stopped there. All three now reach the documents a reader opens.
- **The out-of-band collector's health check** — a 200 from anything on the
  port counted as the grid answering. The signature is verified, so an
  unrelated service on 9090 no longer produces false confirmations.
- **Marker echo scored as a finding** — a channel that merely reflected the
  payload back was counted as having executed it.

### Docs

- **CVE-Bench, measured rather than promised** — a three-task run scoring
  0/3, with the cause: no target published a spec the recon path can read,
  so the walk attacked whatever the landing page linked to. The numbers,
  the shared cause and the criterion that is within reach are written down
  in `docs/benchmarks/cve-bench.md` instead of left for a launch post.

### Changed

- **The bench attacker receives the task** — the CVE-Bench adapter parses
  what a task is and what counts as solving it; the runner passed only a
  URL. The task now reaches the attacker. Nothing downstream consults it
  yet, and that is stated where it is true rather than implied away.

## [1.4.0] - 2026-07-24

### Autonomy and unified reporting

The planner stops being an isolated component and starts steering the
pipeline, and the report finally shows all three attack surfaces the
platform covers rather than only the network one.

### Added
- **Planner phase in the pipeline** — `ScanPhase.PLAN` runs between intel
  and exploit behind `enable_planner` / `CYBERAI_ENABLE_PLANNER`, building
  an ordered subtask plan from the in-memory knowledge-base graph. The
  exploit agent consumes that plan and follows its CVE ordering, so
  graph-derived prioritisation drives the attack path instead of being
  recomputed. Off by default; a run without the flag is unchanged.
- **`--planner/--no-planner`** — tri-state CLI override matching the other
  feature flags, plus a post-scan summary of the plan by subtask type.
- **Findings grouped by attack surface** — reports classify every finding
  as Network, MCP or Web3 from its originating agent. Markdown renders one
  section per surface with a domain breakdown, and the JSON export carries
  the agent and domain on each finding plus a domain index. Grouping only
  activates when a scan actually spans more than one surface, so
  single-surface reports are unchanged.

## [1.3.1] - 2026-07-23
### Visibility sprint

A maintenance release that makes the project visible and verifiable from
the outside. No new agent capability; every change makes an existing one
provable.

### Fixed
- **Scope guard on the exploit agent** — `authorized_scope` was enforced by
  the orchestrator only, so calling the agent directly bypassed it. The
  base agent now gates OOB payload delivery and the nuclei runner itself.
- **Local benchmark suite actually runs** — the bundled vulnerable targets
  had no entrypoint and the container ran an idle process, so the suite
  reported 0/3 regardless of engine behaviour. Targets rewritten on the
  stdlib HTTP server, the builder mounts them read-only and waits for a
  real HTTP readiness signal. The suite now reports pass@1 3/3.

### Added
- **Live recon CI** — nightly rate-limited recon-only run against
  scanme.nmap.org with the report uploaded as an artifact and the result
  published as a README badge.
- **`--recon-only` and `--max-rps`** — recon-only pipelines and an
  nmap rate cap for legally-invited external targets.
- **Sample scorecard** — `examples/local-bench/scorecard.md`, reproducible
  with a single command.
- **Recorded demo** — an asciinema-recorded run of the local suite rendered
  as a GIF in the README, with `docs/demo/record.sh` to reproduce it.
- **Launch post draft** — `blog/launch-post-draft.md`, unpublished.

### Docs
- README: architecture diagram, honest roadmap, differentiator paragraph,
  and the local suite's real per-class numbers with an explicit statement
  that the suite is self-authored and not comparable to external
  benchmarks. No external-benchmark score is claimed.

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

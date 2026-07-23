# CyberAI is alive: honest benchmarks, offensive MCP/LLM red-team, and on-chain Web3 proof

> **Status: draft.** Not published yet. Numbers below are re-verified before release.

Most offensive-security AI projects announce capabilities. This post announces
numbers, source paths, and a command you can run yourself. Where a number does
not exist yet, it says so.

## What CyberAI is

CyberAI is a multi-agent offensive-security platform: eight agents (recon,
intel, exploit, report, planner, mcp-scan, redteam, web3) run a typed, audited
pipeline over a shared knowledge base. Around 18,800 lines of Python, 1,038
tests green, mypy strict clean on the checked surface, MIT.

It is not a wrapper that pipes nmap output into a chat model. Three things make
it a different category of tool.

## 1. Offensive MCP and LLM red-team, not a config scanner

The Model Context Protocol is now an attack surface, and defensive scanners for
it already exist — mcp-scan, Cisco's scanner, and several others. They all do
the same thing: statically inspect *your own installed* servers and flag risky
configuration.

CyberAI takes the opposite direction. During a pentest it discovers an MCP
server or an LLM/RAG endpoint belonging to the *target*, and attacks it:

| module | what it does |
| --- | --- |
| `mcp_scan/poisoning.py` | hidden instructions in tool descriptions and schemas |
| `mcp_scan/overprivilege.py` | declared capability vs. what a tool actually reaches |
| `mcp_scan/attestation.py` | missing message/origin authentication |
| `mcp_scan/exposure.py` | locally-bound servers reachable from outside, DNS rebinding |
| `mcp_scan/trust.py` | implicit trust propagation between chained servers |
| `redteam/fuzzer.py` | live injection fuzzing of any LLM channel |

A finding from the fuzzer is only promoted to confirmed when an out-of-band
callback lands. Injected canaries are served through
[phantom-grid](https://github.com/evkir/phantom-grid); no callback, no claim.

```bash
cyberai mcp-scan http://target/mcp --report
```

## 2. Web3 discovery with on-chain proof

Public benchmarks converge on the same result: for smart contracts the
bottleneck is *discovery*, not repair or transaction construction. So the Web3
agent stacks engines rather than betting on one.

- **Static, doubled** — Slither and Cyfrin aderyn run independently; agreement
  between them promotes a finding to high confidence.
- **Symbolic** — halmos synthesizes invariant candidates from the ABI and
  produces counterexamples that pure static analysis misses.
- **On-chain** — the interesting part. A generated Foundry exploit is replayed
  against an anvil mainnet fork. The finding is confirmed only if the fork
  shows a real state change with measured `profit_wei`. This is the same
  discipline as the OOB rule on the network side: evidence, not plausibility.
- **Access control** — an owner/role/modifier graph with missing-auth,
  unprotected-init and delegatecall detectors, since access control remains the
  single largest category of on-chain loss.

Output is an Immunefi-shaped submission with severity, funds-at-risk and PoC.

```bash
cyberai web3 audit ./contracts --immunefi
```

## 3. Honest benchmarks, including where they are weak

The field is loud. A reproducible scorecard is cheaper to trust than a press
release, so every number ships with the method that produced it.

**Local suite — pass@1 3/3 (100%).** Three deliberately vulnerable targets
(SQL injection, command injection, path traversal) built and served from this
repository, run in Docker by the real engine.

```bash
cyberai bench run --suite local --engine real --scorecard reports/scorecard.md
```

Read that number correctly: **this suite is authored by the same project it
measures.** It proves the engine end-to-end works against live targets and it
guards against regression. It is *not* evidence of competitive standing, and it
should not be compared to CVE-Bench or CyBench results.

**EVMBench detect — adapter shipped, numbers pending.** The grader is a
deterministic class-overlap proxy rather than the upstream LLM judge: fully
reproducible offline, never drifts with a judge model, but a recall *lower
bound* and coarser than upstream. That tradeoff is documented in
`docs/benchmarks/evmbench.md` rather than hidden in a footnote.

**External benchmarks — not run yet.** No CVE-Bench or CyBench figure is
claimed anywhere in this project. When they exist they will be published
whatever they say; published agents currently score in the low teens on
CVE-Bench, and a low honest number is more useful than a high unverifiable one.

Every run emits a manifest with engine version, provider, model and timestamp,
and a regression gate fails the build when solve-rate drops between releases.

**Live pulse.** A nightly workflow runs recon-only, rate-limited, against
scanme.nmap.org — the host whose owner invites exactly that — and publishes the
result as a README badge with the run artifact attached. Public proof the
pipeline still runs today, not on release day.

## Air-gapped by construction

Red-team and NDA work often forbids sending client infrastructure to a
third-party API. CyberAI runs the full pipeline on local models through Ollama
or vLLM, and `core/egress_guard.py` asserts the absence of outbound calls in
local mode; `core/model_router.py` selects a model per phase, so a cheap local
model handles recon while a stronger one handles exploitation when policy
allows it.

The badge says **Air-Gapped Ready**, not "zero data leakage" — an absolute
claim of that kind needs an independent egress audit, which has not happened.

## What this is not

- Not autonomous. It is an operator's instrument, and the operator is
  accountable for scope.
- Not a bug-bounty cannon. Legal scope is enforced in code, and external
  targets in CI are limited to recon against an invited host.
- Not finished. The planner/critic loop, exploit memory and dashboard work are
  in progress and honestly marked as such in the roadmap.

## Try it

```bash
pip install cyberai
cyberai bench run --suite local --engine real
```

Source: <https://github.com/evkir/CyberAI> · MIT · issues and PRs welcome.

CyberAI is developed alongside mas-sentry-toolkit under MASec Lab.

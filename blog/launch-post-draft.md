# CyberAI is alive: honest benchmarks, offensive MCP/LLM red-team, and on-chain Web3 proof

> **Status: draft.** Not published yet. Numbers below are re-verified before release.

Most offensive-security AI projects announce capabilities. This post announces
numbers, source paths, and a command you can run yourself. Where a number does
not exist yet, it says so.

## What CyberAI is

CyberAI is a multi-agent offensive-security platform: eight agents (recon,
intel, exploit, report, planner, mcp-scan, redteam, web3) run a typed, audited
pipeline over a shared knowledge base. 24,169 lines of Python under
`cyberai/` plus 24,088 lines of tests, 2001 of which pass at `v1.5.0` in
the pre-commit gate (15 slow ones deselected there and run separately),
`mypy --strict` clean on the typed core (`cyberai/core/types.py`), Apache-2.0.

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
| `cyberai/agents/mcp_scan/poisoning.py` | hidden instructions in tool descriptions and schemas |
| `cyberai/agents/mcp_scan/overprivilege.py` | declared capability vs. what a tool actually reaches |
| `cyberai/agents/mcp_scan/attestation.py` | missing message/origin authentication |
| `cyberai/agents/mcp_scan/exposure.py` | locally-bound servers reachable from outside, DNS rebinding |
| `cyberai/agents/mcp_scan/trust.py` | implicit trust propagation between chained servers |
| `cyberai/agents/redteam/fuzzer.py` | live injection fuzzing of any LLM channel |

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

**Local suite — pass@1 4/4 (100%), twice over.** Four deliberately vulnerable
targets (SQL injection, command injection, path traversal, blind SSRF) built
and served from this repository, run in Docker. `--engine real` fires fixed
per-class probes and answers whether the targets and the harness are sound.
`--engine agent` answers the question that matters: recon discovers the
surface, exploit attacks it, and nothing is known about the target beyond its
URL. Both score 4/4, and the two verdicts are compared task by task — a
disagreement is recorded as a finding rather than smoothed over.

```bash
cyberai bench run --suite local --engine real --scorecard reports/scorecard.md
cyberai bench run --suite local --engine agent
```

The blind-SSRF target answers identically whichever way it goes, so the only
proof it can produce is an out-of-band callback carrying the run nonce. That
path stays off in the global defaults, because it needs a reachable
collector; the bench profile turns it on, because a blind target cannot be
scored without it. It used to be the operator's job through an environment
variable, and the run scored 3/4 without it. Measured again on 2026-08-15
with nothing set by hand: 4/4, agent and probe agreeing on all four. Task
list and method: `docs/benchmarks/local-suite.md`.

Read that number correctly: **this suite is authored by the same project it
measures.** It proves the engine end-to-end works against live targets and it
guards against regression. It is *not* evidence of competitive standing: a
self-authored 100% ranks this project against nobody, and the number must not be
read as a score on the same scale as CVE-Bench or CyBench. What it can be set
beside is the external result below — not to compare magnitudes, but because who
wrote the suite is exactly what separates the two figures.

**EVMBench detect — adapter shipped, numbers pending.** The grader is a
deterministic class-overlap proxy rather than the upstream LLM judge: fully
reproducible offline, never drifts with a judge model, but a recall *lower
bound* and coarser than upstream. That tradeoff is documented in
`docs/benchmarks/evmbench.md` rather than hidden in a footnote.

**CVE-Bench — 0/3, and the reason is one, not three.** Three tasks
(CVE-2024-4442, CVE-2024-5084, CVE-2024-36412) against an upstream checkout,
graded by the upstream grader running inside the target container. Not solved,
published anyway.

The three failures share a cause. All three runs report no machine-readable API
surface: `spec_url` null, zero routes, and the only endpoint source was links
scraped out of the HTML. So the walk attacked whatever the landing page linked
to — on the WordPress target, eight static assets under `/wp-includes/` carrying
a cache-busting parameter. Eight inert parameters out of eight is the correct
answer to the question that was actually asked.

The question worth asking was elsewhere, and the targets volunteer it: both
announce their API in a `Link` response header — `/wp-json/`, which answers 200,
and `/api/docs.jsonld`, which answers 403. Nothing in the recon path parses that
header, and API discovery knows OpenAPI and Swagger paths only, which its module
docstring states plainly. That is a capability not claimed, not a defect. 218
requests, 27 parameters, zero confirmed — and the score stays at zero until the
recon path can read the surface these targets publish.

**What other agents score.** The CVE-Bench paper (arXiv:2503.17332, ICML
2025) measured three agent frameworks over all 40 tasks with
gpt-4o-2024-11-20 and five attempts per task: up to 10% zero-day, up to
12.5% one-day. Two of its numbers are zeros, and those say more. ZAP 2.16.1
with every option enabled solved nothing, and the multi-agent framework
driven by Llama 3.1 solved nothing either -- the authors read
that as the distance between that model and GPT-4o. CyberAI runs on a local
model.

None of this is a comparison, and the doc says so at more length: those runs
scored the pre-v2.1.0 criteria, where creating a file counts as success,
while this checkout scores RCE. Different criterion, 40 tasks against 3,
five attempts against one. Context for what the benchmark is like, not a
scale our zero sits on.

Put beside the 4/4 above, the pair is the point: the suite we wrote passes, the
suite we did not write does not, and both numbers ship with the method that
produced them. A self-authored 100% on its own would be worth very little. Full
measurement: `docs/benchmarks/cve-bench.md`.

Every run emits a manifest with engine version, provider, model and timestamp,
and a regression gate fails the build when solve-rate drops between releases.

**Live pulse.** A nightly workflow runs recon-only, rate-limited, against
scanme.nmap.org — the host whose owner invites exactly that — and publishes the
result as a README badge with the run artifact attached. Public proof the
pipeline still runs today, not on release day.

## Air-gapped by construction

Red-team and NDA work often forbids sending client infrastructure to a
third-party API. CyberAI runs the full pipeline on local models through Ollama
or vLLM, and `cyberai/core/egress_guard.py` asserts the absence of outbound
calls in local mode; `cyberai/core/model_router.py` selects a model per phase, so a cheap local
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

Source: <https://github.com/evkir/CyberAI> · Apache-2.0 · issues and PRs welcome.

CyberAI is developed alongside mas-sentry-toolkit under MASec Lab.

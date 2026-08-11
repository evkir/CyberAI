# Competitive landscape — AI-native offensive security, 2026

**Data collected:** 2026-08-11. Every claim below carries its source.
Nothing here is written from model memory: figures without a named
primary source were dropped rather than rounded into a narrative.

**Why this file has a date in the title.** An undated positioning
document rots silently. Three earlier CyberAI plans referenced a
competitive analysis that did not exist, which is how a badge becomes a
lie. If today is more than six months past the collection date above,
treat this as history and re-collect.

## 1. The category has split in three

Buyer-facing roundups collapse very different products into one list.
The three groups solve different problems and are not substitutes:

| Group | What it sells | Examples |
|---|---|---|
| Enterprise validation platforms | Continuous attack-path validation across internal, external, cloud, Kubernetes | Horizon3.ai (NodeZero), Pentera |
| Autonomous web pentest engines | On-demand exploitation of web apps, findings gated on confirmed exploitability | XBOW, Corgea, MindFort |
| Open-source agents and research | Reproducible agents, published benchmark scores, papers | PentestGPT, VulnBot, xOffense, CAI, and the awesome-* indexes |

Pricing anchors, for scale rather than comparison: PTaaS subscriptions
are quoted at roughly $30K-$150K+ per year (Equixly, 2026-06-01), while
one packaged autonomous vendor publishes per-pentest plans starting at
$4,000 (Corgea, 2026-07-08). Most autonomous vendors require a sales
call.

CyberAI sits in group three and should stop trying to be read as group
one or two. The credibility currency in group three is a reproducible
number, not a feature list.

## 2. Benchmarks — the honest numbers

These are the published results a reader can check. They are also the
bar CyberAI's own scorecard has to clear before any claim is made.

| Benchmark | Shape | Published result |
|---|---|---|
| CVE-Bench (arXiv 2503.17332, ICML 2025 spotlight) | 40 critical-severity real-world web CVEs | Agents exploit up to 13% zero-day, up to 25% one-day |
| Cybench (arXiv 2408.08926, ICLR 2025 oral) | 40 professional CTF tasks from 4 competitions | Used as the standard CTF-capability reference |
| ARTEMIS (arXiv 2512.09882, Stanford / CMU / Gray Swan) | Live university network vs 10 human professionals | Agent placed second, with a higher false-positive rate than every human |

### Reading these numbers

The headline results and the measured results disagree, and the
disagreement is the most useful fact in this document. An autonomous
agent reached the top of HackerOne's US leaderboard in June 2025, and an
agent placed second against professionals in December 2025 — yet
autonomous exploitation of real web CVEs sits at 13-25%. Volume-weighted
leaderboards and real-CVE exploitation measure different things.

**Action item for CyberAI, not a talking point.** CVE-Bench v2.1.0
(released 2026-01-12) contains a breaking change: arbitrary file upload
was removed as an evaluation criterion and replaced with remote code
execution. Any score produced by our adapter against an older revision
is not comparable to a v2.1.0 score. Version has to be recorded next to
every number we publish.

## 3. Niche 1 — MCP and LLM red-team

The threat is documented and the defensive tooling is young.

OWASP now carries an MCP Tool Poisoning entry describing the root cause
as a trust gap between connect-time and runtime: tool descriptions are
reviewed once when the agent connects, while tool responses reach the
model's context with no equivalent check.

Existing tooling is mostly static: mcp-scan (Invariant Labs) analyses
tool descriptions for known injection patterns and cross-server
shadowing; promptfoo ships an MCP red-team configuration and a
deliberately rogue server; ghostprobe scans advertised capabilities. CSA
published a research note on tool poisoning on 2026-07-02.

Where the gap is: static description analysis does not cover the runtime
response channel that OWASP names as the root cause. That is the
opening, and it is narrow — it will not stay open long.

## 4. Niche 2 — Web3 discovery

This niche is crowded and the incumbents publish accuracy figures.

GPTScan and its commercial form MetaScan report over 90% precision on
token contracts, analysing 1,000 lines of Solidity in about 14 seconds.
iAudit, a two-stage multi-agent framework, reports 91.21% F1 on real
smart-contract vulnerabilities. Immunefi states it protects over $190B
in user funds and has paid over $100M to researchers.

Directly adjacent to CyberAI's planned shape: BountyForge is an
open-source Claude Code skill running parallel agents over EVM, Move,
Solana and TRON with submission-ready Immunefi and HackerOne reports.
Anyone evaluating CyberAI's Web3 path will find it.

Implication: detection accuracy is not a differentiator here. A
confirmed on-chain proof-of-concept is.

## 5. Niche 3 — honest benchmarks as the product

No vendor in groups one or two publishes a failure rate. The open
indexes note the problem directly: star counts measure visibility, not
capability, and vendors self-report scores in their own READMEs.

This is the cheapest defensible position available to a solo project,
and the only one that does not require outspending anyone: publish the
zeros, pin the benchmark version, record the environment, and make every
run reproducible. It is also the one that dies instantly the first time
a number is inflated.

## Sources

All URLs retrieved 2026-08-11.

- CVE-Bench repository and release notes — https://github.com/uiuc-kang-lab/cve-bench
- CVE-Bench paper (arXiv 2503.17332) — https://arxiv.org/pdf/2503.17332
- Benchmark scoreboard with primary-source citations — https://www.stingrai.io/blog/ai-pentest-benchmark-results-2026
- AI pentesting agents timeline and paper index — https://appsecsanta.com/research/ai-pentesting-agents-2026
- Open-source AI pentest index — https://github.com/insidetrust/awesome-ai-pentest
- Offensive AI agentic landscape index — https://github.com/Yeti-791/Awesome-Offensive-AI-Agentic-Landscape
- OWASP MCP Tool Poisoning — https://owasp.org/www-community/attacks/MCP_Tool_Poisoning
- CSA research note on MCP tool poisoning — https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/
- promptfoo MCP security testing guide — https://www.promptfoo.dev/docs/red-team/mcp-security-testing/
- Web3 x AI agents survey (arXiv 2508.02773) — https://arxiv.org/pdf/2508.02773
- BountyForge — https://github.com/Gabson0x/bountyforge
- Immunefi bug bounty program overview — https://immunefi.com/bug-bounty-program/
- Continuous pentest vendor comparison — https://equixly.com/blog/2026/06/01/10-best-continuous-penetration-testing-vendors-of-2026/
- Packaged AI pentest pricing — https://corgea.com/learn/best-ai-pentesting-tools

# Web3 Discovery Workflow — from `.sol` to Immunefi submission

CyberAI's Web3 agent is **discovery-first**: the hard part of a smart-contract
audit is finding the bug, not writing the exploit. The agent chains a static,
symbolic, and on-chain stack so that every reported issue is backed by a real
artifact — ideally a confirmed on-chain proof, not a linter guess.

## Tool stack

| Stage | Tool | What it contributes |
|-------|------|---------------------|
| Static | Slither | Fast detector pass (reentrancy, delegatecall, low-level calls) |
| Static | aderyn | Second static engine; findings confirmed by both = high confidence |
| Access control | built-in | Owner/role/modifier graph, missing-auth & privilege-escalation paths |
| Symbolic | halmos | Symbolic execution over Foundry; finds what static analysis misses |
| On-chain PoC | Foundry (anvil + forge) | Mainnet-fork exploit; a measured balance change is the ground truth |

Slither and aderyn cross-validate; a finding both engines report is promoted to
high confidence. halmos synthesizes invariant candidates and returns symbolic
counterexamples. Foundry replays a generated exploit on a mainnet fork — a
finding is only marked *confirmed* when the fork shows real profit.

## Prerequisites

Install the toolchain (each stage degrades gracefully if a binary is absent):

```bash
# Slither
pipx install slither-analyzer
# aderyn (Cyfrin)
cargo install aderyn
# Foundry (anvil + forge) and halmos
curl -L https://foundry.paradigm.xyz | bash && foundryup
pipx install halmos
```

## Step 1 — audit a local contract

```bash
cyberai web3 audit contracts/Vault.sol
```

This runs the full discovery chain and prints each finding with its check name
and severity. Findings are bucketed in the result by source: `findings`
(Slither), `aderyn_findings`, `access_findings`, `halmos_findings`, and
`poc_findings` (confirmed Foundry PoCs). A confirmed PoC is the strongest
evidence and is always reported first.

## Step 2 — severity model

Severity follows **VSCS v2.3** and the Immunefi tiering: `Critical`, `High`,
`Medium`, `Low`, `Insight`. Severity is calibrated per check, never inflated —
an ownership/upgrade takeover or a confirmed on-chain exploit maps to Critical;
a symbolic-only counterexample maps to High; informational detectors scale down.

## Step 3 — Immunefi submission

```bash
cyberai web3 audit contracts/Vault.sol --immunefi
```

Each finding is rendered as an Immunefi-ready Markdown submission: title,
severity, impact (with a funds-at-risk statement), proof of concept, and a
recommendation section. A confirmed Foundry PoC carries a concrete ETH figure
derived from the fork's measured profit; everything else uses a qualitative
bound from the severity tier — never a fabricated number.

## Step 4 — validate before you submit

Before pasting a draft into the Immunefi dashboard, cross-check it against the
raw detector evidence with the LLM judge. It flags any claim — a CVE, a vuln
class, an impact — that no tool in the chain actually backs:

```python
from cyberai.agents.web3.judge import judge_web3_findings

verdict = judge_web3_findings(submission_markdown, agent_result, llm)
if not verdict.supported:
    print("Unsupported claims:", verdict.unsupported_claims)
```

The judge is graceful by contract: if the LLM is unavailable it returns a
pass-through verdict and never blocks the audit.

## Honest note

Discovery rate on public Web3 benchmarks is reported transparently in
`docs/benchmarks/evmbench.md`. The value of the chain is not a headline number
but the on-chain proof: a finding CyberAI marks *confirmed* changed state on a
fork, so it is not a false positive.

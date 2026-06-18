# Web3 Audit Workflow — SmartContractAgent → Slither → Immunefi

## Overview

The `SmartContractAgent` runs static analysis on a Solidity contract and maps
each finding to an [Immunefi](https://immunefi.com/) severity tier — so you can
triage before submitting to a bounty program. It is **standalone**: a contract
is not a network target, so this agent runs outside the recon→intel→exploit
pipeline.

## Components                                                                              SmartContractAgent.run(target)

+-- local .sol  --> SlitherTool.analyze() --> parse_slither_json()

|                                                |

|                                                v

|                                   immunefi_severity.classify_all()

|                                   immunefi_severity.highest_tier()

+-- address     --> EtherscanClient.fetch_source()   (graceful w/o API key)                - `cyberai/agents/web3/agent.py` — `SmartContractAgent`
- `cyberai/agents/web3/slither_tool.py` — `SlitherTool`, `parse_slither_json`,
  `SlitherFinding`
- `cyberai/agents/web3/immunefi_severity.py` — `classify`, `classify_all`,
  `highest_tier`
- `cyberai/agents/web3/etherscan.py` — `EtherscanClient`

## Input modes

| `target` | Mode | Path |
|----------|------|------|
| local `*.sol` file | `local` | Slither analysis (primary) |
| contract address | `address` | Etherscan source fetch (needs API key) |

Local `.sol` is the primary, fully-offline path. Address mode is graceful
without `ETHERSCAN_API_KEY` (returns source metadata only).

## Severity mapping

Slither detectors are mapped to Immunefi tiers by a per-check table; unknown
detectors fall back to `impact × confidence`:

| Slither detector | Immunefi tier |
|------------------|---------------|
| `reentrancy-eth` | Critical |
| `arbitrary-send` | Critical |
| `suicidal` | Critical |
| `controlled-delegatecall` | Critical |
| (unknown) | impact × confidence fallback |

`highest_tier(findings)` returns the worst tier across all findings — your
headline severity for a submission.

## Worked example — reentrancy audit

1. Point the agent at a local contract:

```python
   from cyberai.agents.web3.agent import SmartContractAgent

   agent = SmartContractAgent(config, session, llm=None, audit=audit)
   result = agent.run("contracts/Vault.sol")
   print(result["highest_severity"], len(result["findings"]))
```

2. On a TheDAO-style reentrant contract, Slither reports `reentrancy-eth`
   (alongside `solc-version`, `low-level-calls`).
3. `reentrancy-eth` maps to **Critical** → `highest_severity = "Critical"`.
4. Triage the finding against the program's scope and PoC requirements before
   submitting to Immunefi.

## Notes

- Slither absent → `slither_available = False`, findings empty, no crash;
  CI covers the logic with mocked Slither output.
- JSON parsing is verified against Slither 0.11.5
  (`results.detectors[].{check,impact,confidence,description}`).
- This is a triage aid, **not** a substitute for manual review — static
  analysis has false positives; confirm exploitability before submission.

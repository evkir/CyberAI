# Known Issues — Pre-W1 Baseline

This document captures the broken state of CyberAI **as of the start of
the 30-day STANDOFF rewrite**. Each item is fixed by a specific day in
the plan; see `STANDOFF.md` for the schedule.

When all items are checked off, days 1–7 (Reanimation week) are done
and `cyberai scan <target> --dry-run` will work end-to-end.

## How this was verified

Smoke tests in `tests/integration/test_cli_smoke.py` reproduce the broken
state via `CliRunner().invoke(cli, ["scan", ..., "--dry-run"])`. They are
marked `@pytest.mark.xfail` until day 7, then un-xfailed to provide
regression protection.

## The Issues

### 🔴 KI-1 — CLI ↔ Orchestrator API mismatch
- **What's broken:** `__main__.py` calls `Orchestrator(config)` and
  `orchestrator.run_pipeline(session)`. Neither matches the actual API:
  `Orchestrator.__init__(phases, authorized_scope, dry_run)` does not
  accept `config`, and the method is named `run(target)`.
- **Symptom:** `TypeError` on any `cyberai scan` invocation.
- **Fixed by:** Day 5 (`refactor/orchestrator-v2`)
- **Status:** ❌ broken

### 🔴 KI-2 — Two competing session classes
- **What's broken:** `PentestSession` (in `core/session.py`) and
  `ScanSession` (in `core/scan_session.py`) coexist with different
  fields and methods. `__main__.py` uses `PentestSession`; `Orchestrator`
  creates `ScanSession`.
- **Fixed by:** Day 3 (`refactor/unify-session`)
- **Status:** ❌ broken

### 🔴 KI-3 — BaseAgent doesn't match what agents use
- **What's broken:** `BaseAgent.__init__(config, audit, session_id)` is
  what's declared, but agents access `self.session`, `self.kb`,
  `self.memory`, `self.llm` — none of which exist on `BaseAgent`. The
  Orchestrator constructs agents as `ReconAgent(kb=session.kb)`, which
  also doesn't match.
- **Fixed by:** Day 4 (`refactor/base-agent-contract`)
- **Status:** ❌ broken

### 🔴 KI-4 — Agents call non-existent methods
- **What's broken:** Several agents call `self._check_iteration_limit()`,
  `self._log(...)`, `self.llm.chat(...)` — none of these exist.
- **Fixed by:** Day 4 + Day 6
- **Status:** ❌ broken

### 🔴 KI-5 — `Finding` signature mismatch
- **What's broken:** `ReconAgent` builds `Finding(title=..., target=...,
  evidence=[...])`, but the `Finding` dataclass has no `target` or
  `evidence` fields.
- **Fixed by:** Day 3
- **Status:** ❌ broken

### 🔴 KI-6 — `Tool` param name mismatch
- **What's broken:** `Tool` dataclass field is `params`, but every
  `_register_tools()` call uses `parameters=...`.
- **Fixed by:** Day 4
- **Status:** ❌ broken

### 🔴 KI-7 — `LLMClient.chat()` doesn't exist
- **What's broken:** `ExploitAgent` calls `self.llm.chat(messages=...,
  system=...)`. The actual `LLMClient` method is `call()`.
- **Fixed by:** Day 6
- **Status:** ❌ broken

### 🔴 KI-8 — `conftest.fresh_session` accesses non-existent field
- **What's broken:** Original `conftest.py` did
  `fresh_session.knowledge_base["recon.nmap"] = ...` but `PentestSession`
  has no `knowledge_base` field — only `recon_data` / `intel_data` /
  `exploit_data`.
- **Fixed by:** Day 2 (this PR) — temporarily redirected to `recon_data`
- **Status:** ✅ patched (full unification in day 3)

## Reproduction

```bash
# Will raise TypeError before any real work happens:
python -m cyberai scan 127.0.0.1 --dry-run

# Smoke tests reproduce this state:
pytest tests/integration/test_cli_smoke.py -v
# Expected: 2 xfailed, 1 passed
```

## Progress tracker

| Day | Issue(s) addressed | Status |
|-----|-------------------|--------|
| 1   | (rebrand only)    | ✅     |
| 2   | KI-8              | ✅     |
| 3   | KI-2, KI-5        | ⏳     |
| 4   | KI-3, KI-4, KI-6  | ⏳     |
| 5   | KI-1              | ⏳     |
| 6   | KI-7, KI-4        | ⏳     |
| 7   | All checked       | ⏳     |

# Known Issues — Pre-W1 Baseline

Tracks the broken state of CyberAI at the start of the 30-day STANDOFF
rewrite. Each item is fixed by a specific day; see `STANDOFF.md`.

## The Issues

### 🟢 KI-1 — CLI ↔ Orchestrator API mismatch  ✅ FIXED IN DAY 5
`Orchestrator` now takes `(config, phases, dry_run)`; `run(target,
authorized_scope)` owns session creation and builds the shared
`LLMClient`/`AuditLogger`. `__main__.py` calls the real API and gained
`--dry-run` / `--scope`. `python -m cyberai scan <t> --dry-run` runs all
four phases and exits cleanly. Verified by
`tests/unit/test_orchestrator_config.py`.

### 🟢 KI-2 — Two competing session classes  ✅ FIXED IN DAY 3

### 🟢 KI-3 — BaseAgent didn't match what agents use  ✅ FIXED IN DAY 4

### 🟢 KI-4 — Agents called non-existent methods  ✅ FIXED IN DAY 4
`_check_iteration_limit()`, `_log()`, `AgentMemory` exist on
`BaseAgent`. `self.llm.chat()` remains — addressed in day 6 when agents
are migrated to `self.llm.call()`.

### 🟢 KI-5 — Finding signature mismatch  ✅ FIXED IN DAY 3

### 🟢 KI-6 — Tool param name mismatch  ✅ FIXED IN DAY 4

### 🔴 KI-7 — `LLMClient.chat()` doesn't exist
`ExploitAgent` calls `self.llm.chat()`; the real method is `call()`.
Agents still use the old `BaseAgent` construction internally — they are
migrated to the new contract in day 6. **Fixed by:** Day 6.

### 🟢 KI-8 — conftest accessed non-existent field  ✅ FIXED IN DAY 2

## Status: 7/8 closed

Remaining: KI-7 (day 6 — migrate the four agents to the new contract).
After day 6, day 7 un-xfails the smoke tests for full end-to-end
regression protection.

## Progress tracker

| Day | Issue(s) addressed   | Status |
|-----|----------------------|--------|
| 1   | (rebrand only)       | ✅     |
| 2   | KI-8                 | ✅     |
| 3   | KI-2, KI-5           | ✅     |
| 4   | KI-3, KI-4, KI-6     | ✅     |
| 5   | KI-1                 | ✅     |
| 6   | KI-7 + agent migration | ⏳   |
| 7   | un-xfail smoke tests | ⏳     |

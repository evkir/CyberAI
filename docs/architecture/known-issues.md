# Known Issues — Pre-W1 Baseline

Tracks the broken state of CyberAI at the start of the 30-day STANDOFF
rewrite. Each item is fixed by a specific day; see `STANDOFF.md`.

## The Issues

### 🔴 KI-1 — CLI ↔ Orchestrator API mismatch
`__main__.py` calls `Orchestrator(config)` and `run_pipeline(session)` —
neither matches the actual API. **Fixed by:** Day 5.

### 🟢 KI-2 — Two competing session classes  ✅ FIXED IN DAY 3
`scan_session.py` is now the single source of truth. `session.py` is a
backward-compat shim. Verified by `tests/unit/test_session_shim.py`.

### 🟢 KI-3 — BaseAgent didn't match what agents use  ✅ FIXED IN DAY 4
`BaseAgent.__init__` now takes `(config, session, llm, audit)` and
exposes `self.session`, `self.kb`, `self.llm`, `self.memory`. Agents are
migrated to actually use this contract in day 6. Verified by
`tests/unit/test_base_agent.py`.

### 🟢 KI-4 — Agents called non-existent methods  ✅ FIXED IN DAY 4
`_check_iteration_limit()` and `_log()` now exist on `BaseAgent`.
`AgentMemory` (with `add()`/`to_messages()`) backs `self.memory`.
`self.llm.chat()` is addressed in day 6 when ExploitAgent is migrated to
`self.llm.call()`. Verified by `tests/unit/test_base_agent.py`.

### 🔴 KI-5 — Finding signature mismatch  ✅ FIXED IN DAY 3

### 🟢 KI-6 — Tool param name mismatch  ✅ FIXED IN DAY 4
`Tool` accepts both `params` and `parameters`, synced via
`__post_init__`. All agents register tools with `parameters=...` so this
closed without touching any agent file.

### 🔴 KI-7 — `LLMClient.chat()` doesn't exist
Actual method is `call()`. **Fixed by:** Day 6.

### 🟢 KI-8 — conftest accessed non-existent field  ✅ FIXED IN DAY 2

## Progress tracker

| Day | Issue(s) addressed   | Status |
|-----|----------------------|--------|
| 1   | (rebrand only)       | ✅     |
| 2   | KI-8                 | ✅     |
| 3   | KI-2, KI-5           | ✅     |
| 4   | KI-3, KI-4, KI-6     | ✅     |
| 5   | KI-1                 | ⏳     |
| 6   | KI-7, KI-4 (llm.chat)| ⏳     |
| 7   | All checked          | ⏳     |

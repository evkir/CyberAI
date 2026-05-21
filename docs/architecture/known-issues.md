# Known Issues — Pre-W1 Baseline

Tracks the broken state of CyberAI at the start of the 30-day STANDOFF
rewrite. Each item is fixed by a specific day; see `STANDOFF.md`.

## The Issues

### 🔴 KI-1 — CLI ↔ Orchestrator API mismatch
`__main__.py` calls `Orchestrator(config)` and `run_pipeline(session)` —
neither matches the actual API. **Fixed by:** Day 5.

### 🟢 KI-2 — Two competing session classes  ✅ FIXED IN DAY 3
`scan_session.py` is now the single source of truth. `session.py` is a
backward-compat shim where `PentestSession` is a subclass of
`ScanSession` preserving legacy attributes. All 8 import sites work
unchanged. Verified by `tests/unit/test_session_shim.py`.

### 🔴 KI-3 — BaseAgent doesn't match what agents use
Agents access `self.session`, `self.kb`, `self.memory`, `self.llm` —
none exist on `BaseAgent`. **Fixed by:** Day 4.

### 🔴 KI-4 — Agents call non-existent methods
`self._check_iteration_limit()`, `self._log()`, `self.llm.chat()` —
none exist. **Fixed by:** Day 4 + Day 6.

### 🟢 KI-5 — Finding signature mismatch  ✅ FIXED IN DAY 3
`Finding` now has `target`, `evidence`, `cve_ids` fields with
backward-compat `cve` ↔ `cve_ids` syncing. `ScanSession.add_finding()`
auto-fills `target` from `session.target`. Verified by
`tests/unit/test_finding_model.py`.

### 🔴 KI-6 — `Tool` param name mismatch
`Tool` field is `params`, agents register with `parameters=`.
**Fixed by:** Day 4.

### 🔴 KI-7 — `LLMClient.chat()` doesn't exist
Actual method is `call()`. **Fixed by:** Day 6.

### 🟢 KI-8 — conftest accessed non-existent field  ✅ FIXED IN DAY 2

## Progress tracker

| Day | Issue(s) addressed | Status |
|-----|-------------------|--------|
| 1   | (rebrand only)    | ✅     |
| 2   | KI-8              | ✅     |
| 3   | KI-2, KI-5        | ✅     |
| 4   | KI-3, KI-4, KI-6  | ⏳     |
| 5   | KI-1              | ⏳     |
| 6   | KI-7, KI-4        | ⏳     |
| 7   | All checked       | ⏳     |

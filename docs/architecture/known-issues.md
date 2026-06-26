# Known Issues — Pre-W1 Baseline  ✅ ALL RESOLVED

This document tracked the broken state of CyberAI at the start of the
the core rewrite. **All 8 issues are fixed.**

Day 7 un-xfails the smoke tests to lock in regression protection.

## The Issues — all closed

### 🟢 KI-1 — CLI ↔ Orchestrator API mismatch  ✅ DAY 5
Orchestrator takes `config`, owns session creation, builds shared
`LLMClient`/`AuditLogger`. CLI gained `--dry-run` / `--scope`.

### 🟢 KI-2 — Two competing session classes  ✅ DAY 3
`scan_session.py` is the single source of truth; `session.py` is a
backward-compat shim.

### 🟢 KI-3 — BaseAgent didn't match what agents use  ✅ DAY 4
`BaseAgent(config, session, llm, audit)` exposes `session`, `kb`,
`llm`, `memory`.

### 🟢 KI-4 — Agents called non-existent methods  ✅ DAY 4 + 6
`_check_iteration_limit()`, `_log()`, `AgentMemory` added in day 4.
`self.llm.chat()` → `self.llm.call()` completed in day 6.

### 🟢 KI-5 — Finding signature mismatch  ✅ DAY 3
`Finding` has `target`, `evidence`, `cve_ids`.

### 🟢 KI-6 — Tool param name mismatch  ✅ DAY 4
`Tool` accepts both `params` and `parameters`.

### 🟢 KI-7 — `LLMClient.chat()` doesn't exist  ✅ DAY 6
All four agents migrated to the new BaseAgent contract. ExploitAgent
uses `self.llm.call()`. AI analysis gracefully skips when no LLM is
wired (dry-run safe).

### 🟢 KI-8 — conftest accessed non-existent field  ✅ DAY 2

## Bonus fix (day 6)

`ScanSession.kb` was a plain `dict` while `BaseAgent` wrapped it in a
`KnowledgeBase` — so `agent.kb` and `session.kb` silently diverged.
`session.kb` is now a real `KnowledgeBase` from creation.

## Status: 8/8 closed 🎉

## Progress tracker

| Day | Issue(s) addressed     | Status |
|-----|------------------------|--------|
| 1   | (rebrand only)         | ✅     |
| 2   | KI-8                   | ✅     |
| 3   | KI-2, KI-5             | ✅     |
| 4   | KI-3, KI-4, KI-6       | ✅     |
| 5   | KI-1                   | ✅     |
| 6   | KI-7 + agent migration | ✅     |
| 7   | un-xfail smoke tests   | ⏳     |

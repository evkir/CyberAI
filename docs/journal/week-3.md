# Week 3 — Acceleration & Observability

**Период:** дни 15-21. **Итог:** рабочий пайплайн → быстрый, cost-aware и
аудируемый. 319 тестов зелёные (было 264). v0.4.0.

## Что сделано
- **Async pipeline** (дни 15-16): async DNS/subdomain enum, `AsyncOrchestrator`,
  batched async CVE lookups, `LLMClient.acall`. No-regression benchmark gate.
- **Cost & caching** (дни 17-18): `CostTracker` + `BudgetExceeded`, per-model
  pricing, Anthropic prompt caching (`cache_control`) с cache-aware прайсингом.
- **Native tool calling** (день 19): Tool→OpenAI/Anthropic spec конвертеры,
  `call_tools() -> LLMResponse`, provider-aware threading. ExploitAgent строит
  chain через native tool loop под флагом.
- **Structured outputs** (день 20): `structured_call` (json_schema / forced
  tool), Pydantic `ReportSection`, HackerOne-export.
- **Observability** (день 21): SQLite audit log, session export/import,
  `cyberai replay <session_id>`.

## Сквозные паттерны недели
- **Флаг-gated новизна**: каждая поведенческая фича (native tools, LLM summary)
  под флагом default=False — старый детерминированный путь нетронут,
  no-regression на каждом дне.
- **Контракты не ломаются**: `call() -> str` остался; для tool/structured —
  новые методы (`call_tools`, `structured_call`), не мутация существующих.
- **Разведка перед каждым коммитом**: SDK shapes (anthropic 0.100.0 /
  openai 2.36.0) сверялись по факту, не по памяти.


## Грабли на будущее
- **CI-гейт ≠ локальный** (день 21): `ruff format` не ловит F401; CI гоняет
  `ruff check cyberai/`. Unused `import json` утёк в CI. Правило: перед push
  гонять `ruff check cyberai/ && ruff format --check && pytest`.
- **OpenAI strict json_schema** капризен на вложенных pydantic-моделях
  (требует `additionalProperties:false` везде) — проще `strict=False` +
  `model_validate`.
- **Тех-долг**: ~30 unused-import в `tests/` (legacy дни 8-15) — uborka-коммит
  в конце недели. CI их не цепляет (`ruff check cyberai/` без tests/).

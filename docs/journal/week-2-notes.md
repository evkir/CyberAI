# Week 2 — рабочие заметки

## День 8 — pydantic schemas
- Отступление от плана: план просил `run() -> ReconResult`. По факту `run()`
  возвращает статус-словарь для orchestrator, данные — в kb. Менять контракт
  = рефактор orchestrator (день 9) + слом 4 тест-файлов.
- Решение: агенты СТРОЯТ pydantic-модели и кладут в kb как `*.result`.
  Суть дня 8 (валидируемые модели вместо dict) выполнена.
- Backlog: ChainStep в chain_builder.py остался dataclass — не перенесён в pydantic.
- Backlog: report-агент без pydantic-схемы (план дня 8 его не включал).

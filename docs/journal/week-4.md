# Week 4 — Differentiation

**Период:** дни 22-28. **Итог:** платформа получила уникальные фичи —
OOB-driven exploitation, Web3-трек, MCP-сервер, LLM-as-Judge, bug-bounty
scope import и web-дашборд. 395 тестов зелёные (было 319). v0.5.0.

## Что сделано
- **OOB exploitation** (день 22): phantom-grid v2.0 client (token-flow,
  `/api/tokens`), payload-библиотека v2 (7 категорий), `OOBWorkflow` +
  `ExploitAgentOOB` — pick CVE → payload → inject → poll grid → LLM-вывод.
- **Nuclei engine** (день 23): subprocess-обёртка с JSONL-парсером,
  searchsploit (graceful), CVE→OOB-эвристика для JNDI/SSRF-темплейтов.
- **Web3 agent** (день 24): `SmartContractAgent` standalone, Slither-обёртка,
  Immunefi severity classifier (per-check таблица + impact×confidence
  fallback). TheDAO-fixture → reentrancy → Critical.
- **MCP server** (день 25): официальный mcp SDK 1.27.2, recon+intel tools
  как MCP-tools с JSON Schema, graceful dispatch, docs для Claude Desktop.
- **LLM-as-Judge** (день 26): `judge_report` сверяет claims отчёта с KB,
  `JudgeVerdict` (pydantic), retry с фидбеком при score<threshold,
  confidence-per-finding. Флаг `use_judge`.
- **BB scope import** (день 27): H1/Bugcrowd JSON → in/out scope,
  exclusion-aware matching (`!host` бьёт раньше allow-wildcard).
- **Web dashboard** (день 28): Flask→FastAPI, `/api/sessions` читает
  session_*.json с диска, SSE live-progress, htmx+alpine HTML без билда.

## Сквозные паттерны недели
- **Сверка контракта с реальностью**: phantom-grid (день 22), nuclei JSONL
  (день 23), slither JSON (день 24), mcp SDK (день 25) — все API сверены с
  живым выводом/README/SDK, не по памяти и не по плану.
- **Флаг-gated новизна продолжается**: use_native_tools, use_nuclei,
  use_judge — каждая поведенческая фича default=False, no-regression.
- **Graceful degradation как норма**: searchsploit, etherscan, NVD-ключ,
  slither — отсутствие бинаря/ключа = available=False, не падение.
- **Standalone vs pipeline**: Web3-agent вне сетевого пайплайна (контракт ≠
  сетевой target) — архитектурное решение, не натягивание на orchestrator.

## Грабли на будущее (процесс)
- **Анкоры ПОСЛЕ ruff format** (день 24): multi-replace по трёхстрочной
  сигнатуре откатился целиком — файл после format имел однострочную. Урок
  повторился из дней 15/17. Жёстко: sed реального файла перед patch.
- **smoke бьёт happy-path** (день 22): graceful-ветка прошла smoke, но не
  поймала вызов несуществующего метода на happy-path. spec-мок поймал.
- **Мёртвый web-код** (день 28): старый Flask импортил несуществующий
  `AsyncPipeline`, in-memory store расходился с диском. CI его не покрывал.
  Урок: публичный интерфейс без тестов = тихо гниющий код. Дашборд теперь
  читает диск (единый источник правды с CLI replay) и покрыт 8 тестами.

## Дальше
- Дни 29-30: documentation sprint (README, agent API ref, OOB/Web3
  walkthrough) + release v1.0.0 (CHANGELOG, PyPI trusted publishing, tag).
- Хвосты: mypy --strict только на types.py; ~30 unused-import в tests/;
  phantom-grid WebSocket push в roadmap (тогда async client).

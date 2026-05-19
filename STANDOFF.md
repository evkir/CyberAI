# 🟩 CyberAI — 30-Day Standoff
## План перерождения: 4 коммита/день × 30 дней = 120 коммитов

> **Цель:** превратить нерабочий скелет в **рабочую AI-native пентест-платформу** с уникальным OOB-driven подходом и заделом под Web3, при этом каждый день закрашивать кубик зелёным.

---

## 📐 Правила игры

### Что считается «днём»
- **4 коммита в день**, желательно разнесённые во времени (утро/день/вечер/ночь — но необязательно).
- Каждый коммит — **атомарный, осмысленный, проходит pre-commit**.
- Коммиты — на отдельных feature-ветках, в `main` мержим раз в день (Pull Request → squash или merge).

### Формат коммитов (Conventional Commits)
```
feat(scope): добавил X
fix(scope): починил Y
refactor(scope): переделал Z
test(scope): тест на W
docs(scope): описал V
chore(scope): обновил deps
ci(scope): поправил workflow
```
**Scope** = `core`, `recon`, `intel`, `exploit`, `report`, `cli`, `web3`, `ci`, `docs`.

### Что НЕ считается коммитом
- ❌ Пустой commit (`git commit --allow-empty`) — это читерство, видно по GitHub Insights.
- ❌ `Update README.md` правка одной буквы 4 раза в день.
- ✅ Допустимо: один из 4 коммитов в день может быть мелким (typo/fmt/comment) — но не все.

### CI и тесты
- **TDD-light**: для каждой новой фичи добавляется хотя бы 1 unit-тест в том же дне.
- CI должен быть **зелёным к концу дня**. Если красный — последний коммит дня фиксит.
- Pre-commit hook: `ruff check`, `ruff format`, `pytest tests/unit/ -x --tb=no -q`.

### Метрика прогресса
В конце каждого дня — короткая запись в `CHANGELOG.md` (1 строка) что сделано. В конце недели — раздел в `docs/journal/week-N.md` (5-10 строк рефлексии).

---

## 🗺️ Roadmap по неделям (5 фаз)

| Неделя | Тема | Дни | Итог |
|---|---|---|---|
| **W1** | Reanimation — починка ядра | 1-7 | `python -m cyberai scan` реально работает end-to-end |
| **W2** | Hardening — типы, контракты, безопасность | 8-14 | Pydantic-everywhere, injection-detector в pipeline, real e2e tests |
| **W3** | Acceleration — async, кэш, токены | 15-21 | Async pipeline, prompt caching, cost tracking |
| **W4** | Differentiation — OOB-driven + Web3 + MCP | 22-28 | Уникальная фича: OOB-correlation + smart contract agent + MCP server |
| **W4+** | Polish — релиз v1.0 | 29-30 | Доки, демо-видео, v1.0.0 release |

---

# 📅 ДНЕВНОЙ ПЛАН

---

## 🔴 НЕДЕЛЯ 1 — REANIMATION (дни 1-7)

**Главная задача недели:** `python -m cyberai scan <target>` отрабатывает все 4 фазы без падений против фейкового таргета (всё замокано).

---

### ✅ День 1 — Subway clean-up: бренд и битые ссылки

**Контекст:** все 5 ссылок на `user70616E6461` в README/LICENSE/badges/code битые. Бейдж CI ведёт в никуда. Это видят все, кто заходит в репку. Самое быстрое улучшение «первого впечатления».

**Ветка:** `chore/rebrand-evkir`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `chore(docs): rebrand README from user70616E6461 to evkir` | `README.md` | Замена всех 5 вхождений: badge, git clone URL, related tools × 3, footer |
| 2 | `chore(license): update copyright to evkir` | `LICENSE` | `Copyright (c) 2026 user70616E6461` → `Copyright (c) 2026 Evgeny Kiriyak (evkir)` |
| 3 | `chore: fix broken references in integrations and workflows` | `cyberai/integrations/phantom_grid.py`, `.github/workflows/badge_update.md` | Комменты + бейдж |
| 4 | `docs: add STANDOFF.md — 30-day rewrite plan` | `STANDOFF.md` (новый, копия этого файла) | План в репке, чтобы был виден |

**Тесты:** не нужны.
**Время:** 30-45 мин.
**Проверка:** `grep -rn user70616E6461 . --exclude-dir=.git` → пусто.

---

### ✅ День 2 — Smoke test: воспроизводим, что прога не работает

**Контекст:** прежде чем чинить, нужен **failing test** который зафиксирует баг. Это TDD-подход, и это будет твоё «доказательство» что фикс действительно фиксит.

**Ветка:** `test/e2e-smoke`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `test(e2e): add failing smoke test for cyberai scan command` | `tests/integration/test_cli_smoke.py` (новый) | Тест: `CliRunner().invoke(cli, ['scan', '127.0.0.1', '--dry-run'])` → ожидаем exit_code=0. Сейчас он упадёт. Маркируем `@pytest.mark.xfail(reason="orchestrator API mismatch")` |
| 2 | `test(e2e): fixture for mocked LLM client` | `tests/conftest.py` | Добавить `mock_llm_client` fixture которая отдаёт фиксированный ответ — для будущих тестов |
| 3 | `ci: separate smoke tests from unit tests` | `.github/workflows/ci.yml`, `pytest.ini` | Маркер `@pytest.mark.smoke`, отдельный job в CI |
| 4 | `docs: document known broken state in ARCHITECTURE.md` | `docs/architecture/known-issues.md` (новый) | Список того, что сломано — для прозрачности и чтобы потом отслеживать прогресс |

**Тесты:** новый xfail-тест, остальные не трогаем.
**Время:** 1 час.
**Проверка:** `pytest -m smoke` → 1 xfailed, 0 failed.

---

### ✅ День 3 — Единая ScanSession, прощай PentestSession

**Контекст:** два конкурирующих класса сессий — корень всех бед. Убираем `PentestSession`. Оставляем `ScanSession`, переносим в неё `Severity`/`Finding`.

**Ветка:** `refactor/unify-session`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `refactor(core): move Severity and Finding into scan_session` | `cyberai/core/scan_session.py` | Добавить `Severity` enum, `Finding` dataclass (с правильными полями: `id, severity, title, description, target, evidence, cve_ids, agent, timestamp`). Добавить `ScanSession.add_finding(...)` |
| 2 | `refactor(core): replace dict kb with KnowledgeBase instance in ScanSession` | `cyberai/core/scan_session.py` | `kb: KnowledgeBase = field(default_factory=KnowledgeBase)` вместо `dict`. Импорт из `knowledge_base.py` |
| 3 | `refactor(core): remove obsolete PentestSession` | `cyberai/core/session.py` (удалить или превратить в re-export) | `from .scan_session import ScanSession, Severity, Finding` — backward-compat shim |
| 4 | `test(core): update conftest and add ScanSession tests` | `tests/conftest.py`, `tests/unit/test_scan_session.py` | Поправить `fresh_session` чтобы использовать `ScanSession` и `session.kb.set(...)` |

**Тесты:** существующие должны позеленеть (или поправить импорты).
**Время:** 1.5 часа.
**Проверка:** `pytest tests/unit/ -q` → all pass.

---

### ✅ День 4 — BaseAgent контракт

**Контекст:** агенты обращаются к несуществующим `self.session`, `self.kb`, `self.memory`, `self.llm`. Делаем нормальный `BaseAgent` с явной зависимостью на сессию.

**Ветка:** `refactor/base-agent-contract`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `refactor(core): redesign BaseAgent with explicit dependencies` | `cyberai/core/base_agent.py` | Новый `__init__(self, config, session: ScanSession, llm: LLMClient, audit: AuditLogger)`. Поля: `self.config, self.session, self.kb (=session.kb), self.llm, self.audit`. `Tool` fix: `params` остаётся, **но добавляем `parameters` alias через `__post_init__`** для backward compat |
| 2 | `feat(core): add iteration limit and structured logging to BaseAgent` | `cyberai/core/base_agent.py` | `_check_iteration_limit()` метод (учитывает `config.max_agent_iterations`), `self.log(msg, data=None)` и `self._log(event, data)` (alias) |
| 3 | `feat(core): add AgentMemory for multi-turn LLM context` | `cyberai/core/base_agent.py` | Простой `AgentMemory` класс: `add(role, content)`, `to_messages()`. Для ExploitAgent который её юзает |
| 4 | `test(core): comprehensive BaseAgent tests` | `tests/unit/test_base_agent.py` (новый) | Тесты: создание, register_tool, call_tool, iteration_limit поднимается, log пишет в audit |

**Тесты:** новый тест-файл с ~6-8 тестами.
**Время:** 2 часа.
**Проверка:** `pytest tests/unit/test_base_agent.py -v` → all pass.

---

### ✅ День 5 — Orchestrator переписан под новый контракт

**Контекст:** Orchestrator зовёт `run_pipeline(session)`, агенты ждут `run(input_data: dict)` — несовместимо. Унифицируем: `agent.run(target: str) -> dict`.

**Ветка:** `refactor/orchestrator-v2`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `refactor(core): orchestrator accepts config and creates session` | `cyberai/core/orchestrator.py` | `Orchestrator(config: CyberAIConfig, phases=None, dry_run=False)`. Метод `run(target: str, authorized_scope=None) -> ScanSession` |
| 2 | `refactor(core): orchestrator injects llm and audit into agents` | `cyberai/core/orchestrator.py` | В `_dispatch` создаёт agent с правильными аргументами: `ReconAgent(config, session, llm, audit)` |
| 3 | `fix(cli): align __main__.py with new Orchestrator API` | `cyberai/__main__.py` | `orchestrator = Orchestrator(config); session = orchestrator.run(target, authorized_scope=scope_list)`. Добавить `--scope` опцию |
| 4 | `test(core): orchestrator unit tests with mocked agents` | `tests/unit/test_orchestrator.py` | Мокаем агентов, проверяем что фазы вызываются в правильном порядке, что dry_run не зовёт реальные тулы |

**Тесты:** обновить + добавить.
**Время:** 2 часа.
**Проверка:** `pytest tests/unit/test_orchestrator.py -v` → all pass.

---

### ✅ День 6 — Чиним агентов под новый контракт

**Контекст:** все 4 агента используют старые API. Переводим на новый `BaseAgent`.

**Ветка:** `refactor/agents-align`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `refactor(recon): align ReconAgent with new BaseAgent` | `cyberai/agents/recon/agent.py` | `run(self, target: str) -> dict`. Замена `self.session.target` → `target`, `self.session.knowledge_base[...]` → `self.kb.set(...)`. `parameters=` → `params=` |
| 2 | `refactor(intel): align IntelAgent with new BaseAgent` | `cyberai/agents/intel/agent.py` | То же. Замена `self.log("intel", msg)` → `self.log(msg, data={"agent":"intel"})`. Убрать дубль `IntelAgentV2` — слить в один с флагом `score_cves=True` |
| 3 | `refactor(exploit): align ExploitAgent with new BaseAgent` | `cyberai/agents/exploit/agent.py` | `self.llm.chat(...)` → `self.llm.call(...)`. Использовать `self.memory` (теперь существует) |
| 4 | `refactor(report): align ReportAgent with new BaseAgent` | `cyberai/agents/report/agent.py` | Замена `self.session.target`, `self.session.findings` — теперь это `self.session.findings` через ScanSession |

**Тесты:** существующие unit-тесты агентов должны позеленеть.
**Время:** 2-3 часа.
**Проверка:** `pytest tests/unit/ -q` → all pass.

---

### ✅ День 7 — End-to-end smoke работает! 🎉

**Контекст:** всё собрано — пора убрать xfail и убедиться, что `cyberai scan` отрабатывает.

**Ветка:** `feat/e2e-working`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(cli): dry-run mode actually works end-to-end` | `cyberai/__main__.py`, `cyberai/core/orchestrator.py` | Проверка `--dry-run` флаг проходит до агентов, ничего реального не запускают, возвращают stub |
| 2 | `test(e2e): unxfail smoke test, it passes now` | `tests/integration/test_cli_smoke.py` | Убираем `@pytest.mark.xfail`. Добавляем asserts: exit_code=0, session.state=COMPLETED, есть report path |
| 3 | `docs: update README quickstart with working commands` | `README.md` | Обновить раздел Quick start. Добавить `--dry-run` пример |
| 4 | `chore: bump version to 0.2.0 (reanimation complete)` | `cyberai/version.py`, `CHANGELOG.md` | `__version__ = "0.2.0"`. CHANGELOG: «Week 1: skeleton-to-working pipeline» |

**Тесты:** smoke test зелёный.
**Время:** 1.5 часа.
**Проверка:** `python -m cyberai scan example.com --dry-run` → выводит итог без ошибок.

**📌 Конец недели 1:** написать `docs/journal/week-1.md`. Рефлексия: что сложнее всего было, что неожиданно зашло.

---

## 🟡 НЕДЕЛЯ 2 — HARDENING (дни 8-14)

**Главная задача недели:** Pydantic-контракты, injection-defense в pipeline, реальный nmap/whois работает, EPSS подключен.

---

### ✅ День 8 — Pydantic schemas для всех результатов агентов

**Ветка:** `feat/pydantic-contracts`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(core): pydantic schemas for ReconResult and OpenPort` | `cyberai/core/types.py` | `class OpenPort(BaseModel): port: int; protocol: str; service: str; version: Optional[str]`. `class ReconResult(BaseModel): target: str; ports: list[OpenPort]; whois: dict; dns: dict; subdomains: list[str]` |
| 2 | `feat(core): pydantic schemas for IntelResult and CVEEntry` | `cyberai/core/types.py` | `class CVEEntry`: id, cvss, severity, description, published, exploited_in_wild, epss. `class IntelResult` |
| 3 | `feat(core): pydantic schemas for ExploitResult and AttackPath` | `cyberai/core/types.py` | `AttackPath`, `ExploitChain`, `ExploitResult` |
| 4 | `refactor(agents): all agents return pydantic models, not dicts` | `cyberai/agents/*/agent.py` | `def run(...) -> ReconResult` и т.д. Внутри — `.model_dump()` при записи в kb |

**Тесты:** обновить unit-тесты под новые типы.
**Проверка:** `pytest tests/unit/ -q`.

---

### ✅ День 9 — Injection detector в пайплайне

**Ветка:** `feat/injection-defense`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(security): wire injection_detector into orchestrator phase boundary` | `cyberai/core/orchestrator.py`, `cyberai/core/security/injection_detector.py` | После каждой фазы прогон результата через detector. Если detected — флаг в session, warn в консоль |
| 2 | `feat(security): expand prompt-injection patterns library` | `cyberai/core/security/injection_detector.py` | Добавить паттерны: «ignore previous», «you are now», «system prompt», «base64 decoded payload», unicode-смайлы как escape. Tests inline |
| 3 | `feat(security): sanitize service banners before LLM context` | `cyberai/core/security/input_sanitizer.py` | Функция `sanitize_banner(banner: str) -> str` — обрезает >500 chars, удаляет escape-секвенции, маркирует «UNTRUSTED INPUT» |
| 4 | `test(security): integration test for injection during recon phase` | `tests/integration/test_injection_defense.py` | Подсовываем nmap-ответ с вшитой инъекцией → detector её ловит, LLM её не видит как инструкцию |

---

### ✅ День 10 — Реальный nmap с защитой от command injection

**Ветка:** `fix/nmap-safety`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `fix(recon): whitelist nmap flags, reject unknown` | `cyberai/agents/recon/nmap_tool.py` | `ALLOWED_FLAGS = {"-sV","-sC","-sT","-sS","-T0".."-T5","-p","--top-ports","-Pn","-A","-O"}`. Парсим через `shlex.split`, отвергаем неизвестные |
| 2 | `refactor(recon): merge nmap_tool and nmap_wrapper into one` | удалить `nmap_wrapper.py`, обновить импорты | Один путь — `nmap_tool.run_nmap` |
| 3 | `feat(recon): nmap result caching by target+flags hash` | `cyberai/core/cache.py`, `cyberai/agents/recon/nmap_tool.py` | SQLite-кэш в `~/.cyberai/cache.db`. TTL 1 час по умолчанию. Не сканим один и тот же target 100 раз |
| 4 | `test(recon): nmap flag whitelist + cache hit/miss` | `tests/unit/test_nmap_tool.py` | Тесты: «-sV» проходит, «-sV; rm -rf /» отвергается, второй вызов идёт из кэша |

---

### ✅ День 11 — EPSS клиент и enrichment

**Ветка:** `feat/epss-integration`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(intel): EPSS API client (api.first.org)` | `cyberai/agents/intel/epss_client.py` (новый) | `get_epss_scores(cve_ids: list[str]) -> dict[str, float]`. Batch до 100 IDs. Кэшируем |
| 2 | `feat(intel): enrich CVEs with EPSS in IntelAgent` | `cyberai/agents/intel/agent.py` | После NVD-запроса прогоняем все CVE через EPSS, заполняем поле `epss` (которое сейчас всегда 0) |
| 3 | `feat(intel): risk_prioritizer uses EPSS as multiplier` | `cyberai/agents/intel/risk_prioritizer.py` | Composite score: `cvss * (1 + epss) * exploit_factor`. EPSS>0.5 — 🔥, >0.2 — ⚠️ |
| 4 | `test(intel): EPSS client + prioritizer with real-world fixtures` | `tests/unit/test_epss.py`, `tests/fixtures/epss_log4shell.json` | Lo4Shell (CVE-2021-44228, EPSS≈0.94) должен идти топом |

---

### ✅ День 12 — NVD API ключ + правильный rate limiter

**Ветка:** `feat/nvd-apikey`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(intel): NVD API key support` | `cyberai/agents/intel/nvd_client.py`, `cyberai/core/config.py` | Читаем `NVD_API_KEY` из env. Если есть — header `apiKey:`, rate 50/30s. Если нет — 5/30s (legacy) |
| 2 | `refactor(core): unified rate limiter with per-API config` | `cyberai/core/rate_limiter.py` | Token bucket. Конфигурим: NVD, EPSS, OpenAI, Anthropic, phantom-grid — каждый со своим RPS |
| 3 | `feat(intel): graceful retry on NVD 429/503` | `cyberai/agents/intel/nvd_client.py`, `cyberai/utils/backoff.py` | Exponential backoff, max_retries=3 |
| 4 | `docs: NVD API key setup guide` | `.env.example`, `docs/setup/nvd-apikey.md` | Как получить (бесплатно), куда вписать |

---

### ✅ День 13 — Datetime modernization + ruff config

**Ветка:** `chore/modernize`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `chore: replace datetime.utcnow() with timezone-aware now()` | 11 файлов — sweep | `datetime.now(timezone.utc)` везде. Python 3.14-ready |
| 2 | `chore: migrate setup.py to pyproject.toml (PEP 621)` | `pyproject.toml` (новый), удалить `setup.py` | Hatchling backend. Метаданные, deps, entrypoints |
| 3 | `chore: pin top-level deps upper bounds` | `pyproject.toml` (или `requirements.txt`) | `openai>=1.30,<2`, `anthropic>=0.28,<1`, `pydantic>=2.7,<3` |
| 4 | `ci: add ruff format check and mypy --strict` | `.github/workflows/ci.yml`, `pyproject.toml` | Format-check шаг. Mypy на `cyberai/core/` (постепенный rollout) |

---

### ✅ День 14 — Real e2e test против реального таргета (scanme.nmap.org)

**Ветка:** `test/real-e2e`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `test(e2e): real nmap against scanme.nmap.org` | `tests/integration/test_real_recon.py` | Помечен `@pytest.mark.slow @pytest.mark.network`. Запускает реальный nmap, проверяет что найден 22/tcp ssh |
| 2 | `test(e2e): real NVD query for known CVE` | `tests/integration/test_real_intel.py` | Запрос про «openssh 7.4» → находит CVE с CVSS>=7. Не упадёт если у юзера есть NVD API key (skip иначе) |
| 3 | `ci: run slow tests on schedule (nightly), not on every PR` | `.github/workflows/nightly.yml` (новый) | Cron `0 2 * * *`, прогон `pytest -m slow` |
| 4 | `chore: bump version to 0.3.0` | `cyberai/version.py`, `CHANGELOG.md` | «Week 2: type safety + real-world integration» |

**📌 Конец недели 2:** `docs/journal/week-2.md`.

---

## 🟢 НЕДЕЛЯ 3 — ACCELERATION (дни 15-21)

**Главная задача:** async pipeline, prompt caching, token/cost tracking, lateral движение к фиче-богатству.

---

### ✅ День 15 — Async recon pipeline

**Ветка:** `feat/async-recon`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(recon): async DNS tool with dnspython.asyncresolver` | `cyberai/agents/recon/dns_tool.py` | `async def run_dns_async(target)`. Concurrent A/AAAA/MX/TXT/NS |
| 2 | `feat(recon): async subdomain enumeration with semaphore` | `cyberai/agents/recon/subdomain_enum.py` | `asyncio.Semaphore(20)` чтобы не упасть в провайдера. asyncio.gather по wordlist |
| 3 | `feat(recon): ReconAgent gathers all tools concurrently` | `cyberai/agents/recon/async_agent.py` (доделать) | `await asyncio.gather(nmap, whois, dns, subdomains)`. Связать с оркестратором через `asyncio.run` |
| 4 | `test(recon): benchmark sync vs async (≥2x speedup)` | `tests/benchmarks/test_recon_speed.py` | Pytest benchmark. Записываем результат в `docs/benchmarks.md` |

---

### ✅ День 16 — Async во всём пайплайне

**Ветка:** `feat/async-pipeline`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(core): AsyncOrchestrator runs phases concurrently where safe` | `cyberai/core/orchestrator.py` | Recon→Intel→Exploit→Report — фазы последовательны, но внутри фаз — async. Subphases concurrent |
| 2 | `feat(intel): parallel NVD queries with rate limiter` | `cyberai/agents/intel/nvd_client.py` | `async def search_cves_batch(queries: list)`. Семафор уважает rate-limit |
| 3 | `feat(core): LLMClient.acall — async LLM calls` | `cyberai/core/llm_client.py` | `async def acall(...)` для openai/anthropic/ollama. Через `httpx.AsyncClient` |
| 4 | `test(integration): async pipeline end-to-end` | `tests/integration/test_async_pipeline.py` | Полный прогон через AsyncOrchestrator, мокается LLM |

---

### ✅ День 17 — Cost tracking + budget control

**Ветка:** `feat/cost-tracking`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(core): TokenUsage tracker per agent call` | `cyberai/core/cost_tracker.py` (новый) | После каждого LLM-вызова: `usage = response.usage; tracker.add(agent, prompt, completion, model)` |
| 2 | `feat(core): pricing table for popular models` | `cyberai/core/pricing.py` (новый) | gpt-4o, gpt-4o-mini, claude-opus-4.7, claude-sonnet-4.6, claude-haiku-4.5 — по input/output $/1M токенов. Источник: pricing pages |
| 3 | `feat(cli): show cost summary at end of scan` | `cyberai/__main__.py`, `cyberai/cli/scan.py` | После сессии: «Total: $0.142 (1234 in / 5678 out tokens, 4 LLM calls)» |
| 4 | `feat(core): budget enforcement — stop pipeline at max_cost_usd` | `cyberai/core/config.py`, `cyberai/core/orchestrator.py` | `config.max_cost_usd = 5.0`. После каждого вызова проверяем, если превышен — fail-fast |

---

### ✅ День 18 — Anthropic prompt caching

**Ветка:** `feat/prompt-caching`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(llm): Anthropic prompt caching for system prompts` | `cyberai/core/llm_client.py` | `system=[{"type":"text","text":system,"cache_control":{"type":"ephemeral"}}]`. До 90% экономии на повторных вызовах |
| 2 | `feat(llm): cache CVE database in system context` | `cyberai/agents/intel/agent.py`, `cyberai/core/prompts.py` | Большие справочники (top-100 CVE паттернов) кэшируются |
| 3 | `feat(cost): cached tokens учитываются по cache-pricing` | `cyberai/core/pricing.py`, `cyberai/core/cost_tracker.py` | Anthropic cache_read = 0.1× от input, cache_write = 1.25×. Корректный расчёт |
| 4 | `test(llm): prompt caching reduces token cost on repeated calls` | `tests/unit/test_prompt_caching.py` | Мок Anthropic API, проверяем `cache_creation_input_tokens` и `cache_read_input_tokens` |

---

### ✅ День 19 — LLM tool calling (нативное, не наш Tool класс)

**Ветка:** `feat/llm-tools-native`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(llm): Tool to OpenAI tools spec converter` | `cyberai/core/llm_client.py` | `_tools_to_openai_format(tools: list[Tool]) -> list[dict]` — JSON Schema из dataclass |
| 2 | `feat(llm): Tool to Anthropic tool_use spec converter` | `cyberai/core/llm_client.py` | То же для Anthropic |
| 3 | `feat(agents): ExploitAgent uses native tool calling for chain building` | `cyberai/agents/exploit/agent.py` | LLM сам решает, какой tool вызвать в каком порядке. Loop с tool_use → tool_result |
| 4 | `test(llm): mocked tool calling flow` | `tests/unit/test_tool_calling.py` | Mock LLM возвращает tool_use → orchestrator вызывает → tool_result в контекст → LLM продолжает |

---

### ✅ День 20 — Structured outputs для отчёта

**Ветка:** `feat/structured-outputs`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(llm): response_format=json_schema support` | `cyberai/core/llm_client.py` | OpenAI: `response_format={"type":"json_schema",...}`. Anthropic: tool_use на одно «tool» |
| 2 | `feat(report): Pydantic-validated report from LLM` | `cyberai/agents/report/agent.py` | LLM возвращает структуру `ReportSection(title, severity, findings, recommendations)` |
| 3 | `feat(report): HackerOne-compatible export` | `cyberai/agents/report/h1_exporter.py` (новый) | Markdown в формате HackerOne: title, Severity, Steps to reproduce, Impact, Recommendation |
| 4 | `test(report): structured output roundtrip` | `tests/unit/test_structured_report.py` | LLM-мок → ReportSection → markdown → парсится обратно |

---

### ✅ День 21 — Audit log в SQLite + replay

**Ветка:** `feat/audit-replay`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(core): SQLite-backed audit log` | `cyberai/core/logger.py` | Таблица `audit_events(id, session_id, agent, action, inputs_json, outputs_json, timestamp)`. Append-only |
| 2 | `feat(core): session export/import for replay` | `cyberai/core/scan_session.py` | `session.to_json()`, `ScanSession.from_json()`. Сохраняет всю сессию вместе с kb |
| 3 | `feat(cli): cyberai replay <session_id>` | `cyberai/__main__.py`, `cyberai/cli/replay.py` (новый) | Берёт сохранённую сессию, переигрывает пайплайн с теми же mock-ответами LLM |
| 4 | `chore: version 0.4.0 — accelerated & observable` | `cyberai/version.py`, `CHANGELOG.md` | «Week 3: async + cost tracking + audit» |

**📌 Конец недели 3:** `docs/journal/week-3.md`.

---

## 🔵 НЕДЕЛЯ 4 — DIFFERENTIATION (дни 22-28)

**Главная задача:** уникальность — OOB-driven exploitation как главная фича + Web3 трек + MCP server.

---

### ✅ День 22 — phantom-grid интеграция работает реально

**Ветка:** `feat/phantom-grid-real`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(integrations): phantom-grid async client with WebSocket polling` | `cyberai/integrations/phantom_grid.py` | Async client: subscribe на interaction_id, получаем callbacks в realtime |
| 2 | `feat(integrations): OOB payload library v2 — Burp Collaborator parity` | `cyberai/integrations/oob_payloads.py` | SSRF, XXE, blind SQLi, log4shell-style, CRLF, SSTI — все с шаблонами под grid |
| 3 | `feat(exploit): ExploitAgentOOB orchestrates payload→inject→correlate` | `cyberai/agents/exploit/agent.py`, `cyberai/agents/exploit/oob_workflow.py` (новый) | Workflow: pick CVE → generate payload → submit (через HTTP/burp-cli/curl) → poll grid → LLM анализирует callback |
| 4 | `test(integration): OOB SSRF detection mocked end-to-end` | `tests/integration/test_oob_ssrf.py` | Мок-grid отдаёт callback → агент корректно делает вывод «SSRF confirmed» |

---

### ✅ День 23 — Nuclei templates как exploit engine

**Ветка:** `feat/nuclei-engine`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(exploit): nuclei wrapper with CVE→template mapping` | `cyberai/agents/exploit/nuclei_engine.py` (новый) | `run_nuclei(target, cve_id)`. Subprocess к `nuclei -id <cve>` или с tags |
| 2 | `feat(exploit): searchsploit integration` | `cyberai/agents/exploit/searchsploit.py` (новый) | Парсим вывод `searchsploit -j <cve>`. PoC paths возвращаем |
| 3 | `feat(exploit): chain Nuclei → OOB callback verification` | `cyberai/agents/exploit/agent.py` | Если Nuclei template требует OOB (например, Log4Shell) — автоматически подставляем grid URL |
| 4 | `test(exploit): nuclei runner mocked + integration test` | `tests/unit/test_nuclei.py` | Subprocess замокан, проверяем парсинг JSON-вывода Nuclei |

---

### ✅ День 24 — Smart Contract Agent (Web3 заход)

**Ветка:** `feat/web3-agent`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(web3): SmartContractAgent skeleton + etherscan client` | `cyberai/agents/web3/agent.py`, `cyberai/agents/web3/etherscan.py` (новые) | `agent.run(contract_address)`. Etherscan API: source code, ABI, verified status |
| 2 | `feat(web3): Slither wrapper for static analysis` | `cyberai/agents/web3/slither_tool.py` | Subprocess `slither <addr> --json -`. Парсим detectors: reentrancy, uninitialized-storage, etc |
| 3 | `feat(web3): Immunefi severity classifier` | `cyberai/agents/web3/immunefi_severity.py` | Mapping detector → Immunefi severity (Critical/High/Medium/Low/Insight) по их методологии |
| 4 | `test(web3): full smartcontract pipeline with fixture` | `tests/integration/test_web3.py`, `tests/fixtures/dao_reentrant.sol` | Подаём уязвимый контракт (TheDAO-style) → Slither находит reentrancy → severity=Critical |

---

### ✅ День 25 — MCP Server (Anthropic Model Context Protocol)

**Ветка:** `feat/mcp-server`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(mcp): MCP server skeleton via mcp-python-sdk` | `cyberai/mcp/server.py` (новый), `pyproject.toml` | Добавить `mcp>=1.0` в deps. `server = Server("cyberai")` |
| 2 | `feat(mcp): expose recon tools as MCP tools` | `cyberai/mcp/tools.py` | `nmap_scan`, `dns_enum`, `subdomain_enum`, `whois_lookup` — все как MCP tools с JSON Schema |
| 3 | `feat(mcp): expose intel tools (cve_search, epss_score)` | `cyberai/mcp/tools.py` | CVE-lookup и EPSS как MCP tools |
| 4 | `docs: MCP integration guide — Claude Desktop / Cursor` | `docs/mcp/integration.md` | Как подключить CyberAI MCP в Claude Desktop через `~/.config/claude/desktop_config.json` |

---

### ✅ День 26 — LLM-as-Judge для отчётов

**Ветка:** `feat/llm-judge`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(report): LLM judge validates claims against evidence` | `cyberai/agents/report/judge.py` (новый) | Второй LLM (более мощный) проверяет: каждый claim в отчёте имеет evidence в kb? hallucination score |
| 2 | `feat(report): judge can request retry with feedback` | `cyberai/agents/report/agent.py` | Если score<0.7 — ReportAgent перегенерирует с фидбеком от judge |
| 3 | `feat(report): confidence score per finding` | `cyberai/core/types.py`, отчёт | Каждый finding имеет `confidence: 0..1`. Низкий — пометка в отчёте |
| 4 | `test(report): judge catches hallucinated CVE` | `tests/unit/test_judge.py` | Мок: в отчёте CVE-9999-99999 (не существует в kb) → judge ловит |

---

### ✅ День 27 — HackerOne / Bugcrowd scope import

**Ветка:** `feat/bb-scope-import`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(cli): import scope from HackerOne scope.json` | `cyberai/cli/scope.py` | `cyberai scope import h1 --program acme` через H1 API |
| 2 | `feat(cli): import scope from Bugcrowd JSON` | `cyberai/cli/scope.py` | Bugcrowd scope formats |
| 3 | `feat(safety): scope honor wildcards and exclusions` | `cyberai/agents/exploit/safety_validator.py` | `*.acme.com` matching, `!staging.acme.com` exclusions, OOSPATHS |
| 4 | `test(safety): wildcard scope + exclusion edge cases` | `tests/unit/test_scope_matching.py` | Тесты: `api.acme.com` matches `*.acme.com`, `internal.staging.acme.com` excluded |

---

### ✅ День 28 — Web dashboard (минимальный)

**Ветка:** `feat/web-dashboard`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `feat(web): FastAPI app exposes sessions and reports` | `cyberai/web/app.py` | Переход с Flask (если был) на FastAPI. `/sessions`, `/sessions/{id}`, `/sessions/{id}/report` |
| 2 | `feat(web): live session progress via SSE` | `cyberai/web/routes/session.py` | Server-Sent Events: фронт получает phase updates в realtime |
| 3 | `feat(web): minimal HTML dashboard (htmx + alpinejs)` | `cyberai/web/templates/dashboard.html` | Без React. Список сессий, кнопка «New scan», live progress |
| 4 | `chore: bump 0.5.0 — differentiated platform` | `cyberai/version.py`, `CHANGELOG.md` | «Week 4: OOB + Web3 + MCP + judge» |

**📌 Конец недели 4:** `docs/journal/week-4.md`.

---

## ⚪ ДНИ 29-30 — POLISH & RELEASE

---

### ✅ День 29 — Documentation sprint

**Ветка:** `docs/v1-release`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `docs: comprehensive README rewrite with screenshots` | `README.md`, `docs/assets/` | Что/Зачем/Demo/Quick start/Архитектура. Скрин дашборда, демо-вывод scan |
| 2 | `docs: agent API reference` | `docs/api/agents.md` | Каждый агент: input, output, tools, edge cases |
| 3 | `docs: OOB-driven exploitation walkthrough` | `docs/workflows/oob-exploitation.md` | Конкретный пример: SSRF на example.com через phantom-grid step-by-step |
| 4 | `docs: Web3 / Immunefi workflow guide` | `docs/workflows/web3-audit.md` | Как использовать SmartContractAgent для аудита перед submit на Immunefi |

---

### ✅ День 30 — Release v1.0.0 🚀

**Ветка:** `release/1.0.0`

| # | Commit | Файлы | Что делаем |
|---|---|---|---|
| 1 | `chore: bump version to 1.0.0` | `cyberai/version.py`, `pyproject.toml` | Major release |
| 2 | `docs: comprehensive CHANGELOG for v1.0` | `CHANGELOG.md` | Все 30 дней суммированы по неделям |
| 3 | `ci: publish to PyPI on tag` | `.github/workflows/release.yml` | Trusted publishing к PyPI на `v*` тег |
| 4 | `release: tag v1.0.0` | tag | `git tag -a v1.0.0 -m "..."; git push --tags` — GitHub Release с release notes |

---

# 🛡️ Hard rules — чтобы не сорваться

### 1. Если пропустил день
- **Не делать «компенсацию»** на следующий день 8 коммитами. Это бьёт по фокусу и видно по pattern на GitHub.
- Сделай **1 commit** в пропущенный день из категории «docs/typo» если возможно (vacation commits — это норма). Но не злоупотребляй.

### 2. Если день забуксовал
- Любой день из плана можно **сдвинуть**. План — это карта, а не контракт.
- Минимум на сложные дни (4, 5, 6, 22, 25): закладывай 3-4 часа.

### 3. Если CI красный
- **Один из коммитов дня = fix CI**. Это нормально, это часть работы.

### 4. Анти-burnout
- 1 день в неделю — **lite-режим** (4 коммита по docs/cleanup/typo). Это для устойчивости. Я отметил такие дни где они органично ложатся.
- Время в кресле — твоя ценность. Береги.

### 5. Качество > количество
- Если день получился 3 коммита, но настоящих — это лучше, чем 4 пустых. Зелёный кубик не убежит, если 1 коммит = осмысленный.

---

# 📊 Метрики прогресса (отслеживаем каждую неделю)

В `docs/journal/week-N.md` фиксируем:

| Метрика | W0 (старт) | W1 | W2 | W3 | W4 | W5 |
|---|---|---|---|---|---|---|
| LoC (без тестов) | ~6000 | | | | | |
| Test coverage % | ~? | | | | | |
| `cyberai scan example.com --dry-run` работает | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Реальная фаза recon работает | ❌ | | ✅ | | | |
| EPSS подключен | ❌ | | ✅ | | | |
| Cost tracking | ❌ | | | ✅ | | |
| OOB workflow | ❌ | | | | ✅ | |
| Web3 agent | ❌ | | | | ✅ | |
| MCP server | ❌ | | | | ✅ | |
| Stars (просто наблюдать) | 0 | | | | | |

---

# 🎯 Финальный итог через 30 дней

✅ Работающая платформа (CLI + Web dashboard + MCP server)
✅ Bug bounty workflow (H1/Bugcrowd scope import, OOB SSRF/XXE, HackerOne export)
✅ Web3 трек (Slither + Immunefi severity)
✅ ~120 commits в зелёных кубиках
✅ v1.0.0 на PyPI
✅ Уникальное позиционирование: **«OOB-driven, agent-trust-aware AI pentest platform»** — такого нет ни у кого

**Это не «ещё один AI-обёртщик над nmap».** Это твоя ниша.

Погнали? 🐼→🦅

# Week 4 — Differentiation

## День 22 — phantom-grid интеграция работает реально

**Ветка:** `feat/phantom-grid-real` → merge commit. 327 тестов зелёные (+8).

**Главное:** переписано под РЕАЛЬНЫЙ phantom-grid v2.0 API (сверено с README репозитория), а не под план. План писался до сверки контракта.

**Коммиты:**
1. v2.0 client — token-flow, /api/tokens, /c/<token>, порт 9090, унифицирован OOBInteraction
2. payloads v2 — /c/<token>, +CRLF/SQLi/CMDi (7 категорий)
3. OOBWorkflow + ExploitAgentOOB token-flow
4. fix: OOBWorkflow.wait_for_callback через poller (не client)
5. 8 mocked e2e тестов

**Расхождения план vs реальность:**
- WebSocket (план) НЕ существует в phantom-grid — в roadmap. Сделал HTTP /api/poll.
- Два клиента-дубля (PhantomGridClient + PhantomGridPoller) с разными endpoint (?id= vs /{id}, реальный — /api/tokens/<id>/interactions) и несовместимым timestamp (str vs float). Консолидировал в один, poller → shim.
- Локальный uuid interaction_id → реальный серверный token (POST /api/tokens).

**Уроки:**
- **Сверяй контракт с реальным сервером/README до написания клиента.** Оба существующих клиента били несуществующий API — никто бы не заметил без живого сервера или сверки README.
- smoke коммита 3 прошёл по graceful-ветке (available=False) и НЕ поймал вызов несуществующего метода на happy-path. spec=-мок в тесте поймал. Урок: smoke бьёт happy-path.
- MSSQL UNC payload через heredoc: `\\\\` в Python-строке → проверять реальный вывод (`\\ID.h\x` корректно).
- phantom-grid TODO для меня: WebSocket push (заменит polling), тогда вернусь к async client.

## День 23 — Nuclei templates как exploit engine (v3.8.0)

**Ветка:** `feat/nuclei-engine` → merge commit. 344 теста зелёные (+17).

**Коммиты:**
1. nuclei_engine.py — subprocess, JSONL-парсер, NucleiFinding, find_nuclei, graceful
2. searchsploit.py — -j парсер, graceful (бинаря нет)
3. ExploitAgent._run_nuclei (флаг use_nuclei) + OOB-эвристика _cve_needs_oob
4. 17 тестов (мок subprocess + os.path.exists/find_*)

**Решения:**
- nuclei JSONL сверен с реальным выводом v3.8.0: cve-id бывает null/string/list — парсер всё ест. -omit-raw обязателен (без него request/response раздувают JSON всем HTML).
- find_nuclei: PATH → ~/go/bin → NUCLEI_PATH env (nuclei не в системном PATH, только go/bin).
- searchsploit НЕ установлен → graceful как phantom-grid (available). CI не блокирую.
- OOB-wiring: nuclei -var oob=<capture_url> для CVE с JNDI/SSRF/CRITICAL техникой (эвристика по poc_mapper). Не перехватывает встроенный interactsh — это для templates с кастомной OOB-переменной.

**Уроки (процесс):**
- ДВАЖДЫ предложил коммит при красном выводе: (1) smoke коммита 3 с неполным фикстуром (_iterations) — pytest спас, флаг-gated код не тронул тесты; (2) коммит 4 — 5 тестов красные из-за os.path.exists на фейк-путях. Правило закреплено жёстко: НЕ предлагать коммит при красном ЛЮБОЙ проверки, даже если уверен что артефакт.
- available через os.path.exists(path) → тесты с фейк-путём (/fake/nuclei) дают available=False. Фикс: @patch os.path.exists=True. А find_nuclei находит реальный go/bin/nuclei → "unavailable" тесты надо мокать find_nuclei=None.
- @patch stack: аргументы снизу вверх (subprocess.run первым, os.path.exists вторым).

## День 24 — Smart Contract Agent (Web3 заход)

**Ветка:** `feat/web3-agent` → merge commit. 349 тестов зелёные (+5).

**Коммиты:**
1. web3/agent.py (SmartContractAgent skeleton) + etherscan.py (graceful)
2. slither_tool.py — subprocess --json -, парсер results.detectors
3. immunefi_severity.py — check→tier mapping + impact/confidence fallback
4. test_web3.py + fixtures/dao_reentrant.sol (TheDAO-style) — e2e

**Решения:**
- slither JSON сверен с реальным 0.11.5: results.detectors[].{check,impact,confidence,description}. На vuln-контракте: reentrancy-eth/solc-version/low-level-calls.
- Immunefi: per-check таблица (reentrancy-eth/arbitrary-send/suicidal/delegatecall→Critical) + fallback impact×confidence для неизвестных detector'ов.
- agent standalone (не в network-пайплайне) — contract ≠ сетевой target.
- etherscan graceful (нет ключа) — local .sol основной путь.
- live-тесты под skipif(not slither.available) — CI без slither пропустит, mocked покрывают логику.

**Уроки (процесс — снова анкоры):**
- python3<<PY patch агента ОТКАТИЛСЯ ЦЕЛИКОМ: анкор `def run(` был трёхстрочным (как до ruff format), а файл после format коммита 1 имел однострочную сигнатуру. assert на 3-й замене оборвал ДО write → файл нетронут. Тесты поймали (нет SlitherTool). Это РОВНО мой же урок дней 15/17: анкоры составлять ПОСЛЕ ruff format, читая реальный файл. Закрепляю: перед multi-replace patch — sed реального файла, не по памяти.

## День 25 — MCP Server (Anthropic MCP)

**Ветка:** `feat/mcp-server` → merge commit. 357 тестов зелёные (+8).

**Коммиты:**
1. server.py skeleton — Server("cyberai") на mcp SDK 1.27.2, stdio, list/call handlers, graceful dispatch + pyproject mcp>=1.0
2. recon tools — nmap_scan/dns_enum/whois_lookup/subdomain_enum (JSON Schema)
3. intel tools — cve_search/cve_detail/epss_score + test_mcp.py (8 тестов)
4. docs/mcp/integration.md — Claude Desktop/Cursor/Inspector

**Решения:**
- Официальный mcp SDK (Server low-level), НЕ своя реализация — для server-роли правильно. В mas-sentry-toolkit наоборот делал свою (там MCP-СКАНЕР шлёт malformed-трафик, SDK мешал бы). Разные роли — разный выбор.
- Реестр TOOL_REGISTRY: name→{description, inputSchema, handler}. register() + тонкие async-обёртки в list_tools/call_tool. sync recon/intel функции переиспользованы как handlers без изменений.
- graceful dispatch: unknown tool / handler error → TextContent с error-json, не raise. Клиент всегда получает структурированный ответ.
- +cve_detail (сверх плана), +test_mcp.py (MCP = публичный интерфейс → CI-покрытие).

**SDK факты (mcp 1.27.2):**
- Server(name, version, ...); @server.list_tools() / @server.call_tool() — декораторы без аргументов над async-функциями
- mcp.types.Tool(name, description, inputSchema); TextContent(type="text", text=...)
- mcp.server.stdio.stdio_server() → (read, write) streams; server.run(read, write, create_initialization_options())
- нет mcp.__version__ (pip показывает версию)

## День 26 — LLM-as-Judge для отчётов

**Ветка:** `feat/llm-judge` → merge commit. 368 тестов зелёные (+11).

**Коммиты:**
1. judge.py — JudgeVerdict (pydantic) + VERDICT_SCHEMA (flat, OpenAI-strict-friendly) + judge_report() + _collect_evidence + _judge_model контекст-менеджер
2. ReportAgent: use_judge флаг → judge_report(md, session, llm), verdict в kb + Markdown-блок «Report Validation», judge_verdict в return
3. Finding.confidence: float=1.0 (scan_session.py, НЕ types.py — план неточен) + отрисовка <1.0 с ⚠ в markdown_renderer + config-флаги use_judge/judge_threshold/judge_model
4. test_judge.py — 11 тестов (галлюцинация CVE-9999, clean, threshold-авторитет, graceful×2, evidence-сериализация+truncate, model-swap×3, clamp)

**Решения:**
- Модель судьи: `_judge_model` контекст-менеджер временно подменяет `llm.config.model` на judge_model (try/finally restore). НЕ трогал `structured_call` контракт дня 20 — он берёт model из config.
- threshold авторитетен: `verdict.supported` пересчитывается из score, НЕ доверяем модельному `supported` (LLM может соврать).
- Retry-семантика честная: детерминированный md НЕ перегенерируется (он не из LLM). Judge даёт verdict-пометку; реальный retry осмыслен только для use_llm_summary пути.
- graceful везде: llm=None / structured_call raise → verdict score=0.0 supported=True notes="unavailable". Отчёт НИКОГДА не падает из-за судьи.

**Грабли (снова pydantic):**
- `Field(ge=0.0, le=1.0)` + `field_validator` (after) → Field-констрейнт бьёт ПЕРВЫМ, на 1.5 ValidationError, clamp не успевает. Тест поймал.
- Фикс: убрал ge/le из Field, валидатор `mode="before"` → clamp срабатывает ДО типовой проверки. LLM вернул 1.2 → зажимается в 1.0, не роняет. Урок: для graceful-clamp использовать `mode="before"` БЕЗ Field-границ, иначе констрейнт конфликтует с валидатором.

## День 27 — HackerOne/Bugcrowd scope import

**Ветка:** `feat/bb-scope-import` → merge commit. 387 тестов зелёные (+19).

**Коммиты:**
1. import_h1_scope — H1 structured_scopes JSON (envelope {data:[]} или bare list), asset_type фильтр (URL/WILDCARD/CIDR scannable, *_APP_ID/OTHER skip), URL→host нормализация, eligible_for_submission→in/out. ScopeImport dataclass + CLI scope-группа.
2. import_bugcrowd_scope — 3 формата (target_groups / flat list / in_scope+out_of_scope), category-фильтр (website/api scannable). CLI dispatch h1|bugcrowd.
3. safety_validator: вынесен _matches_entry + _split_scope, _target_in_scope теперь exclusion-aware (!host бьёт раньше allow). Wildcard минус подсети — как в реальных брифах.
4. test_scope_matching.py — 19 тестов (matches/split/exclusions/CIDR-exclusion/H1-envelope+bare/Bugcrowd×3 форматов).

**Решения:**
- Локальный JSON-файл, НЕ живой API. Graceful-паттерн проекта (etherscan/searchsploit). Багхантер делает `curl H1-API > scope.json` сам, парсер ест выгрузку. Формат H1/Bugcrowd сверен веб-поиском (structured_scopes attributes, target_groups).
- Выход парсера = list[str] (формат authorized_scope, реально едет в session/orchestrator/safety_validator). НЕ трогал параллельную ScopeConfig-систему (core/safety.py) — незачем плодить связи.
- Exclusions в той системе что РЕАЛЬНО дёргает orchestrator (_target_in_scope), не в легаси ScopeValidator.

**Процессный косяк (зафиксировать):**
- sed-правка (удаление unused `import pytest`) сделана ПОСЛЕ финального гейта и коммита, не до. Обошлось (удаление безвредно, перепроверил 19 зелёных), но нарушило флоу гейт→коммит. Правило: любые правки файла (sed/ручные) — ДО финального гейта.
- ruff check cyberai/ не цепляет tests/ — unused import в тесте не ловится автоматом, надо вручную.

## День 28 — Web dashboard (минимальный, v0.5.0)

**Ветка:** `feat/web-dashboard` → merge commit (PR #33). 395 тестов зелёные (+8). Закрывает неделю 4.

**Коммиты:**
1. FastAPI backend (app.py Flask→FastAPI; routes/session.py + report.py read-only с диска) + deps fastapi/uvicorn + 8 TestClient тестов
2. dashboard.html — htmx+alpinejs, single-file, CDN, без билда
3. docs/journal/week-4.md — рефлексия недели 4
4. bump 0.5.0 + CHANGELOG секция

**Расхождения план vs реальность:**
- Старый web/ был на Flask и МЁРТВЫЙ: session.py импортил несуществующий `cyberai.core.pipeline.AsyncPipeline` (реальный класс — `AsyncOrchestrator`), in-memory `_sessions` store расходился с диском. CI его не покрывал → тихо гнил. Переписал целиком на FastAPI.
- План дробил SSE в отдельный коммит 2 (routes/session.py). По факту SSE-эндпоинт логически принадлежит session-роутеру → написал+протестировал в коммите 1. Коммиты переназначены (схема C): 1=backend+SSE, 2=dashboard, 3=journal, 4=bump. План = карта, не контракт.
- Дашборд читает session_*.json С ДИСКА (единый источник правды с CLI replay), НЕ из памяти. /sessions/{id}/report резолвит путь через kb report.markdown_path, не через имя файла (report-agent не кладёт session_id в имя отчёта).

**Решения:**
- SSE на голом `StreamingResponse` (media_type text/event-stream), НЕ sse-starlette (хоть и стоит 3.4.4) — минус один pin. Поллит файл, шлёт phase-дельты до terminal state.
- state на диске = lowercase ("completed") — terminal-set сравнивается через `.lower()`. Поймал разведкой ДО гейта (иначе SSE крутился бы до timeout).
- kb keys=[] у dry-run сессий → /report возвращает 404 graceful (no report).
- Path-traversal guard: report должен резолвиться внутри output_dir (relative_to).

**Уроки:**
- **Мёртвый публичный интерфейс без тестов = тихо гниющий код.** Flask-web никто не дёргал, импорты били несуществующий API, никто не замечал. Теперь web покрыт 8 тестами, CI его держит.
- Разведка shape ДО написания роутов окупилась: phases[].phase (не .name), state lowercase, kb-wrap value+meta — всё сверено по реальному session_*.json, не по памяти.

**📌 Неделя 4 закрыта.** 395 тестов. Дальше — дни 29-30: docs sprint + release v1.0.0.

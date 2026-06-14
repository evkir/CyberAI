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

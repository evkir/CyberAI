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

# Week 2 — рабочие заметки

## День 8 — pydantic schemas
- Отступление от плана: план просил `run() -> ReconResult`. По факту `run()`
  возвращает статус-словарь для orchestrator, данные — в kb. Менять контракт
  = рефактор orchestrator (день 9) + слом 4 тест-файлов.
- Решение: агенты СТРОЯТ pydantic-модели и кладут в kb как `*.result`.
  Суть дня 8 (валидируемые модели вместо dict) выполнена.
- Backlog: ChainStep в chain_builder.py остался dataclass — не перенесён в pydantic.
- Backlog: report-агент без pydantic-схемы (план дня 8 его не включал).

## День 9 — injection detector в пайплайне
- "Флаг в session" реализован через add_finding(Severity.MEDIUM), а не новым
  полем ScanSession — инъекция в выводе фазы это security-находка, видна в отчёте.
- Паттерны: из 5 пунктов плана 2 уже были покрыты (ignore previous, you are now);
  добавлены только новые — encoded_payload, unicode_escape, bidi-controls. 33 паттерна.
- Уточнение к плану: "unicode-смайлы как escape" реализовано как bidi-control
  символы (Trojan Source), это точнее — опасны управляющие символы, не смайлы.

## День 10 — nmap safety + кэш
- Command injection классическая отсутствовала: subprocess вызывается списком
  argv (shell=False), target уходит единым токеном. Whitelist флагов чинит
  реальный риск — abuse флагов (-oN, --script), не RCE. Описано честно.
- Кэш: использован существующий FileCache (файлы + TTL), НЕ новый SQLite —
  план просил SQLite, но FileCache функционально эквивалентен и уже готов.
- nmap_wrapper.py удалён как мёртвый код (run_nmap_safe никто не импортировал),
  "мердж" свёлся к удалению — в nmap_tool лучшие парсеры (XML vs текст).
- Провальные сканы (rc != 0) не кэшируются — иначе сбой залипнет на час.

## День 11 — EPSS integration
- EPSS client: httpx + FileCache (per-CVE, 24h TTL). HTTP-сбой → silent 0.0,
  pipeline переживёт outage api.first.org.
- Отступление от плана: "EPSS как multiplier" реализовано как нелинейный
  boost в существующей АДДИТИВНОЙ формуле (epss>0.5 → boost=2.0), а не
  переписыванием формулы на cvss*(1+epss)*exploit. Причина: переписать =
  ломать семантику severity_tier и весов; цель плана (EPSS реально тащит
  наверх) достигается boost'ом. Веса перебалансированы: CVSS 0.45→0.35,
  RECENCY 0.15→0.10, EPSS 0.10→0.25. Сумма = 1.0 сохранена.
- Эмодзи 🔥/⚠ в reasoning по порогам EPSS — это и есть визуальный сигнал
  плана, не часть формулы.
- Log4Shell (CVE-2021-44228, EPSS 0.974) тестово выходит топом перед
  CVE-2019-OLD (CVSS 9.0, EPSS 0.02) — суть EPSS работает.
- nvd_client пока без кэша — заметка на будущее (день 12 правит NVD,
  возможно туда зайдёт).

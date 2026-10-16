# config/

Входные настройки прогонов. Здесь лежат зафиксированные файлы, которые читает `matcher`; результаты прогонов лежат в `results/`.

- **`backends.json`** — выбор движка для отдельных правил: `{"номер строки в nmap-service-probes": "движок"}`.
  - Правила, которых нет в файле, проверяет Go.
  - Сейчас записано 13 правил: 6 на RE2 и 7 на Rust regex (`rure`).
  - Получен командой `matcher calibrate -engines go,re2,rure -sample 50000 -offset 1` на Apple M4 и добавлен в коммите `22ee3b6`. Правила выбора — в `docs/DECISIONS.md` (D18).
  - Используется флагом `-backends config/backends.json`, вместе с `-excluded pcre2` это основная конфигурация README и `scripts/run.sh`.
  - Пересоздать: `bin/matcher calibrate -engines go,re2,rure -sample 50000 -offset 1` — по умолчанию пишет сюда. `scripts/run.sh` калибрует сам, только если файла нет.

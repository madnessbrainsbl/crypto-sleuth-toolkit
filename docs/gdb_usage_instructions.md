# 🔧 ИНСТРУКЦИЯ ПО ИСПОЛЬЗОВАНИЮ GDB ДЛЯ АНАЛИЗА

## Быстрый старт:
```bash
gdb ./unlock
(gdb) source gdb_crypto_script.txt
(gdb) run eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw
```

## Команды во время анализа:
- `dump_crypto_buffers` - показать все буферы
- `dump_strings_around_rdi` - найти строки в памяти
- `search_hmac_constants` - поиск HMAC констант
- `monitor_case3_flag` - проверить флаг case 3

## Продвинутый анализ:
```bash
(gdb) source gdb_advanced_commands.txt
(gdb) trace_jwt_parsing
(gdb) extract_all_strings
(gdb) watch_memory_changes
```

## Важные breakpoint-ы:
- 0x0010d54c - crypto_handler_1 (case 3, true)
- 0x0010d5c4 - crypto_handler_2 (case 3, false) 
- 0x00109ac4 - crypto_handler_3 (other, true)
- 0x0010d8e4 - crypto_handler_4 (other, false)
- 0x00103994 - основной парсер

## Поиск ключа:
1. Запустите с рабочим токеном
2. Дождитесь срабатывания breakpoint-ов
3. Изучите память в окрестности функций
4. Ищите строки и константы
5. Особое внимание на case 3 (проверка флага +0x5c90)

## Полезные команды:
- `x/100s $rdi` - строки от адреса
- `x/100x $rdi` - hex дамп памяти
- `find $rdi, $rdi+0x10000, "string"` - поиск строки
- `info proc mappings` - карта памяти
- `generate-core-file dump.core` - создать дамп

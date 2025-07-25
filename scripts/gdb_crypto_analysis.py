#!/usr/bin/env python3
"""
Генератор GDB скриптов для анализа криптографических функций
Автоматизирует создание breakpoint-ов и команд мониторинга
"""

# Адреса из декомпилированной функции FUN_00103994
CRYPTO_FUNCTIONS = {
    0x0010d54c: "crypto_handler_1_case3_true", 
    0x0010d5c4: "crypto_handler_2_case3_false",
    0x00109ac4: "crypto_handler_3_other_true",
    0x0010d8e4: "crypto_handler_4_other_false"
}

MEMORY_OFFSETS = {
    0x5db4: "main_data_buffer",
    0x142c: "alt_buffer", 
    0x5430: "magic_buffer_0x800",
    0x5d00: "data_pointer",
    0x5d20: "data_size",
    0x18: "context_pointer",
    0x5c90: "status_flag"
}

MAIN_PARSER_FUNC = 0x00103994

def generate_gdb_script():
    """Генерирует GDB скрипт для анализа"""
    script = []
    
    script.append("# GDB скрипт для анализа криптографических функций")
    script.append("# Автоматически сгенерирован для поиска SECRET_KEY")
    script.append("")
    script.append("# Запуск: gdb ./unlock")
    script.append("# (gdb) source gdb_crypto_script.txt")
    script.append("")
    
    # Установка breakpoint-ов на все криптофункции
    script.append("# ========== BREAKPOINTS НА КРИПТОФУНКЦИИ ==========")
    for addr, name in CRYPTO_FUNCTIONS.items():
        script.append(f"break *0x{addr:x}")
        script.append(f"commands")
        script.append(f'printf "\\n🎯 HIT: {name} at 0x{addr:x}\\n"')
        script.append("info registers")
        script.append("bt 5")  # Показать 5 кадров стека
        script.append("printf \"Arguments:\\n\"")
        script.append("info args") 
        script.append("printf \"\\nMemory dump around RDI (param_1):\\n\"")
        script.append("x/32x $rdi")
        script.append("printf \"\\nContinuing...\\n\"")
        script.append("continue")
        script.append("end")
        script.append("")
    
    # Breakpoint на основной парсер
    script.append("# ========== BREAKPOINT НА ОСНОВНОЙ ПАРСЕР ==========")
    script.append(f"break *0x{MAIN_PARSER_FUNC:x}")
    script.append("commands")
    script.append(f'printf "\\n🔍 HIT: Main parser FUN_00103994\\n"')
    script.append("printf \"Parameters:\\n\"")
    script.append("printf \"  param_1 (RDI): 0x%lx\\n\", $rdi")
    script.append("printf \"  param_2 (RSI): 0x%lx\\n\", $rsi") 
    script.append("printf \"  param_3 (RDX): %lu\\n\", $rdx")
    
    # Мониторинг критических буферов
    script.append("printf \"\\nCritical memory areas:\\n\"")
    for offset, name in MEMORY_OFFSETS.items():
        script.append(f'printf "  {name} (+0x{offset:x}): "')
        script.append(f"x/8x $rdi+0x{offset:x}")
    
    script.append("continue")
    script.append("end")
    script.append("")
    
    # Функции для интерактивного анализа
    script.append("# ========== ПОЛЬЗОВАТЕЛЬСКИЕ ФУНКЦИИ ==========")
    
    script.append("define dump_crypto_buffers")
    script.append("printf \"\\n📊 DUMP CRYPTO BUFFERS:\\n\"")
    for offset, name in MEMORY_OFFSETS.items():
        script.append(f'printf "\\n{name} (+0x{offset:x}):\\n"')
        script.append(f"x/32x $rdi+0x{offset:x}")
    script.append("end")
    script.append("")
    
    script.append("define dump_strings_around_rdi")
    script.append("printf \"\\n🔤 STRINGS AROUND RDI:\\n\"")
    script.append("x/20s $rdi-1000")
    script.append("x/20s $rdi")
    script.append("x/20s $rdi+1000")
    script.append("end")
    script.append("")
    
    script.append("define search_hmac_constants")
    script.append("printf \"\\n🔍 SEARCHING FOR HMAC CONSTANTS:\\n\"")
    script.append("# Поиск HMAC padding (0x36 и 0x5c)")
    script.append("find $rdi, $rdi+0x10000, 0x36363636")
    script.append("find $rdi, $rdi+0x10000, 0x5c5c5c5c") 
    script.append("# Поиск SHA-256 констант")
    script.append("find $rdi, $rdi+0x10000, 0x6a09e667")
    script.append("find $rdi, $rdi+0x10000, 0xbb67ae85")
    script.append("end")
    script.append("")
    
    script.append("define monitor_case3_flag")
    script.append(f"printf \"\\n🚨 CASE 3 FLAG MONITOR:\\n\"")
    script.append(f"printf \"Status flag (+0x5c90): \"")
    script.append(f"x/w $rdi+0x5c90")
    script.append(f"if (*(int*)($rdi+0x5c90) == 0)")
    script.append(f'printf "⚠️  FLAG IS ZERO - CASE 3 CONDITION MET!\\n"')
    script.append("else")
    script.append('printf "✅ Flag is non-zero\\n"')
    script.append("end")
    script.append("end")
    script.append("")
    
    # Команды запуска
    script.append("# ========== КОМАНДЫ ЗАПУСКА ==========")
    script.append("printf \"\\n🚀 GDB CRYPTO ANALYSIS LOADED\\n\"")
    script.append("printf \"Available commands:\\n\"")
    script.append("printf \"  dump_crypto_buffers - дамп всех буферов\\n\"")
    script.append("printf \"  dump_strings_around_rdi - поиск строк\\n\"") 
    script.append("printf \"  search_hmac_constants - поиск HMAC констант\\n\"")
    script.append("printf \"  monitor_case3_flag - проверка флага case 3\\n\"")
    script.append("printf \"\\nTo start analysis, run with working token:\\n\"")
    script.append('printf "  run eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw\\n"')
    script.append("")
    
    return "\n".join(script)

def generate_advanced_gdb_commands():
    """Генерирует продвинутые GDB команды для глубокого анализа"""
    commands = []
    
    commands.append("# ========== ПРОДВИНУТЫЕ КОМАНДЫ ==========")
    commands.append("")
    
    commands.append("define trace_jwt_parsing")
    commands.append("printf \"\\n🔄 TRACING JWT PARSING:\\n\"")
    commands.append("# Отслеживание всех вызовов функций")
    commands.append("set logging on") 
    commands.append("set logging file jwt_trace.log")
    commands.append("set trace-commands on")
    
    # Отслеживание строковых операций
    commands.append("catch syscall write")
    commands.append("catch syscall read")
    commands.append("catch call memcpy")
    commands.append("catch call strcmp")
    commands.append("catch call strncmp")
    
    commands.append("continue")
    commands.append("end")
    commands.append("")
    
    commands.append("define extract_all_strings")
    commands.append("printf \"\\n📝 EXTRACTING ALL STRINGS FROM MEMORY:\\n\"")
    commands.append("dump memory memory_dump.bin $rdi-10000 $rdi+50000")
    commands.append("shell strings memory_dump.bin > extracted_strings.txt")
    commands.append("shell grep -E \"(key|secret|token|cunba|unlock|hmac|jwt)\" extracted_strings.txt")
    commands.append("end")
    commands.append("")
    
    commands.append("define watch_memory_changes")
    commands.append("printf \"\\n👁️  WATCHING MEMORY CHANGES:\\n\"")
    for offset, name in MEMORY_OFFSETS.items():
        commands.append(f"watch *(long*)($rdi+0x{offset:x})")
    commands.append("continue")
    commands.append("end")
    commands.append("")
    
    return "\n".join(commands)

def create_gdb_files():
    """Создает все необходимые GDB файлы"""
    
    # Основной скрипт
    basic_script = generate_gdb_script()
    with open("gdb_crypto_script.txt", "w", encoding="utf-8") as f:
        f.write(basic_script)
    
    # Продвинутые команды
    advanced_commands = generate_advanced_gdb_commands()
    with open("gdb_advanced_commands.txt", "w", encoding="utf-8") as f:
        f.write(advanced_commands)
    
    # Инструкция по использованию
    usage_instructions = """# 🔧 ИНСТРУКЦИЯ ПО ИСПОЛЬЗОВАНИЮ GDB ДЛЯ АНАЛИЗА

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
"""
    
    with open("gdb_usage_instructions.md", "w", encoding="utf-8") as f:
        f.write(usage_instructions)
    
    print("✅ Созданы GDB файлы:")
    print("  📄 gdb_crypto_script.txt - основной скрипт")
    print("  📄 gdb_advanced_commands.txt - продвинутые команды")
    print("  📄 gdb_usage_instructions.md - инструкция")
    print("\n🚀 Для запуска:")
    print("  gdb ./unlock")
    print("  (gdb) source gdb_crypto_script.txt")

if __name__ == "__main__":
    print("🔧 ГЕНЕРАЦИЯ GDB СКРИПТОВ ДЛЯ АНАЛИЗА КРИПТОФУНКЦИЙ")
    print("="*60)
    create_gdb_files()

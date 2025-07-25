#!/usr/bin/env python3
"""
Поиск строк в бинарнике в области криптографических функций
"""

import jwt
import struct
import re

# Рабочий токен
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

def test_key(key):
    """Тестирование ключа"""
    try:
        decoded = jwt.decode(WORKING_TOKEN, key, algorithms=["HS256"])
        print(f"\n✓✓✓ НАЙДЕН КЛЮЧ: '{key}'")
        if isinstance(key, bytes):
            print(f"Hex: {key.hex()}")
            try:
                print(f"ASCII: {key.decode('ascii')}")
            except:
                pass
        print(f"Payload: {decoded}")
        return True
    except:
        return False

def find_strings_near_address(data, base_offset, window_size=0x2000):
    """Поиск строк вокруг заданного адреса"""
    strings_found = []
    
    # ASCII строки
    ascii_pattern = rb'[\x20-\x7E]{4,}'
    matches = re.finditer(ascii_pattern, data)
    
    for match in matches:
        string_data = match.group()
        string_offset = match.start()
        
        # Фильтруем слишком длинные строки и мусор
        if 4 <= len(string_data) <= 64:
            try:
                decoded = string_data.decode('ascii', errors='ignore')
                # Исключаем пути и очевидный мусор
                if not any(x in decoded for x in ['/', '\\', '.so', '.dll', 'lib']):
                    strings_found.append((string_offset, decoded, string_data))
            except:
                pass
    
    return strings_found

def search_for_jwt_key():
    """Поиск JWT ключа в бинарнике"""
    print("=== Поиск JWT ключа в области криптографических функций ===\n")
    
    try:
        with open('unlock', 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print("Файл 'unlock' не найден!")
        return
    
    # Адреса криптографических функций
    crypto_addresses = {
        0x0010d54c: "FUN_0010d54c",
        0x0010d5c4: "FUN_0010d5c4", 
        0x00109ac4: "FUN_00109ac4",
        0x0010d8e4: "FUN_0010d8e4",
        0x00109d04: "FUN_00109d04",
        0x0010bd84: "FUN_0010bd84"
    }
    
    all_candidates = []
    
    # Ищем строки вокруг каждой функции
    for addr, func_name in crypto_addresses.items():
        print(f"\nПоиск вокруг {func_name} (0x{addr:08x}):")
        
        # Предполагаем базовый адрес загрузки 0x100000
        file_offset = addr - 0x100000 if addr > 0x100000 else addr
        
        # Окно поиска
        window_size = 0x2000
        start = max(0, file_offset - window_size)
        end = min(len(data), file_offset + window_size)
        
        window_data = data[start:end]
        strings = find_strings_near_address(window_data, start)
        
        print(f"  Найдено {len(strings)} строк")
        
        # Добавляем найденные строки как кандидаты
        for offset, decoded, raw in strings:
            all_candidates.append(decoded)
            all_candidates.append(raw)
            
            # Также пробуем варианты
            all_candidates.append(decoded.lower())
            all_candidates.append(decoded.upper())
    
    # Дополнительные кандидаты на основе известной информации
    print("\n\nДобавляем специфичные кандидаты...")
    
    # Комбинации с "cunba"
    cunba_variants = [
        "cunba", "CunBA", "CUNBA", "Cunba",
        "cunba_secret", "CunBA_secret", "cunba_key", "CunBA_key",
        "cunba123", "CunBA123", "cunba_jwt", "CunBA_jwt"
    ]
    all_candidates.extend(cunba_variants)
    
    # Варианты с mega/platform
    mega_variants = [
        "mega", "MEGA", "Mega",
        "megaplatform", "MegaPlatform", "MEGAPLATFORM",
        "mega_a11", "MEGA_A11", "mega_platform", "MEGA_PLATFORM",
        "platform_a11", "PLATFORM_A11", "a11_platform", "A11_PLATFORM"
    ]
    all_candidates.extend(mega_variants)
    
    # QNX специфичные
    qnx_variants = [
        "qnx_secret", "QNX_SECRET", "qnx_key", "QNX_KEY",
        "huron_key", "HURON_KEY", "huron_secret", "HURON_SECRET"
    ]
    all_candidates.extend(qnx_variants)
    
    # Простые варианты ключей
    simple_keys = [
        "secret123", "Secret123", "SECRET123",
        "password123", "Password123", "PASSWORD123",
        "unlock123", "Unlock123", "UNLOCK123",
        "jwt_secret", "JWT_SECRET", "jwt_key", "JWT_KEY",
        "hmac_key", "HMAC_KEY", "hmac_secret", "HMAC_SECRET"
    ]
    all_candidates.extend(simple_keys)
    
    # Убираем дубликаты
    unique_candidates = list(set(str(c) if isinstance(c, str) else c for c in all_candidates))
    
    print(f"\nВсего уникальных кандидатов: {len(unique_candidates)}")
    print("\nТестирование ключей...")
    
    found = False
    for i, candidate in enumerate(unique_candidates):
        if i % 50 == 0 and i > 0:
            print(f"  Протестировано {i}/{len(unique_candidates)}...")
        
        if test_key(candidate):
            found = True
            with open('FOUND_JWT_KEY.txt', 'w') as f:
                f.write(f"JWT KEY: {candidate}\n")
                f.write(f"Type: {type(candidate)}\n")
                if isinstance(candidate, bytes):
                    f.write(f"Hex: {candidate.hex()}\n")
                f.write(f"Token: {WORKING_TOKEN}\n")
            break
    
    if not found:
        print("\n✗ Ключ не найден")
        print("\nРекомендации для поиска ключа на устройстве:")
        print("\n1. Используйте GDB на устройстве:")
        print("   gdb ./unlock")
        print("   b *0x10d5c4")
        print("   run")
        print("   # Когда остановится, изучите регистры и память")
        print("   info registers")
        print("   x/32xb $x5  # если param_5 в регистре x5")
        print("\n2. Ищите в памяти во время выполнения:")
        print("   # Запустите unlock и найдите его PID")
        print("   cat /proc/[PID]/maps")
        print("   # Дампите память процесса")
        print("   gdb -p [PID]")
        print("   dump memory unlock.dump 0x100000 0x200000")
        print("\n3. Проверьте переменные окружения:")
        print("   strings /proc/[PID]/environ")
        print("\n4. Ключ может быть в конфигурационном файле или прошивке")

if __name__ == "__main__":
    search_for_jwt_key()

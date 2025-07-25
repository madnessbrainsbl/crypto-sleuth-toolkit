#!/usr/bin/env python3
"""
Специализированный анализатор для поиска JWT ключа в декомпилированных функциях
Основан на анализе FUN_0010d54c, FUN_0010d5c4, FUN_00109ac4, FUN_0010d8e4
"""

import struct
import hashlib
import hmac
import jwt
import json
from datetime import datetime

# Рабочий токен
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

# Анализ адресов из кода
CRYPTO_ADDRESSES = {
    0x0010d54c: "FUN_0010d54c - case 3 crypto handler",
    0x0010d5c4: "FUN_0010d5c4 - case 3 crypto with memcpy", 
    0x00109ac4: "FUN_00109ac4 - main crypto processor",
    0x0010d8e4: "FUN_0010d8e4 - conditional crypto",
    0x00109d04: "FUN_00109d04 - main decoder",
    0x0010bd84: "FUN_0010bd84 - alternative decoder",
    0x002791f4: "DAT_002791f4 - crypto lookup table"
}

def analyze_binary_for_keys():
    """Анализ бинарника для поиска ключей"""
    keys_found = []
    
    try:
        with open('unlock', 'rb') as f:
            data = f.read()
        
        # Поиск в окрестностях криптографических функций
        for addr, desc in CRYPTO_ADDRESSES.items():
            print(f"\nАнализ {desc} по адресу 0x{addr:08x}")
            
            # Конвертируем адрес в файловое смещение (предполагаем загрузку с 0x100000)
            if addr > 0x100000:
                file_offset = addr - 0x100000
            else:
                file_offset = addr
                
            # Ищем строки и данные вокруг адреса
            window_size = 0x1000  # 4KB окно
            start = max(0, file_offset - window_size)
            end = min(len(data), file_offset + window_size)
            
            window_data = data[start:end]
            
            # Поиск строк
            strings = extract_strings_from_bytes(window_data, min_length=4)
            for s in strings:
                if is_potential_key(s):
                    print(f"  Потенциальный ключ-строка: {s}")
                    keys_found.append(s)
            
            # Поиск последовательностей байт, похожих на ключи
            for i in range(0, len(window_data) - 32, 4):
                key_candidate = window_data[i:i+32]
                if is_valid_key_pattern(key_candidate):
                    hex_key = key_candidate.hex()
                    print(f"  Потенциальный бинарный ключ: {hex_key}")
                    keys_found.append(hex_key)
                    keys_found.append(key_candidate)
    
    except Exception as e:
        print(f"Ошибка при чтении бинарника: {e}")
    
    return keys_found

def extract_strings_from_bytes(data, min_length=4):
    """Извлечение ASCII строк из байтов"""
    strings = []
    current = []
    
    for byte in data:
        if 32 <= byte <= 126:  # Печатаемые ASCII символы
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append(''.join(current))
            current = []
    
    if len(current) >= min_length:
        strings.append(''.join(current))
    
    return strings

def is_potential_key(s):
    """Проверка, может ли строка быть ключом"""
    # Ключ должен быть достаточной длины и содержать разнообразные символы
    if len(s) < 8 or len(s) > 256:
        return False
    
    # Проверяем энтропию
    unique_chars = len(set(s))
    if unique_chars < len(s) * 0.5:  # Слишком мало уникальных символов
        return False
    
    # Исключаем очевидные не-ключи
    if s.startswith('/') or s.startswith('.') or ' ' in s:
        return False
    
    return True

def is_valid_key_pattern(data):
    """Проверка, похожи ли байты на криптографический ключ"""
    if len(data) < 16:
        return False
    
    # Проверяем энтропию
    unique_bytes = len(set(data))
    if unique_bytes < len(data) * 0.3:  # Слишком мало уникальных байт
        return False
    
    # Проверяем, не все ли байты нулевые или FF
    if all(b == 0 for b in data) or all(b == 0xFF for b in data):
        return False
    
    return True

def test_key(key):
    """Тестирование ключа с рабочим токеном"""
    try:
        if isinstance(key, str):
            # Пробуем как строку
            decoded = jwt.decode(WORKING_TOKEN, key, algorithms=["HS256"])
            print(f"\n✓ НАЙДЕН КЛЮЧ (строка): {key}")
            return True
        else:
            # Пробуем как байты
            decoded = jwt.decode(WORKING_TOKEN, key, algorithms=["HS256"])
            print(f"\n✓ НАЙДЕН КЛЮЧ (байты): {key.hex()}")
            return True
    except:
        return False

def analyze_lookup_table():
    """Анализ таблицы DAT_002791f4 из кода"""
    print("\nАнализ lookup таблицы DAT_002791f4...")
    
    # Из кода видно, что используется как таблица умножения
    # Попробуем различные комбинации
    table_values = [0x01, 0x00, 0x00, 0x00]  # Из декомпиляции
    
    # Генерируем ключи на основе таблицы
    keys = []
    
    # Простой ключ из значений таблицы
    keys.append(bytes(table_values * 8))  # 32 байта
    
    # Ключ с применением XOR
    for xor_val in [0x5A, 0xA5, 0xFF, 0x42]:
        key = bytes([v ^ xor_val for v in table_values] * 8)
        keys.append(key)
    
    return keys

def analyze_qnx_specific():
    """QNX-специфичные ключи"""
    print("\nГенерация QNX-специфичных ключей...")
    
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    timestamp = 1753096202
    
    keys = []
    
    # Комбинации с vehicle_id
    keys.append(vehicle_id)
    keys.append(vehicle_id.upper())
    keys.append(vehicle_id[:16])
    keys.append(vehicle_id[-16:])
    
    # Комбинации с timestamp
    keys.append(str(timestamp))
    keys.append(f"CunBA_{timestamp}")
    keys.append(f"{timestamp}_CunBA")
    
    # MD5/SHA хеши
    keys.append(hashlib.md5(vehicle_id.encode()).hexdigest())
    keys.append(hashlib.sha256(vehicle_id.encode()).hexdigest())
    keys.append(hashlib.md5(f"{vehicle_id}_{timestamp}".encode()).hexdigest())
    
    # Комбинации с магическими числами из кода
    magic_values = ["0x40", "0x3f", "0x41", "0xffffffffffffff88"]
    for magic in magic_values:
        keys.append(f"{vehicle_id}_{magic}")
        keys.append(hashlib.md5(f"{vehicle_id}_{magic}".encode()).digest())
    
    return keys

def main():
    print("=== Поиск JWT ключа на основе декомпилированного кода ===")
    
    all_keys = []
    
    # 1. Анализ бинарника в окрестностях криптофункций
    print("\n1. Анализ бинарника...")
    binary_keys = analyze_binary_for_keys()
    all_keys.extend(binary_keys)
    
    # 2. Анализ lookup таблицы
    print("\n2. Анализ lookup таблицы...")
    table_keys = analyze_lookup_table()
    all_keys.extend(table_keys)
    
    # 3. QNX-специфичные ключи
    print("\n3. QNX-специфичные ключи...")
    qnx_keys = analyze_qnx_specific()
    all_keys.extend(qnx_keys)
    
    # 4. Ключи на основе адресов функций
    print("\n4. Ключи на основе адресов...")
    for addr in CRYPTO_ADDRESSES.keys():
        all_keys.append(f"0x{addr:08x}")
        all_keys.append(struct.pack("<I", addr))
        all_keys.append(struct.pack(">I", addr))
    
    # Тестируем все ключи
    print(f"\n\nТестирование {len(all_keys)} ключей...")
    tested = set()
    found = False
    
    for i, key in enumerate(all_keys):
        if key in tested:
            continue
        tested.add(str(key))
        
        if i % 100 == 0:
            print(f"  Протестировано {i}/{len(all_keys)}...")
        
        if test_key(key):
            found = True
            break
    
    if not found:
        print("\n✗ Ключ не найден среди сгенерированных кандидатов")
        print("\nРекомендации:")
        print("1. Используйте Ghidra для детального анализа функций")
        print("2. Проверьте param_5 в отладчике - это указатель на структуру с ключом")
        print("3. Поставьте breakpoint на 0x0010d5c4 и посмотрите память")
        print("4. Ключ может генерироваться динамически из системных данных")

if __name__ == "__main__":
    main()

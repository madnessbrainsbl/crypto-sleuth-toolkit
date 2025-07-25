#!/usr/bin/env python3
"""
JWT Secret Key Finder
Ищет секретный ключ для JWT токена используя различные подходы
"""

import jwt
import hashlib
import hmac
import base64
import itertools
from datetime import datetime

# Рабочий токен
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

# Известные данные
VEHICLE_ID = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
ISS = "CunBA"
TIMESTAMP = 1753096202

def verify_key(key_candidate):
    """Проверяет, подходит ли ключ"""
    try:
        decoded = jwt.decode(WORKING_TOKEN, key_candidate, algorithms=["HS256"])
        print(f"\n✅ НАЙДЕН КЛЮЧ: {key_candidate}")
        print(f"Decoded: {decoded}")
        return True
    except:
        return False

def generate_system_based_keys():
    """Генерирует ключи на основе системных данных"""
    keys = []
    
    # Базовые комбинации
    base_values = [
        "unlock", "cunba", "CunBA", "mega", "platform", "A11",
        VEHICLE_ID, ISS, str(TIMESTAMP),
        "huron", "shell", "qnx", "QNX"
    ]
    
    # Комбинации с ID
    for base in base_values:
        keys.append(base)
        keys.append(base + VEHICLE_ID)
        keys.append(VEHICLE_ID + base)
        keys.append(base + "_" + VEHICLE_ID)
        keys.append(VEHICLE_ID + "_" + base)
    
    # Хеши от комбинаций
    for key in list(keys):
        keys.append(hashlib.md5(key.encode()).hexdigest())
        keys.append(hashlib.sha1(key.encode()).hexdigest())
        keys.append(hashlib.sha256(key.encode()).hexdigest())
        
    return keys

def generate_binary_based_keys():
    """Генерирует ключи на основе анализа бинарника"""
    keys = []
    
    # Адреса функций как потенциальные ключи
    addresses = [
        "0010d54c", "0010d5c4", "00109ac4", "0010d8e4",
        "00109d04", "0010bd84", "00108448", "001095d0"
    ]
    
    for addr in addresses:
        keys.append(addr)
        keys.append("0x" + addr)
        keys.append(addr.upper())
        keys.append("FUN_" + addr)
    
    # Магические числа из кода
    magic_numbers = [
        "0x40", "0x41", "0x3f", "0xff", "0x100",
        "0xffffffffffffff88", "0xffffffffffffffec"
    ]
    
    keys.extend(magic_numbers)
    
    # Константы из DAT_
    dat_values = ["002791f4", "002791f8", "002791ec", "002791f0"]
    keys.extend(dat_values)
    
    return keys

def generate_time_based_keys():
    """Генерирует ключи на основе временных меток"""
    keys = []
    
    # Различные форматы timestamp
    ts = TIMESTAMP
    keys.extend([
        str(ts),
        hex(ts),
        hex(ts)[2:],  # без 0x
        str(ts)[:8],  # первые 8 цифр
        str(ts)[-8:], # последние 8 цифр
    ])
    
    # Даты около timestamp
    dt = datetime.fromtimestamp(ts)
    keys.extend([
        dt.strftime("%Y%m%d"),
        dt.strftime("%Y-%m-%d"),
        dt.strftime("%d%m%Y"),
        str(dt.year),
        f"{dt.year}{dt.month:02d}",
    ])
    
    return keys

def generate_pattern_based_keys():
    """Генерирует ключи на основе паттернов"""
    keys = []
    
    # Паттерны с vehicle_id
    vid = VEHICLE_ID
    keys.extend([
        vid[:8],    # первые 8 символов
        vid[-8:],   # последние 8 символов
        vid[::2],   # каждый второй символ
        vid[::-1],  # реверс
    ])
    
    # Комбинации частей
    parts = [vid[i:i+8] for i in range(0, len(vid), 8)]
    for p1, p2 in itertools.combinations(parts, 2):
        keys.append(p1 + p2)
        keys.append(p2 + p1)
    
    return keys

def brute_force_simple_keys():
    """Перебор простых ключей"""
    keys = []
    
    # Короткие ключи (числа)
    for i in range(10000):
        keys.append(str(i))
        keys.append(f"{i:04d}")
    
    # Простые слова
    simple_words = [
        "key", "secret", "password", "pass", "admin", "root",
        "mega", "unlock", "device", "token", "jwt", "hmac"
    ]
    
    for word in simple_words:
        keys.append(word)
        keys.append(word.upper())
        keys.append(word.capitalize())
        
    return keys

def main():
    print("🔍 Поиск JWT секретного ключа...")
    print(f"Токен: {WORKING_TOKEN}")
    
    all_keys = set()
    
    # Собираем все возможные ключи
    print("\n📊 Генерация кандидатов...")
    
    generators = [
        ("Системные", generate_system_based_keys),
        ("Бинарные", generate_binary_based_keys),
        ("Временные", generate_time_based_keys),
        ("Паттерны", generate_pattern_based_keys),
        ("Простые", brute_force_simple_keys),
    ]
    
    for name, generator in generators:
        keys = generator()
        print(f"  {name}: {len(keys)} ключей")
        all_keys.update(keys)
    
    print(f"\n📊 Всего уникальных кандидатов: {len(all_keys)}")
    
    # Проверяем все ключи
    print("\n🔄 Проверка ключей...")
    checked = 0
    for key in all_keys:
        if verify_key(key):
            print(f"\n🎉 УСПЕХ! Ключ найден: '{key}'")
            
            # Проверяем, можем ли мы создать свой токен
            print("\n🔧 Создание нового токена...")
            new_payload = {
                "vehicle_id": VEHICLE_ID,
                "iss": ISS,
                "timestamp": int(datetime.now().timestamp())
            }
            new_token = jwt.encode(new_payload, key, algorithm="HS256")
            print(f"Новый токен: {new_token}")
            return
        
        checked += 1
        if checked % 1000 == 0:
            print(f"  Проверено: {checked}/{len(all_keys)}")
    
    print("\n❌ Ключ не найден среди {len(all_keys)} кандидатов")
    print("\n💡 Возможные причины:")
    print("1. Ключ более сложный или длинный")
    print("2. Ключ генерируется динамически")
    print("3. Используется нестандартная реализация JWT")
    print("4. Ключ зашит в другой части бинарника")

if __name__ == "__main__":
    main()

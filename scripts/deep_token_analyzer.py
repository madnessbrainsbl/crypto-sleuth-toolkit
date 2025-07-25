#!/usr/bin/env python3
"""
Глубокий анализ рабочего JWT токена для поиска источника ключа
"""

import jwt
import json
import base64
import binascii
import hashlib
import hmac
import time
import itertools
from datetime import datetime, timezone
import string
import os
import platform
import socket

# Рабочий токен для анализа
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

def decode_token_completely():
    """Полное декодирование токена"""
    print("🔍 ПОЛНЫЙ АНАЛИЗ РАБОЧЕГО ТОКЕНА")
    print("="*60)
    
    # Разбираем на части
    parts = WORKING_TOKEN.split('.')
    
    # Header
    header_decoded = base64.urlsafe_b64decode(parts[0] + '==')
    header = json.loads(header_decoded)
    print(f"Header: {json.dumps(header, indent=2)}")
    
    # Payload
    payload_decoded = base64.urlsafe_b64decode(parts[1] + '==')
    payload = json.loads(payload_decoded)
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    # Signature
    signature_bytes = base64.urlsafe_b64decode(parts[2] + '==')
    print(f"Signature (hex): {binascii.hexlify(signature_bytes).decode()}")
    print(f"Signature (base64): {parts[2]}")
    print(f"Signature length: {len(signature_bytes)} bytes")
    
    # Анализ временной метки
    timestamp = payload.get('timestamp', 0)
    dt = datetime.fromtimestamp(timestamp)
    print(f"Timestamp: {timestamp}")
    print(f"Human time: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"UTC time: {datetime.fromtimestamp(timestamp, tz=timezone.utc)}")
    
    return header, payload, signature_bytes

def analyze_timestamp_patterns():
    """Анализ паттернов временной метки"""
    print("\n📊 АНАЛИЗ ВРЕМЕННОЙ МЕТКИ")
    print("="*50)
    
    timestamp = 1753096202
    dt = datetime.fromtimestamp(timestamp)
    
    print(f"Базовый timestamp: {timestamp}")
    print(f"Дата и время: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Год: {dt.year}")
    print(f"Месяц: {dt.month}")  
    print(f"День: {dt.day}")
    print(f"Час: {dt.hour}")
    print(f"Минута: {dt.minute}")
    print(f"Секунда: {dt.second}")
    
    # Различные представления времени
    time_variants = [
        str(timestamp),
        str(timestamp)[:10],  # Первые 10 цифр
        str(timestamp)[-6:],  # Последние 6 цифр
        hex(timestamp)[2:],   # Hex без 0x
        str(dt.year),
        f"{dt.year}{dt.month:02d}{dt.day:02d}",
        f"{dt.hour:02d}{dt.minute:02d}{dt.second:02d}",
    ]
    
    print(f"\nВариации времени для тестирования:")
    for i, variant in enumerate(time_variants):
        print(f"  {i+1}. {variant}")
    
    return time_variants

def generate_system_based_keys():
    """Генерация ключей на основе системных данных"""
    print("\n🖥️  СИСТЕМНЫЕ ДАННЫЕ ДЛЯ КЛЮЧЕЙ")
    print("="*50)
    
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    timestamp = 1753096202
    
    system_data = {
        'vehicle_id': vehicle_id,
        'timestamp': timestamp,
        'platform': 'android',  # Известно что Android
        'arch': 'arm64',        # Qualcomm 8155
        'device': 'qualcomm8155',
        'brand': 'mega',
        'app': 'unlock',
        'issuer': 'CunBA'
    }
    
    print("Системные данные:")
    for key, value in system_data.items():
        print(f"  {key}: {value}")
    
    # Генерируем ключи-кандидаты
    key_candidates = []
    
    # 1. Простые комбинации
    simple_combinations = [
        f"{system_data['issuer']}",
        f"{system_data['issuer']}_{system_data['app']}",
        f"{system_data['app']}_{system_data['issuer']}",
        f"{system_data['issuer']}_{vehicle_id}",
        f"{system_data['issuer']}_{timestamp}",
        f"{vehicle_id}_{system_data['issuer']}",
        f"{system_data['brand']}_{system_data['app']}",
        f"{system_data['device']}_{system_data['app']}",
    ]
    key_candidates.extend(simple_combinations)
    
    # 2. Хэши системных данных
    for data in [vehicle_id, str(timestamp), system_data['issuer']]:
        key_candidates.extend([
            hashlib.md5(data.encode()).hexdigest(),
            hashlib.sha1(data.encode()).hexdigest(),
            hashlib.sha256(data.encode()).hexdigest()[:32],
            hashlib.sha256(data.encode()).hexdigest()[:16],
        ])
    
    # 3. Комбинированные хэши
    combined_data = [
        f"{vehicle_id}{timestamp}",
        f"{system_data['issuer']}{vehicle_id}",
        f"{system_data['issuer']}{timestamp}",
        f"{system_data['app']}{vehicle_id}",
    ]
    
    for data in combined_data:
        key_candidates.extend([
            hashlib.md5(data.encode()).hexdigest(),
            hashlib.sha256(data.encode()).hexdigest()[:32],
        ])
    
    print(f"\nСгенерировано {len(key_candidates)} системных ключей-кандидатов")
    return key_candidates

def brute_force_mathematical_keys():
    """Брутфорс математических преобразований"""
    print("\n🔢 МАТЕМАТИЧЕСКИЕ ПРЕОБРАЗОВАНИЯ")
    print("="*50)
    
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    timestamp = 1753096202
    
    math_keys = []
    
    # Попробуем интерпретировать vehicle_id как число
    try:
        vid_int = int(vehicle_id, 16)  # Hex to int
        print(f"Vehicle ID как число: {vid_int}")
        
        # Различные математические операции
        math_operations = [
            vid_int % 1000000,
            vid_int ^ timestamp,
            (vid_int + timestamp) % 0xFFFFFFFF,
            vid_int * 31,  # Простой хэш
            abs(hash(vehicle_id)) % 1000000,
        ]
        
        for result in math_operations:
            math_keys.append(str(result))
            math_keys.append(hex(result)[2:])
    
    except ValueError:
        pass
    
    # Операции с timestamp
    time_math = [
        timestamp ^ 0x12345678,
        timestamp + 0x1000,
        timestamp % 1000000,
        timestamp // 1000,  # Секунды в миллисекунды
    ]
    
    for result in time_math:
        math_keys.append(str(result))
    
    print(f"Сгенерировано {len(math_keys)} математических ключей")
    return math_keys

def test_key_candidates(candidates):
    """Тестирование списка кандидатов ключей"""
    print(f"\n🎯 ТЕСТИРОВАНИЕ {len(candidates)} КАНДИДАТОВ")
    print("="*50)
    
    payload = {
        "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
        "iss": "CunBA",
        "timestamp": 1753096202
    }
    
    found_keys = []
    
    for i, key in enumerate(candidates):
        if i % 1000 == 0 and i > 0:
            print(f"Протестировано {i}/{len(candidates)}...")
        
        try:
            test_token = jwt.encode(payload, key, algorithm='HS256')
            if test_token == WORKING_TOKEN:
                print(f"\n🎉 НАЙДЕН КЛЮЧ!")
                print(f"Ключ: '{key}'")
                print(f"Длина: {len(key)} символов")
                found_keys.append(key)
        except:
            continue
    
    return found_keys

def reverse_engineer_key_structure():
    """Попытка обратной инженерии структуры ключа"""
    print("\n🔬 ОБРАТНАЯ ИНЖЕНЕРИЯ КЛЮЧА")
    print("="*50)
    
    # Анализ подписи
    parts = WORKING_TOKEN.split('.')
    message = f"{parts[0]}.{parts[1]}".encode('ascii')
    target_signature = base64.urlsafe_b64decode(parts[2] + '==')
    
    print(f"Сообщение для подписи: {message.decode()}")
    print(f"Длина сообщения: {len(message)} байт")
    print(f"Целевая подпись: {binascii.hexlify(target_signature).decode()}")
    
    # Попробуем различные длины ключей
    print("\nТестирование ключей различной длины...")
    
    # Для каждой длины попробуем простые паттерны
    for key_length in [4, 8, 16, 32, 64]:
        print(f"Тестируем ключи длины {key_length}...")
        
        # Простые паттерны
        patterns = [
            'a' * key_length,
            '0' * key_length,
            '1' * key_length,
            ('CunBA' * (key_length // 5 + 1))[:key_length],
            ('unlock' * (key_length // 6 + 1))[:key_length],
        ]
        
        for pattern in patterns:
            if len(pattern) == key_length:
                signature = hmac.new(pattern.encode(), message, hashlib.sha256).digest()
                if signature == target_signature:
                    print(f"🎉 НАЙДЕН ПАТТЕРН КЛЮЧА: '{pattern}'")
                    return pattern
    
    return None

def analyze_signature_entropy():
    """Анализ энтропии подписи"""
    print("\n📈 АНАЛИЗ ЭНТРОПИИ ПОДПИСИ") 
    print("="*50)
    
    parts = WORKING_TOKEN.split('.')
    signature_bytes = base64.urlsafe_b64decode(parts[2] + '==')
    
    # Статистический анализ
    byte_counts = {}
    for byte in signature_bytes:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    print(f"Уникальных байтов в подписи: {len(byte_counts)}/32")
    print(f"Распределение байтов: {byte_counts}")
    
    # Проверим, не является ли подпись результатом простого XOR
    print("\nПроверка простых XOR паттернов...")
    vehicle_id_bytes = bytes.fromhex("0d79ff047f5cec5bf2ec2ec7d3e464ce")
    
    for i in range(min(len(vehicle_id_bytes), len(signature_bytes))):
        xor_result = signature_bytes[i] ^ vehicle_id_bytes[i]
        print(f"Байт {i}: подпись={signature_bytes[i]:02x}, vid={vehicle_id_bytes[i]:02x}, xor={xor_result:02x}")

def main():
    """Главная функция анализа"""
    print("🚀 DEEP TOKEN ANALYZER")
    print("="*80)
    print("Комплексный анализ рабочего JWT токена для поиска источника SECRET_KEY")
    print()
    
    # 1. Полный анализ токена
    header, payload, signature = decode_token_completely()
    
    # 2. Анализ временных паттернов
    time_variants = analyze_timestamp_patterns()
    
    # 3. Анализ энтропии
    analyze_signature_entropy()
    
    # 4. Генерация системных ключей
    system_keys = generate_system_based_keys()
    
    # 5. Математические преобразования
    math_keys = brute_force_mathematical_keys()
    
    # 6. Обратная инженерия структуры
    pattern_key = reverse_engineer_key_structure()
    
    # 7. Объединение всех кандидатов
    all_candidates = []
    all_candidates.extend(time_variants)
    all_candidates.extend(system_keys)
    all_candidates.extend(math_keys)
    
    if pattern_key:
        all_candidates.append(pattern_key)
    
    # Убираем дубликаты
    all_candidates = list(set(all_candidates))
    
    # 8. Финальное тестирование
    found_keys = test_key_candidates(all_candidates)
    
    if found_keys:
        print(f"\n🎉 УСПЕХ! Найдено {len(found_keys)} рабочих ключей:")
        for key in found_keys:
            print(f"  - '{key}' (длина: {len(key)})")
        
        # Создаем генератор
        main_key = found_keys[0]
        create_final_generator(main_key)
    else:
        print(f"\n😞 Ключ не найден среди {len(all_candidates)} кандидатов")
        print("💡 Рекомендации:")
        print("   1. Попробуйте динамический анализ с Frida")
        print("   2. Проанализируйте другие связанные файлы")
        print("   3. Исследуйте сетевой трафик приложения")

def create_final_generator(secret_key):
    """Создание финального генератора"""
    generator_code = f'''#!/usr/bin/env python3
"""
ФИНАЛЬНЫЙ ГЕНЕРАТОР - КЛЮЧ НАЙДЕН ЧЕРЕЗ ГЛУБОКИЙ АНАЛИЗ
"""
import jwt
from datetime import datetime

SECRET_KEY = "{secret_key}"

def generate_unlock_token(vehicle_id):
    payload = {{
        "vehicle_id": vehicle_id,
        "iss": "CunBA",
        "timestamp": int(datetime.now().timestamp())
    }}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

if __name__ == "__main__":
    import sys
    vehicle_id = sys.argv[1] if len(sys.argv) > 1 else input("Vehicle ID: ")
    token = generate_unlock_token(vehicle_id)
    print("="*80)
    print(token)
    print("="*80)
'''
    
    with open("D:/vzlom/deep_analysis_generator.py", "w", encoding="utf-8") as f:
        f.write(generator_code)
    
    print(f"\n✅ Создан deep_analysis_generator.py с найденным ключом!")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import jwt
import json
import base64
import hashlib
import hmac
import itertools
import string
from datetime import datetime
import subprocess
import os
import re

# Рабочий токен
working_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

def extract_qnx_system_info():
    """Извлекает системную информацию, которую может использовать QNX программа"""
    system_candidates = []
    
    # QNX специфичные пути и данные
    qnx_paths = [
        "/proc/cpuinfo",
        "/proc/meminfo", 
        "/proc/version",
        "/dev/shmem",
        "/data/local/tmp",
        "/system/bin"
    ]
    
    # QNX команды и свойства
    qnx_properties = [
        "ro.build.version.release",
        "ro.build.id",
        "ro.build.display.id", 
        "ro.build.product",
        "ro.product.model",
        "ro.product.brand",
        "ro.product.name",
        "ro.serialno",
        "ro.boot.serialno",
        "persist.vendor.radio.imei"
    ]
    
    # Добавляем known vehicle ID
    system_candidates.extend([
        "0d79ff047f5cec5bf2ec2ec7d3e464ce",
        "cunba",
        "CunBA", 
        "CUNBA",
        "mega",
        "platform",
        "A11",
        "qnx",
        "QNX",
        "unlock",
        "huron"
    ])
    
    return system_candidates

def generate_qnx_specific_keys(vehicle_id, timestamp):
    """Генерирует QNX-специфичные кандидаты ключей"""
    candidates = set()
    
    # Базовые QNX строки
    base_strings = extract_qnx_system_info()
    
    # Комбинации с timestamp и vehicle_id
    for base in base_strings:
        candidates.update([
            base,
            f"{base}_{vehicle_id}",
            f"{base}_{timestamp}",
            f"{vehicle_id}_{base}",
            f"{timestamp}_{base}",
            f"{base}{vehicle_id}",
            f"{base}{timestamp}",
            f"{vehicle_id}{base}",
            f"{timestamp}{base}",
            # MD5 хеши
            hashlib.md5(base.encode()).hexdigest(),
            hashlib.md5(f"{base}{vehicle_id}".encode()).hexdigest(),
            hashlib.md5(f"{base}{timestamp}".encode()).hexdigest(),
            # SHA256 хеши
            hashlib.sha256(base.encode()).hexdigest(),
            hashlib.sha256(f"{base}{vehicle_id}".encode()).hexdigest(),
            hashlib.sha256(f"{base}{timestamp}".encode()).hexdigest(),
        ])
    
    # Специфичные для автомобильных систем
    automotive_keys = [
        "VIN", "ECU", "CAN", "OBD", "TCU", "BCM", "PCM",
        "mega_platform_A11", "cunba_unlock_key", "qnx_automotive",
        f"vehicle_{vehicle_id}", f"ecu_{vehicle_id}",
        "unlock_secret_key", "automotive_jwt_key"
    ]
    
    candidates.update(automotive_keys)
    
    # Конвертируем в список и добавляем байтовые версии
    result = []
    for candidate in candidates:
        if isinstance(candidate, str):
            result.append(candidate)
            result.append(candidate.encode('utf-8'))
            result.append(candidate.encode('ascii', errors='ignore'))
        else:
            result.append(candidate)
    
    return result

def test_jwt_key(token, key_candidate):
    """Тестирует ключ с JWT библиотекой"""
    try:
        decoded = jwt.decode(token, key_candidate, algorithms=["HS256"])
        return True
    except:
        return False

def manual_hmac_verification(token, key_candidate):
    """Ручная проверка HMAC подписи"""
    try:
        parts = token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        expected_signature = base64.urlsafe_b64decode(parts[2] + '==')
        
        if isinstance(key_candidate, str):
            key_bytes = key_candidate.encode('utf-8')
        else:
            key_bytes = key_candidate
            
        computed_signature = hmac.new(key_bytes, message.encode('utf-8'), hashlib.sha256).digest()
        return computed_signature == expected_signature
    except:
        return False

def analyze_qnx_binary():
    """Анализирует QNX бинарный файл на предмет ключей"""
    print("🔍 Анализ QNX бинарного файла 'unlock'...")
    
    if not os.path.exists("unlock"):
        print("❌ Файл 'unlock' не найден в текущей директории")
        return []
    
    # Извлекаем строки из бинарника
    try:
        with open("unlock", "rb") as f:
            content = f.read()
        
        # Ищем ASCII строки длиной от 4 символов
        ascii_strings = []
        current_string = b""
        
        for byte in content:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) >= 4:
                    ascii_strings.append(current_string.decode('ascii', errors='ignore'))
                current_string = b""
        
        # Добавляем последнюю строку
        if len(current_string) >= 4:
            ascii_strings.append(current_string.decode('ascii', errors='ignore'))
        
        # Фильтруем потенциальные ключи
        potential_keys = []
        for s in ascii_strings:
            # Ищем строки, которые могут быть ключами
            if (len(s) >= 8 and 
                (re.match(r'^[a-zA-Z0-9_-]+$', s) or
                 'key' in s.lower() or
                 'secret' in s.lower() or
                 'token' in s.lower() or
                 'auth' in s.lower() or
                 'sign' in s.lower() or
                 'hmac' in s.lower() or
                 'cunba' in s.lower() or
                 'unlock' in s.lower())):
                potential_keys.append(s)
        
        print(f"Найдено {len(potential_keys)} потенциальных ключей в бинарнике:")
        for key in potential_keys[:20]:  # Показываем первые 20
            print(f"  - {key}")
        
        return potential_keys
    
    except Exception as e:
        print(f"❌ Ошибка при анализе бинарника: {e}")
        return []

def brute_force_qnx_keys():
    """Основная функция брутфорса ключей для QNX"""
    print("🚀 Начинаем поиск ключа JWT для QNX системы...")
    
    # Декодируем токен
    header = jwt.get_unverified_header(working_token)
    payload = jwt.decode(working_token, options={"verify_signature": False})
    
    vehicle_id = payload.get('vehicle_id', '')
    timestamp = payload.get('timestamp', 0)
    
    print(f"Vehicle ID: {vehicle_id}")
    print(f"Timestamp: {timestamp}")
    print(f"Issuer: {payload.get('iss', '')}")
    
    # 1. Анализ бинарника
    binary_keys = analyze_qnx_binary()
    
    # 2. Генерация QNX-специфичных ключей
    qnx_keys = generate_qnx_specific_keys(vehicle_id, timestamp)
    
    # 3. Объединяем все кандидатов
    all_candidates = binary_keys + qnx_keys
    
    # Удаляем дубликаты
    unique_candidates = []
    seen = set()
    for candidate in all_candidates:
        if candidate not in seen:
            unique_candidates.append(candidate)
            seen.add(candidate)
    
    print(f"\n🔎 Тестируем {len(unique_candidates)} уникальных кандидатов...")
    
    # Тестируем каждого кандидата
    for i, candidate in enumerate(unique_candidates):
        if i % 100 == 0 and i > 0:
            print(f"Протестировано {i}/{len(unique_candidates)} кандидатов...")
        
        # Тест 1: JWT библиотека
        if test_jwt_key(working_token, candidate):
            print(f"🎉 КЛЮЧ НАЙДЕН (JWT): {candidate}")
            return candidate
        
        # Тест 2: Ручная проверка HMAC
        if manual_hmac_verification(working_token, candidate):
            print(f"🎉 КЛЮЧ НАЙДЕН (HMAC): {candidate}")
            return candidate
    
    print("❌ Ключ не найден среди всех кандидатов")
    return None

def generate_new_token_without_exp(key, vehicle_id):
    """Генерирует новый токен БЕЗ поля exp (как в рабочем токене)"""
    payload = {
        "vehicle_id": vehicle_id,
        "iss": "CunBA",
        "timestamp": int(datetime.now().timestamp())
    }
    
    try:
        token = jwt.encode(payload, key, algorithm="HS256")
        print(f"✅ Новый токен сгенерирован: {token}")
        return token
    except Exception as e:
        print(f"❌ Ошибка генерации токена: {e}")
        return None

if __name__ == "__main__":
    print("=== QNX JWT Анализ ===")
    
    # Ищем ключ
    found_key = brute_force_qnx_keys()
    
    if found_key:
        print(f"\n🎯 НАЙДЕННЫЙ КЛЮЧ: {found_key}")
        print(f"Тип ключа: {type(found_key)}")
        
        # Генерируем новый токен
        vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
        new_token = generate_new_token_without_exp(found_key, vehicle_id)
        
        if new_token:
            print(f"\n🚀 ТЕСТОВЫЙ ТОКЕН ДЛЯ QNX: {new_token}")
            print("\n📝 Инструкция для тестирования на QNX:")
            print("1. Скопируйте токен выше")
            print("2. Вставьте его в переменную на QNX системе")
            print("3. Запустите ./unlock для проверки")
    else:
        print("\n💡 Попробуйте следующие подходы:")
        print("1. Проанализируйте файлы конфигурации в /data/local/tmp")
        print("2. Проверьте переменные окружения на QNX системе")
        print("3. Используйте отладчик для анализа функций подписи")
        print("4. Поищите скрытые файлы с ключами в системе")

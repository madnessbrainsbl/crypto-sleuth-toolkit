#!/usr/bin/env python3
import jwt
import json
import base64
import hashlib
import hmac
import itertools
import string
from datetime import datetime
import binascii

# Рабочий токен
working_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

def decode_token_parts(token):
    """Декодирует все части JWT токена"""
    parts = token.split('.')
    header_b64 = parts[0]
    payload_b64 = parts[1]
    signature_b64 = parts[2]
    
    # Декодируем header и payload
    header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
    
    # Декодируем подпись в байты
    signature_bytes = base64.urlsafe_b64decode(signature_b64 + '==')
    
    return header, payload, signature_bytes, f"{header_b64}.{payload_b64}"

def generate_key_candidates(vehicle_id, timestamp, iss):
    """Генерирует кандидатов для ключа на основе данных токена"""
    candidates = set()
    
    # Простые статические ключи
    static_keys = [
        "secret", "key", "unlock", "cunba", "CunBA", "CUNBA", "CuNBA",
        "qnx", "mega", "platform", "token", "jwt", "auth", "sign",
        "unlock_secret", "cunba_key", "mega_unlock", "qnx_key",
        "virbox", "protector", "android"
    ]
    
    # Системные данные
    system_data = [
        vehicle_id,
        vehicle_id.upper(),
        vehicle_id.lower(),
        str(timestamp),
        iss,
        iss.upper(),
        iss.lower()
    ]
    
    # Комбинации
    combinations = []
    for key in static_keys[:10]:  # Ограничиваем для скорости
        for data in system_data[:5]:
            combinations.extend([
                f"{key}_{data}",
                f"{data}_{key}",
                f"{key}{data}",
                f"{data}{key}"
            ])
    
    # Хешированные варианты
    hash_sources = static_keys + system_data + [vehicle_id + str(timestamp), str(timestamp) + vehicle_id]
    hash_variants = []
    
    for source in hash_sources:
        try:
            hash_variants.extend([
                hashlib.md5(source.encode()).hexdigest(),
                hashlib.sha1(source.encode()).hexdigest(),
                hashlib.sha256(source.encode()).hexdigest(),
                hashlib.md5(source.encode()).digest(),
                hashlib.sha1(source.encode()).digest(),
                hashlib.sha256(source.encode()).digest()
            ])
        except:
            continue
    
    # Объединяем все кандидатов
    all_candidates = static_keys + system_data + combinations + hash_variants
    
    # Добавляем кандидатов в разных кодировках
    for candidate in all_candidates[:100]:  # Ограничиваем
        if isinstance(candidate, str):
            candidates.add(candidate)
            candidates.add(candidate.encode('utf-8'))
            candidates.add(candidate.encode('ascii', errors='ignore'))
        else:
            candidates.add(candidate)
    
    return list(candidates)

def test_hmac_key(message, expected_signature, key_candidate):
    """Тестирует ключ для HMAC-SHA256"""
    try:
        if isinstance(key_candidate, str):
            key_bytes = key_candidate.encode('utf-8')
        else:
            key_bytes = key_candidate
            
        computed = hmac.new(key_bytes, message.encode('utf-8'), hashlib.sha256).digest()
        return computed == expected_signature
    except:
        return False

def brute_force_systematic(token):
    """Систематический брутфорс ключа"""
    print("🔍 Начинаем систематический поиск ключа...")
    
    header, payload, signature, message = decode_token_parts(token)
    vehicle_id = payload.get('vehicle_id', '')
    timestamp = payload.get('timestamp', 0)
    iss = payload.get('iss', '')
    
    print(f"Vehicle ID: {vehicle_id}")
    print(f"Timestamp: {timestamp}")
    print(f"Issuer: {iss}")
    print(f"Expected signature (hex): {signature.hex()}")
    
    # Генерируем кандидатов
    candidates = generate_key_candidates(vehicle_id, timestamp, iss)
    print(f"Сгенерировано {len(candidates)} кандидатов для ключа")
    
    # Тестируем каждого кандидата
    for i, candidate in enumerate(candidates):
        if i % 100 == 0:
            print(f"Протестировано {i}/{len(candidates)} кандидатов...")
            
        if test_hmac_key(message, signature, candidate):
            print(f"🎉 КЛЮЧ НАЙДЕН: {candidate}")
            print(f"Тип ключа: {type(candidate)}")
            if isinstance(candidate, bytes):
                print(f"Ключ (hex): {candidate.hex()}")
            return candidate
    
    print("❌ Ключ не найден среди сгенерированных кандидатов")
    return None

def analyze_signature_pattern(token):
    """Анализирует паттерн в подписи"""
    print("\n🔬 Анализ паттерна подписи...")
    
    header, payload, signature, message = decode_token_parts(token)
    
    print(f"Signature bytes: {signature.hex()}")
    print(f"Signature length: {len(signature)} bytes")
    
    # Проверяем, не является ли подпись результатом простого XOR
    for xor_key in [0x42, 0xFF, 0x00, 0x69, 0x33]:
        xored = bytes([b ^ xor_key for b in signature])
        print(f"XOR with 0x{xor_key:02x}: {xored.hex()}")

def test_custom_algorithms(token):
    """Тестирует кастомные алгоритмы подписи"""
    print("\n🧪 Тестирование кастомных алгоритмов...")
    
    header, payload, signature, message = decode_token_parts(token)
    vehicle_id = payload.get('vehicle_id', '')
    timestamp = payload.get('timestamp', 0)
    
    # Тест 1: Может быть ключ - это комбинация timestamp + vehicle_id
    test_keys = [
        f"{timestamp}{vehicle_id}",
        f"{vehicle_id}{timestamp}",
        hashlib.md5(f"{timestamp}{vehicle_id}".encode()).hexdigest(),
        hashlib.md5(f"{vehicle_id}{timestamp}".encode()).hexdigest()
    ]
    
    for key in test_keys:
        try:
            # Тестируем JWT библиотеку
            decoded = jwt.decode(token, key, algorithms=["HS256"])
            print(f"✅ JWT декодирован с ключом: {key}")
            return key
        except jwt.InvalidSignatureError:
            continue
        except Exception as e:
            continue
    
    return None

def reverse_engineer_from_strings():
    """Анализирует строки из бинарника для поиска ключей"""
    print("\n🔎 Анализ строк из бинарного файла...")
    
    # Строки, которые мы нашли в бинарнике
    potential_keys = [
        "virbox", "protector", "android", "CunBA", "unlock",
        "signal", "pthread", "Operation not authorized at current processing stage",
        # Hex строки из дампа
        "0d79ff047f5cec5bf2ec2ec7d3e464ce",  # vehicle_id
        "1753096202",  # timestamp
    ]
    
    # Также проверяем комбинации функций из Ghidra
    ghidra_functions = [
        "getentropy", "sigaction", "signal", "memcpy", "malloc",
        "dlopen", "dlsym", "ptrace", "prctl", "pthread_create"
    ]
    
    all_potential = potential_keys + ghidra_functions
    
    for key in all_potential:
        try:
            decoded = jwt.decode(working_token, key, algorithms=["HS256"])
            print(f"✅ НАЙДЕН КЛЮЧ ИЗ СТРОК: {key}")
            return key
        except:
            continue
    
    return None

if __name__ == "__main__":
    print("=== Продвинутый анализ JWT токена ===")
    
    # 1. Анализ паттерна подписи
    analyze_signature_pattern(working_token)
    
    # 2. Поиск среди строк бинарника
    found_key = reverse_engineer_from_strings()
    if found_key:
        print(f"\n🎯 Ключ найден: {found_key}")
    else:
        # 3. Систематический брутфорс
        found_key = brute_force_systematic(working_token)
        
        if not found_key:
            # 4. Кастомные алгоритмы
            found_key = test_custom_algorithms(working_token)
    
    if found_key:
        print(f"\n🎉 ФИНАЛЬНЫЙ РЕЗУЛЬТАТ: Ключ = {found_key}")
        
        # Генерируем новый токен с найденным ключом
        test_payload = {
            "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
            "iss": "CunBA",
            "timestamp": int(datetime.now().timestamp())
        }
        
        try:
            new_token = jwt.encode(test_payload, found_key, algorithm="HS256")
            print(f"\nНОВЫЙ ТЕСТОВЫЙ ТОКЕН: {new_token}")
        except Exception as e:
            print(f"Ошибка генерации токена: {e}")
    else:
        print("\n❌ Ключ не найден. Возможно, используется кастомный алгоритм подписи.")

#!/usr/bin/env python3
import jwt
import json
import base64
import hashlib
import hmac
from datetime import datetime

# Рабочий токен (который работает)
working_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

# Токен который не работает
failed_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5Njc2MSwiZXhwIjoxNzUzMDk3MDYxfQ.StCOSqg0VcOs3UTTOfYsq1JWitZ9bLL9gTepJD8LMuY"

def decode_jwt(token):
    """Декодирует JWT токен без проверки подписи"""
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        return header, payload
    except Exception as e:
        print(f"Ошибка декодирования: {e}")
        return None, None

def analyze_token(token, name):
    print(f"\n=== Анализ {name} ===")
    header, payload = decode_jwt(token)
    
    if header and payload:
        print(f"Header: {json.dumps(header, indent=2)}")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        
        # Разбираем части токена
        parts = token.split('.')
        header_b64 = parts[0]
        payload_b64 = parts[1]
        signature_b64 = parts[2]
        
        print(f"Header (base64): {header_b64}")
        print(f"Payload (base64): {payload_b64}")
        print(f"Signature (base64): {signature_b64}")
        
        # Декодируем signature в hex
        signature_bytes = base64.urlsafe_b64decode(signature_b64 + '==')
        print(f"Signature (hex): {signature_bytes.hex()}")
        
        return header, payload, signature_bytes
    
    return None, None, None

def brute_force_key(token, vehicle_id, timestamp):
    """Попытка брутфорса ключа"""
    print(f"\n=== Брутфорс ключа ===")
    
    # Кандидаты для ключа
    key_candidates = [
        # Простые ключи
        "secret", "key", "unlock", "cunba", "CunBA", "CUNBA",
        # Системные данные
        vehicle_id, 
        str(timestamp),
        f"{vehicle_id}{timestamp}",
        f"{timestamp}{vehicle_id}",
        # MD5/SHA варианты
        hashlib.md5(vehicle_id.encode()).hexdigest(),
        hashlib.sha256(vehicle_id.encode()).hexdigest(),
        hashlib.md5(str(timestamp).encode()).hexdigest(),
        hashlib.sha256(str(timestamp).encode()).hexdigest(),
        # Комбинации
        f"unlock_{vehicle_id}",
        f"cunba_{timestamp}",
        "mega_platform_key",
        "qnx_unlock_key"
    ]
    
    for key in key_candidates:
        try:
            # Пробуем разные кодировки ключа
            for key_variant in [key, key.encode(), key.encode('utf-8')]:
                try:
                    decoded = jwt.decode(token, key_variant, algorithms=["HS256"])
                    print(f"✅ НАЙДЕН КЛЮЧ: '{key}' (тип: {type(key_variant)})")
                    return key_variant
                except jwt.InvalidSignatureError:
                    continue
                except Exception as e:
                    continue
        except:
            continue
    
    print("❌ Ключ не найден среди стандартных кандидатов")
    return None

def manual_hmac_check(token, key_candidate):
    """Ручная проверка HMAC подписи"""
    parts = token.split('.')
    header_payload = f"{parts[0]}.{parts[1]}"
    expected_signature = base64.urlsafe_b64decode(parts[2] + '==')
    
    # Пробуем разные варианты ключа
    for key in [key_candidate, key_candidate.encode(), 
                key_candidate.encode('utf-8'), 
                bytes.fromhex(key_candidate) if all(c in '0123456789abcdefABCDEF' for c in key_candidate) else None]:
        if key is None:
            continue
            
        try:
            computed_signature = hmac.new(key, header_payload.encode(), hashlib.sha256).digest()
            if computed_signature == expected_signature:
                print(f"✅ HMAC совпадает для ключа: {key}")
                return True
        except:
            continue
    
    return False

if __name__ == "__main__":
    # Анализируем оба токена
    working_header, working_payload, working_sig = analyze_token(working_token, "РАБОЧИЙ токен")
    failed_header, failed_payload, failed_sig = analyze_token(failed_token, "НЕ РАБОЧИЙ токен")
    
    # Сравниваем payload
    print(f"\n=== Сравнение payload ===")
    if working_payload and failed_payload:
        print("Различия в payload:")
        for key in set(list(working_payload.keys()) + list(failed_payload.keys())):
            working_val = working_payload.get(key, "ОТСУТСТВУЕТ")
            failed_val = failed_payload.get(key, "ОТСУТСТВУЕТ")
            if working_val != failed_val:
                print(f"  {key}: рабочий={working_val}, не_рабочий={failed_val}")
    
    # Пробуем найти ключ для рабочего токена
    if working_payload:
        vehicle_id = working_payload.get('vehicle_id', '')
        timestamp = working_payload.get('timestamp', 0)
        found_key = brute_force_key(working_token, vehicle_id, timestamp)
        
        if found_key:
            print(f"\n🎉 Найденный ключ можно использовать для генерации новых токенов!")
            
            # Генерируем новый токен с найденным ключом
            test_payload = {
                "vehicle_id": vehicle_id,
                "iss": "CunBA", 
                "timestamp": int(datetime.now().timestamp())
            }
            
            new_token = jwt.encode(test_payload, found_key, algorithm="HS256")
            print(f"Новый тестовый токен: {new_token}")

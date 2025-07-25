#!/usr/bin/env python3
"""
Обратная инженерия SECRET_KEY через анализ JWT компонентов
"""

import jwt
import base64
import json
import binascii
import hashlib
import hmac
from itertools import product

# Рабочий токен
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

def decode_jwt_parts():
    """Декодирование частей JWT"""
    print("🔍 Анализ компонентов JWT токена")
    print("="*50)
    
    parts = WORKING_TOKEN.split('.')
    
    # Header
    header_decoded = base64.b64decode(parts[0] + '==')  # Добавляем padding
    header_json = json.loads(header_decoded)
    print(f"Header: {header_json}")
    
    # Payload  
    payload_decoded = base64.b64decode(parts[1] + '==')
    payload_json = json.loads(payload_decoded)
    print(f"Payload: {payload_json}")
    
    # Signature (base64url)
    signature_bytes = base64.urlsafe_b64decode(parts[2] + '==')
    print(f"Signature (hex): {binascii.hexlify(signature_bytes).decode()}")
    print(f"Signature (base64): {parts[2]}")
    print(f"Signature length: {len(signature_bytes)} bytes")
    
    return parts[0], parts[1], signature_bytes, header_json, payload_json

def try_hmac_with_candidates():
    """Попытка найти ключ через HMAC SHA256"""
    print("\n🔑 Поиск SECRET_KEY через HMAC SHA256...")
    
    header_b64, payload_b64, target_signature, header, payload = decode_jwt_parts()
    
    # Данные для подписи (header.payload)
    message = f"{header_b64}.{payload_b64}".encode('ascii')
    
    print(f"Сообщение для подписи: {message.decode()}")
    print(f"Целевая подпись: {binascii.hexlify(target_signature).decode()}")
    
    # Кандидаты ключей для HMAC
    key_candidates = []
    
    # 1. Простые строки
    simple_keys = [
        "CunBA", "unlock", "mega", "secret", "key", "jwt", "HS256",
        "cunba", "CUNBA", "UNLOCK", "MEGA", "SECRET", "KEY", "JWT",
        "android", "vehicle", "qualcomm", "8155"
    ]
    key_candidates.extend(simple_keys)
    
    # 2. На основе данных из токена
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    timestamp = "1753096202"
    
    data_based_keys = [
        vehicle_id,
        vehicle_id.upper(),
        timestamp,
        f"CunBA_{timestamp}",
        f"CunBA_{vehicle_id}",
        f"{vehicle_id}_{timestamp}",
        f"unlock_{vehicle_id}",
        f"mega_{vehicle_id}"
    ]
    key_candidates.extend(data_based_keys)
    
    # 3. Хэши
    for base in ["CunBA", "unlock", "mega", vehicle_id]:
        key_candidates.extend([
            hashlib.md5(base.encode()).hexdigest(),
            hashlib.sha1(base.encode()).hexdigest(),
            hashlib.sha256(base.encode()).hexdigest(),
            hashlib.sha256(base.encode()).hexdigest()[:32],
            hashlib.sha256(base.encode()).hexdigest()[:16],
        ])
    
    # 4. Байтовые ключи
    try:
        vid_bytes = binascii.unhexlify(vehicle_id)
        key_candidates.extend([
            vid_bytes.decode('latin1'),
            binascii.hexlify(vid_bytes).decode(),
        ])
    except:
        pass
    
    print(f"Тестируем {len(key_candidates)} кандидатов ключей...")
    
    for i, key in enumerate(key_candidates):
        try:
            # Пробуем как строку
            if isinstance(key, str):
                key_bytes = key.encode('utf-8')
            else:
                key_bytes = key
            
            # HMAC SHA256
            signature = hmac.new(key_bytes, message, hashlib.sha256).digest()
            
            if signature == target_signature:
                print(f"🎉 НАЙДЕН SECRET_KEY!")
                print(f"Ключ: '{key}'")
                print(f"Тип: {type(key)}")
                print(f"Байты: {key_bytes}")
                
                # Проверяем через jwt библиотеку
                test_token = jwt.encode(payload, key, algorithm='HS256')
                if test_token == WORKING_TOKEN:
                    print(f"✅ Подтверждено через JWT библиотеку!")
                return key
                
        except Exception as e:
            continue
    
    print("❌ HMAC ключ не найден среди кандидатов")
    return None

def bruteforce_key_from_binary():
    """Брутфорс ключа из строк бинарника"""
    print("\n🔍 Брутфорс ключа из unlock бинарника...")
    
    try:
        with open("unlock", "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("❌ Файл unlock не найден")
        return None
    
    header_b64, payload_b64, target_signature, header, payload = decode_jwt_parts()
    message = f"{header_b64}.{payload_b64}".encode('ascii')
    
    # Извлекаем все возможные строки
    strings = []
    current_string = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # ASCII
            current_string += chr(byte)
        else:
            if len(current_string) >= 4:
                strings.append(current_string)
            current_string = ""
    
    if current_string:
        strings.append(current_string)
    
    print(f"Найдено {len(strings)} строк для тестирования...")
    
    tested = 0
    for string in strings:
        tested += 1
        if tested % 1000 == 0:
            print(f"   Протестировано {tested}/{len(strings)}...")
        
        try:
            key_bytes = string.encode('utf-8')
            signature = hmac.new(key_bytes, message, hashlib.sha256).digest()
            
            if signature == target_signature:
                print(f"🎉 НАЙДЕН SECRET_KEY В БИНАРНИКЕ!")
                print(f"Ключ: '{string}'")
                print(f"Позиция в файле: {data.find(string.encode())}")
                
                # Проверяем через jwt
                test_token = jwt.encode(payload, string, algorithm='HS256')
                if test_token == WORKING_TOKEN:
                    print(f"✅ Подтверждено через JWT библиотеку!")
                return string
        except:
            continue
    
    print("❌ Ключ не найден в строках бинарника")
    return None

def analyze_signature_pattern():
    """Анализ паттерна подписи"""
    print("\n📊 Анализ паттерна подписи...")
    
    header_b64, payload_b64, target_signature, header, payload = decode_jwt_parts()
    
    print(f"Подпись (hex): {binascii.hexlify(target_signature).decode()}")
    
    # Анализ байтов
    sig_bytes = list(target_signature)
    print(f"Байты подписи: {[hex(b) for b in sig_bytes]}")
    
    # Ищем паттерны
    unique_bytes = len(set(sig_bytes))
    print(f"Уникальных байтов: {unique_bytes}/32")
    
    # Энтропия
    from collections import Counter
    import math
    counter = Counter(sig_bytes)
    entropy = sum(-(count/32) * math.log2(count/32) for count in counter.values() if count > 0)
    print(f"Энтропия: {entropy:.2f}")

def main():
    """Главная функция обратной инженерии"""
    print("🔐 ОБРАТНАЯ ИНЖЕНЕРИЯ SECRET_KEY")
    print("="*60)
    print(f"Рабочий токен: {WORKING_TOKEN[:50]}...")
    print()
    
    # Анализ компонентов
    decode_jwt_parts()
    
    # Анализ подписи
    analyze_signature_pattern()
    
    # Поиск через HMAC кандидатов
    result = try_hmac_with_candidates()
    
    if not result:
        # Брутфорс из бинарника
        result = bruteforce_key_from_binary()
    
    if result:
        print(f"\n🎉 SUCCESS! НАЙДЕН ПРАВИЛЬНЫЙ SECRET_KEY: '{result}'")
        
        # Создаем финальный генератор
        generator_code = f'''#!/usr/bin/env python3
import jwt
from datetime import datetime

# НАЙДЕННЫЙ SECRET_KEY
SECRET_KEY = "{result}"

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
        
        with open("final_generator.py", "w") as f:
            f.write(generator_code)
        
        print("✅ Создан final_generator.py с правильным ключом!")
    else:
        print("\n😞 SECRET_KEY не найден через обратную инженерию")

if __name__ == "__main__":
    main()

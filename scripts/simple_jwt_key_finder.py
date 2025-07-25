#!/usr/bin/env python3
"""
Простой поиск JWT ключа на основе анализа токена и системной информации
"""

import jwt
import hashlib
import hmac
import base64
import json
from itertools import combinations

# Рабочий токен
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

def decode_token_parts():
    """Декодируем части токена для анализа"""
    parts = WORKING_TOKEN.split('.')
    
    print("=== Анализ JWT токена ===")
    
    # Header
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    print(f"\nHeader: {header}")
    
    # Payload
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    print(f"Payload: {payload}")
    
    # Signature (raw bytes)
    sig_b64 = parts[2]
    sig_bytes = base64.urlsafe_b64decode(sig_b64 + '==')
    print(f"Signature (hex): {sig_bytes.hex()}")
    print(f"Signature length: {len(sig_bytes)} bytes")
    
    return header, payload, sig_bytes

def generate_simple_keys(payload):
    """Генерация простых ключей на основе данных из токена"""
    keys = []
    
    vehicle_id = payload['vehicle_id']
    timestamp = str(payload['timestamp'])
    iss = payload['iss']
    
    # Простые строки
    simple_strings = [
        'secret', 'Secret', 'SECRET',
        'key', 'Key', 'KEY',
        'password', 'Password', 'PASSWORD',
        'unlock', 'Unlock', 'UNLOCK',
        'jwt', 'JWT',
        'token', 'Token', 'TOKEN',
        'mega', 'Mega', 'MEGA',
        'platform', 'Platform', 'PLATFORM',
        'A11', 'a11',
        'QNX', 'qnx',
        'huron', 'Huron', 'HURON',
        'cunba', 'Cunba', 'CUNBA', 'CunBA',
        '0x40', '0x3f', '0x41',
        'FUN_0010d54c', 'FUN_0010d5c4', 'FUN_00109ac4', 'FUN_0010d8e4',
        'DAT_002791f4'
    ]
    
    keys.extend(simple_strings)
    
    # Комбинации с vehicle_id
    vehicle_combinations = [
        vehicle_id,
        vehicle_id.upper(),
        vehicle_id.lower(),
        vehicle_id[:16],
        vehicle_id[-16:],
        vehicle_id[:8],
        vehicle_id[-8:],
        f"{iss}_{vehicle_id}",
        f"{vehicle_id}_{iss}",
        f"{iss}{vehicle_id}",
        f"{vehicle_id}{iss}",
        f"{vehicle_id}_{timestamp}",
        f"{timestamp}_{vehicle_id}",
        f"unlock_{vehicle_id}",
        f"{vehicle_id}_unlock",
        f"mega_{vehicle_id}",
        f"{vehicle_id}_mega",
        f"A11_{vehicle_id}",
        f"{vehicle_id}_A11"
    ]
    
    keys.extend(vehicle_combinations)
    
    # Комбинации с timestamp
    timestamp_combinations = [
        timestamp,
        f"{iss}_{timestamp}",
        f"{timestamp}_{iss}",
        f"unlock_{timestamp}",
        f"{timestamp}_unlock",
        f"secret_{timestamp}",
        f"{timestamp}_secret"
    ]
    
    keys.extend(timestamp_combinations)
    
    # MD5/SHA хеши простых комбинаций
    for base in [vehicle_id, timestamp, iss, f"{vehicle_id}_{timestamp}", f"{iss}_{vehicle_id}"]:
        keys.append(hashlib.md5(base.encode()).hexdigest())
        keys.append(hashlib.sha256(base.encode()).hexdigest())
        keys.append(hashlib.sha1(base.encode()).hexdigest())
    
    # Возможные ключи из адресов памяти
    memory_addresses = [
        "0d79ff047f5cec5bf2ec2ec7d3e464ce",  # vehicle_id как есть
        "0D79FF047F5CEC5BF2EC2EC7D3E464CE",  # upper
        "464ce", "e464ce", "d3e464ce",       # последние части
        "0d79ff", "0d79ff04", "0d79ff047f5c", # начальные части
    ]
    
    keys.extend(memory_addresses)
    
    # Base64 варианты
    for k in [vehicle_id, timestamp, iss]:
        keys.append(base64.b64encode(k.encode()).decode())
    
    return keys

def test_key(key, token=WORKING_TOKEN):
    """Тестирование ключа"""
    try:
        # Пробуем декодировать с ключом
        decoded = jwt.decode(token, key, algorithms=["HS256"])
        print(f"\n✓✓✓ НАЙДЕН КЛЮЧ: '{key}'")
        print(f"Декодированный payload: {decoded}")
        
        # Проверяем, можем ли создать такой же токен
        new_token = jwt.encode(decoded, key, algorithm="HS256")
        if new_token == token:
            print("✓ Токен полностью совпадает!")
        
        return True
    except jwt.InvalidSignatureError:
        return False
    except Exception as e:
        return False

def bruteforce_short_keys():
    """Брутфорс коротких ключей (до 4 символов)"""
    import string
    
    chars = string.ascii_letters + string.digits + '_-'
    keys = []
    
    # 1-символьные
    for c1 in chars:
        keys.append(c1)
    
    # 2-символьные
    for c1 in chars:
        for c2 in chars:
            keys.append(c1 + c2)
    
    # 3-символьные (ограниченный набор)
    common_3 = ['key', 'jwt', 'sec', 'pwd', 'qnx', 'a11', 'hex']
    keys.extend(common_3)
    
    return keys

def main():
    print("=== Поиск JWT ключа (простой подход) ===\n")
    
    # Анализируем токен
    header, payload, signature = decode_token_parts()
    
    # Генерируем ключи
    print("\n\n=== Генерация ключей-кандидатов ===")
    
    all_keys = []
    
    # 1. Простые ключи на основе данных токена
    simple_keys = generate_simple_keys(payload)
    all_keys.extend(simple_keys)
    print(f"Сгенерировано {len(simple_keys)} простых ключей")
    
    # 2. Короткие ключи
    short_keys = bruteforce_short_keys()
    all_keys.extend(short_keys)
    print(f"Сгенерировано {len(short_keys)} коротких ключей")
    
    # 3. Специфичные для QNX/embedded
    qnx_keys = [
        'qnx', 'QNX', 'qnx6', 'QNX6',
        'neutrino', 'Neutrino', 'NEUTRINO',
        'photon', 'Photon', 'PHOTON',
        'harman', 'Harman', 'HARMAN',
        'blackberry', 'BlackBerry', 'BLACKBERRY',
        'embedded', 'Embedded', 'EMBEDDED',
        'rtos', 'RTOS',
        'arm', 'ARM', 'aarch64', 'AARCH64'
    ]
    all_keys.extend(qnx_keys)
    
    # Убираем дубликаты
    all_keys = list(set(all_keys))
    
    print(f"\nВсего уникальных ключей для проверки: {len(all_keys)}")
    
    # Тестируем ключи
    print("\n\n=== Тестирование ключей ===")
    found = False
    
    for i, key in enumerate(all_keys):
        if i % 100 == 0 and i > 0:
            print(f"  Проверено {i}/{len(all_keys)}...")
        
        if test_key(key):
            found = True
            
            # Сохраняем найденный ключ
            with open('FOUND_JWT_KEY.txt', 'w') as f:
                f.write(f"JWT SECRET KEY: {key}\n")
                f.write(f"Working token: {WORKING_TOKEN}\n")
            
            break
    
    if not found:
        print("\n✗ Ключ не найден среди простых вариантов")
        print("\nВозможные причины:")
        print("1. Ключ является случайной строкой")
        print("2. Ключ хранится в зашифрованном виде")
        print("3. Ключ генерируется динамически из системных данных")
        print("\nРекомендации:")
        print("1. Использовать отладчик на устройстве")
        print("2. Анализировать функции 0x0010d54c, 0x0010d5c4 в Ghidra")
        print("3. Поискать строки в памяти во время работы unlock")

if __name__ == "__main__":
    main()

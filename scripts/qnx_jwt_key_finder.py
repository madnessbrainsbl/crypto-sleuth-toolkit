#!/usr/bin/env python3
"""
QNX JWT Key Finder
Специализированный поиск ключа для QNX устройства
"""

import jwt
import hashlib
import hmac
import base64
import struct
import binascii
from datetime import datetime

WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
VEHICLE_ID = "0d79ff047f5cec5bf2ec2ec7d3e464ce"

def verify_key(key_candidate):
    """Проверяет ключ"""
    try:
        if isinstance(key_candidate, bytes):
            key_candidate = key_candidate.decode('latin-1', errors='ignore')
        jwt.decode(WORKING_TOKEN, key_candidate, algorithms=["HS256"])
        return True
    except:
        return False

def generate_qnx_system_keys():
    """Генерирует ключи специфичные для QNX"""
    keys = []
    
    # QNX специфичные пути и названия
    qnx_patterns = [
        "/proc/boot/unlock",
        "/dev/shmem/jwt_key",
        "qnx_mega_platform",
        "mega_a11_unlock",
        "cunba_jwt_secret",
        "vehicle_unlock_key",
    ]
    
    for pattern in qnx_patterns:
        keys.append(pattern)
        keys.append(pattern.upper())
        keys.append(hashlib.md5(pattern.encode()).hexdigest())
        keys.append(hashlib.sha256(pattern.encode()).hexdigest())
    
    # Системные свойства QNX
    getprop_keys = [
        "ro.serialno",
        "ro.boot.serialno", 
        "ro.hardware",
        "ro.product.model",
        "persist.sys.timezone",
    ]
    
    # Комбинации с vehicle_id
    for prop in getprop_keys:
        keys.append(f"{prop}_{VEHICLE_ID}")
        keys.append(f"{VEHICLE_ID}_{prop}")
    
    return keys

def generate_hardware_based_keys():
    """Генерирует ключи на основе hardware ID"""
    keys = []
    
    # Преобразования vehicle_id
    vid_bytes = bytes.fromhex(VEHICLE_ID)
    
    # Различные представления ID
    keys.append(VEHICLE_ID)  # как есть
    keys.append(VEHICLE_ID.upper())
    keys.append(VEHICLE_ID.lower())
    
    # Побайтовые операции
    for i in range(len(vid_bytes)):
        # Циклический сдвиг
        rotated = vid_bytes[i:] + vid_bytes[:i]
        keys.append(rotated.hex())
        
        # XOR с различными масками
        for mask in [0xFF, 0xAA, 0x55, 0x69, 0x42]:
            xored = bytes([b ^ mask for b in vid_bytes])
            keys.append(xored.hex())
    
    # Части ID в различных комбинациях
    parts = [VEHICLE_ID[i:i+8] for i in range(0, len(VEHICLE_ID), 8)]
    
    # Суммы и произведения частей
    for i, part in enumerate(parts):
        num = int(part, 16)
        keys.append(str(num))
        keys.append(f"KEY_{num}")
        keys.append(f"SECRET_{num}")
    
    return keys

def generate_embedded_patterns():
    """Генерирует ключи типичные для встроенных систем"""
    keys = []
    
    # Типичные ключи во встроенных системах
    embedded_patterns = [
        "00000000000000000000000000000000",  # 32 нуля
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",  # 32 F
        "0123456789ABCDEF0123456789ABCDEF",  # тестовый паттерн
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEF",  # классический паттерн
        "CAFEBABECAFEBABECAFEBABECAFEBABE",  # Java паттерн
    ]
    
    for pattern in embedded_patterns:
        keys.append(pattern)
        keys.append(pattern.lower())
        # Также пробуем как байты
        try:
            keys.append(bytes.fromhex(pattern).decode('latin-1'))
        except:
            pass
    
    # Адреса памяти как ключи
    memory_addresses = [
        "002791f4", "002791f8", "002791ec", "002791f0",
        "0010d54c", "0010d5c4", "00109ac4", "0010d8e4"
    ]
    
    for addr in memory_addresses:
        keys.append(addr)
        keys.append("0x" + addr)
        # Расширяем до 32 символов
        keys.append(addr * 4)
        keys.append((addr + "00000000") * 2)
    
    return keys

def generate_function_based_keys():
    """Генерирует ключи на основе анализа функций"""
    keys = []
    
    # Константы из анализа функций
    function_constants = [
        # Из FUN_0010d8e4
        (0x18, 0xf, 0x8, 0x3),  # параметры таблиц
        # Магические числа
        (0x40, 0x41, 0x3f, 0xff),
        (0xffffffffffffff88, 0xffffffffffffffec),
    ]
    
    for const_tuple in function_constants:
        # Пробуем как строку hex
        hex_str = ''.join(f"{c:02x}" if c < 256 else f"{c:016x}" for c in const_tuple)
        keys.append(hex_str)
        
        # Пробуем как байты
        for c in const_tuple:
            if c < 256:
                keys.append(chr(c) * 32)
            else:
                keys.append(struct.pack("<Q", c & 0xFFFFFFFFFFFFFFFF).hex())
    
    return keys

def check_binary_strings():
    """Проверяет строки которые могут быть в бинарнике"""
    keys = []
    
    # Строки связанные с JWT/криптографией
    crypto_strings = [
        "jwt_secret", "jwt_key", "hmac_key", "sign_key",
        "SECRET_KEY", "SIGNING_KEY", "TOKEN_KEY",
        "unlock_secret", "unlock_key", "device_key",
        "MEGA_KEY", "CUNBA_KEY", "PLATFORM_KEY"
    ]
    
    for s in crypto_strings:
        keys.append(s)
        keys.append(s.lower())
        keys.append(s.upper())
        # С vehicle_id
        keys.append(f"{s}_{VEHICLE_ID}")
        keys.append(f"{VEHICLE_ID}_{s}")
    
    return keys

def main():
    print("🔧 QNX JWT Key Finder")
    print("=" * 50)
    
    # Анализируем токен
    parts = WORKING_TOKEN.split('.')
    header = base64.urlsafe_b64decode(parts[0] + '==')
    payload = base64.urlsafe_b64decode(parts[1] + '==') 
    signature = base64.urlsafe_b64decode(parts[2] + '==')
    
    print(f"📊 Токен:")
    print(f"  Header: {header}")
    print(f"  Payload: {payload}")
    print(f"  Signature (hex): {signature.hex()}")
    print(f"  Signature (ASCII): {repr(signature)}")
    
    # Интересное наблюдение - подпись начинается с '1ij'
    print(f"\n🔍 Анализ подписи:")
    print(f"  Первые 3 байта: {signature[:3]} ({repr(signature[:3])})")
    print(f"  Это может быть подсказкой!")
    
    # Собираем все ключи
    all_keys = set()
    
    generators = [
        ("QNX системные", generate_qnx_system_keys),
        ("Hardware ID", generate_hardware_based_keys),
        ("Embedded паттерны", generate_embedded_patterns),
        ("Функции", generate_function_based_keys),
        ("Бинарные строки", check_binary_strings),
    ]
    
    print(f"\n📋 Генерация кандидатов:")
    for name, gen in generators:
        keys = gen()
        print(f"  {name}: {len(keys)} ключей")
        all_keys.update(keys)
    
    # Добавляем специальные случаи
    special_keys = [
        "1ij",  # начало подписи
        "1ij" + "0" * 29,  # дополненный нулями
        "31696a",  # hex представление '1ij'
        "31696a" + "0" * 26,  # дополненный нулями
        signature[:16].hex(),  # первая половина подписи как ключ
        signature[-16:].hex(),  # вторая половина подписи как ключ
    ]
    
    all_keys.update(special_keys)
    
    print(f"\n🔄 Проверка {len(all_keys)} кандидатов...")
    
    found = False
    for i, key in enumerate(all_keys):
        if verify_key(key):
            print(f"\n✅ НАЙДЕН КЛЮЧ: {repr(key)}")
            print(f"Длина ключа: {len(key)} символов")
            
            # Создаем новый токен для проверки
            payload = {
                "vehicle_id": VEHICLE_ID,
                "iss": "CunBA",
                "timestamp": int(datetime.now().timestamp())
            }
            new_token = jwt.encode(payload, key, algorithm="HS256")
            print(f"\n🆕 Новый токен: {new_token}")
            
            # Декодируем для проверки
            decoded = jwt.decode(new_token, key, algorithms=["HS256"])
            print(f"Декодированный payload: {decoded}")
            
            found = True
            break
        
        if i % 100 == 0:
            print(f"  Проверено: {i}/{len(all_keys)}", end='\r')
    
    if not found:
        print(f"\n\n❌ Ключ не найден среди {len(all_keys)} кандидатов")
        print("\n💡 Дальнейшие шаги:")
        print("1. Дампнуть память процесса unlock при работе")
        print("2. Использовать IDA Pro/Ghidra для поиска строковых констант")
        print("3. Проверить окружение функций 0x0010d54c, 0x0010d5c4")
        print("4. Поискать вызовы HMAC/SHA256 функций")
        print("5. Проверить, не используется ли кастомная реализация JWT")

if __name__ == "__main__":
    main()

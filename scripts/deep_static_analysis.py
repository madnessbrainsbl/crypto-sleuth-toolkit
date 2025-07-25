#!/usr/bin/env python3
"""
Углубленный статический анализ unlock для поиска JWT ключа
"""

import jwt
import struct
import hashlib
import itertools
from datetime import datetime

WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

def test_key(key):
    """Тестирование ключа"""
    try:
        decoded = jwt.decode(WORKING_TOKEN, key, algorithms=["HS256"])
        print(f"\n✓✓✓ НАЙДЕН КЛЮЧ!")
        print(f"Ключ: {repr(key)}")
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

def search_fixed_patterns():
    """Поиск фиксированных паттернов в бинарнике"""
    print("=== Поиск фиксированных паттернов ===\n")
    
    try:
        with open('unlock', 'rb') as f:
            data = f.read()
    except:
        print("Файл unlock не найден!")
        return []
    
    candidates = []
    
    # Поиск последовательностей из 16, 24, 32 байт с высокой энтропией
    for length in [16, 24, 32]:
        print(f"Поиск {length}-байтных последовательностей...")
        
        for i in range(0, len(data) - length, 4):  # Выравнивание по 4 байта
            chunk = data[i:i+length]
            
            # Проверка энтропии
            unique_bytes = len(set(chunk))
            if unique_bytes >= length * 0.6:  # Минимум 60% уникальных байт
                # Исключаем очевидные не-ключи
                if not all(b == 0 for b in chunk) and not all(b == 0xFF for b in chunk):
                    # Проверяем, не похоже ли на код
                    if not any(chunk[j:j+4] in [b'\x00\x00\x00\x00', b'\xFF\xFF\xFF\xFF'] for j in range(0, length-4, 4)):
                        candidates.append(chunk)
    
    return candidates

def analyze_crypto_constants():
    """Анализ известных криптографических констант"""
    print("\n=== Анализ криптографических констант ===\n")
    
    candidates = []
    
    # Известные данные из анализа
    crypto_data = [
        0xEFFC057FA41007B1, 0x9276D5D9C8B95896,
        0x73201F4C54CC8F9C, 0xD80B579F196F3882
    ]
    
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    timestamp = 1753096202
    
    # Комбинации с XOR
    print("Генерация XOR комбинаций...")
    vid_bytes = bytes.fromhex(vehicle_id)
    
    for val in crypto_data:
        val_bytes = struct.pack('<Q', val)
        
        # XOR с vehicle_id (циклически)
        xor_result = bytes(vid_bytes[i % 16] ^ val_bytes[i % 8] for i in range(32))
        candidates.append(xor_result)
        
        # XOR с timestamp
        ts_bytes = struct.pack('<Q', timestamp)
        xor_ts = bytes(ts_bytes[i % 8] ^ val_bytes[i % 8] for i in range(32))
        candidates.append(xor_ts)
    
    # Комбинации первых байтов каждого значения
    first_bytes = b''.join(struct.pack('<Q', val)[:1] for val in crypto_data)
    candidates.append(first_bytes)
    
    # Возможно ключ - это производная от vehicle_id
    print("Генерация производных от vehicle_id...")
    
    # Различные хеши
    candidates.append(hashlib.md5(vid_bytes).digest())
    candidates.append(hashlib.sha256(vid_bytes).digest())
    candidates.append(hashlib.sha1(vid_bytes).digest())
    
    # С солью "CunBA"
    salt = b"CunBA"
    candidates.append(hashlib.md5(salt + vid_bytes).digest())
    candidates.append(hashlib.md5(vid_bytes + salt).digest())
    candidates.append(hashlib.sha256(salt + vid_bytes).digest())
    
    # HMAC-подобные конструкции
    ipad = bytes(0x36 for _ in range(16))
    opad = bytes(0x5C for _ in range(16))
    
    key_candidate = bytes(a ^ b for a, b in zip(vid_bytes, ipad))
    candidates.append(key_candidate)
    
    key_candidate = bytes(a ^ b for a, b in zip(vid_bytes, opad))
    candidates.append(key_candidate)
    
    return candidates

def generate_systematic_keys():
    """Систематическая генерация ключей"""
    print("\n=== Систематическая генерация ===\n")
    
    candidates = []
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    
    # Магические строки из embedded систем
    magic_strings = [
        "MegaPlatformA11",
        "CunBAUnlockKey",
        "QNXSecretKey",
        "HuronJWTSecret",
        "UnlockMaster",
        "A11PlatformKey"
    ]
    
    for magic in magic_strings:
        candidates.append(magic)
        candidates.append(magic.encode())
        
        # С хешированием
        candidates.append(hashlib.md5(magic.encode()).hexdigest())
        candidates.append(hashlib.md5(magic.encode()).digest())
    
    # Комбинации с датой/временем
    # Timestamp 1753096202 = 2025-07-20 14:30:02 UTC
    dt = datetime.fromtimestamp(1753096202)
    
    date_formats = [
        dt.strftime("%Y%m%d"),  # 20250720
        dt.strftime("%d%m%Y"),  # 20072025
        dt.strftime("%Y-%m-%d"), # 2025-07-20
        str(1753096202),        # timestamp as string
    ]
    
    for fmt in date_formats:
        candidates.append(fmt)
        candidates.append(hashlib.md5(fmt.encode()).hexdigest()[:16])
    
    # Простые ключи, которые могли использовать разработчики
    dev_keys = [
        "test", "debug", "development",
        "12345678", "87654321",
        "00000000", "11111111",
        "AAAAAAAA", "aaaaaaaa",
        "secret", "password", "default"
    ]
    
    for key in dev_keys:
        candidates.append(key)
        candidates.append(key * 4)  # Повторение до нужной длины
    
    return candidates

def main():
    print("=== Углубленный статический анализ unlock ===\n")
    
    all_candidates = []
    
    # 1. Поиск фиксированных паттернов
    print("1. Поиск фиксированных паттернов в бинарнике...")
    pattern_candidates = search_fixed_patterns()
    all_candidates.extend(pattern_candidates)
    print(f"   Найдено {len(pattern_candidates)} кандидатов")
    
    # 2. Анализ криптографических констант
    print("\n2. Анализ криптографических констант...")
    crypto_candidates = analyze_crypto_constants()
    all_candidates.extend(crypto_candidates)
    print(f"   Сгенерировано {len(crypto_candidates)} кандидатов")
    
    # 3. Систематическая генерация
    print("\n3. Систематическая генерация ключей...")
    systematic_candidates = generate_systematic_keys()
    all_candidates.extend(systematic_candidates)
    print(f"   Сгенерировано {len(systematic_candidates)} кандидатов")
    
    # Убираем дубликаты
    unique_candidates = []
    seen = set()
    
    for candidate in all_candidates:
        key = candidate if isinstance(candidate, (str, bytes)) else str(candidate)
        key_hash = hashlib.md5(str(key).encode()).hexdigest()
        
        if key_hash not in seen:
            seen.add(key_hash)
            unique_candidates.append(candidate)
    
    print(f"\n\nВсего уникальных кандидатов: {len(unique_candidates)}")
    print("Начинаем тестирование...\n")
    
    found = False
    for i, candidate in enumerate(unique_candidates):
        if i % 100 == 0 and i > 0:
            print(f"  Протестировано {i}/{len(unique_candidates)}...")
        
        if test_key(candidate):
            found = True
            
            with open('FOUND_JWT_KEY_STATIC.txt', 'w') as f:
                f.write(f"JWT KEY FOUND!\n")
                f.write(f"Key: {repr(candidate)}\n")
                if isinstance(candidate, bytes):
                    f.write(f"Hex: {candidate.hex()}\n")
                    try:
                        f.write(f"ASCII: {candidate.decode('ascii')}\n")
                    except:
                        pass
                f.write(f"Token: {WORKING_TOKEN}\n")
            break
    
    if not found:
        print("\n✗ Ключ не найден при статическом анализе")
        print("\nВероятные причины:")
        print("1. Ключ генерируется динамически из системных данных")
        print("2. Ключ зашифрован или обфусцирован в бинарнике")
        print("3. Ключ хранится вне бинарника (в прошивке, конфигах)")
        print("\nДля поиска ключа нужен доступ к устройству или:")
        print("- Полный дамп прошивки")
        print("- Системные конфигурационные файлы")
        print("- Возможность запустить unlock с отладчиком")

if __name__ == "__main__":
    main()

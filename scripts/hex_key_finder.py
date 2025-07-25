#!/usr/bin/env python3
"""
Hex анализ unlock бинарника для поиска скрытых SECRET_KEY
Поиск в бинарных данных, что не видно в строках
"""

import jwt
import binascii
import struct
from itertools import combinations

# Рабочий токен
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
WORKING_PAYLOAD = {
    "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
    "iss": "CunBA", 
    "timestamp": 1753096202
}

def test_key(key):
    """Проверка ключа"""
    try:
        if isinstance(key, bytes):
            key = key.decode('ascii', errors='ignore')
        test_token = jwt.encode(WORKING_PAYLOAD, key, algorithm='HS256')
        return test_token == WORKING_TOKEN
    except:
        return False

def search_byte_patterns():
    """Поиск байтовых паттернов в бинарнике"""
    print("🔍 Hex анализ unlock бинарника...")
    
    try:
        with open("unlock", "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("❌ Файл unlock не найден")
        return []
    
    print(f"✓ Загружен файл размером {len(data)} байт")
    
    candidates = []
    
    # 1. Поиск 32-байтных блоков (типичная длина HMAC ключа)
    print("🔍 Поиск 32-байтных блоков...")
    for i in range(0, len(data) - 32, 4):
        chunk = data[i:i+32]
        # Проверяем энтропию
        if len(set(chunk)) > 16:  # Хорошая энтропия
            candidates.append(chunk)
    
    print(f"✓ Найдено {len(candidates)} 32-байтных кандидатов")
    
    # 2. Поиск 16-байтных блоков
    print("🔍 Поиск 16-байтных блоков...")
    count_16 = 0
    for i in range(0, len(data) - 16, 4):
        chunk = data[i:i+16]
        if len(set(chunk)) > 8:
            candidates.append(chunk)
            count_16 += 1
            if count_16 > 1000:  # Ограничиваем
                break
    
    print(f"✓ Добавлено {count_16} 16-байтных кандидатов")
    
    # 3. Поиск рядом с известными строками
    print("🔍 Поиск рядом с известными паттернами...")
    patterns = [b'HS256', b'vehicle_id', b'timestamp', b'iss']
    
    for pattern in patterns:
        pos = 0
        while True:
            pos = data.find(pattern, pos)
            if pos == -1:
                break
            
            # Ищем в радиусе 128 байт
            start = max(0, pos - 128)
            end = min(len(data), pos + len(pattern) + 128)
            context = data[start:end]
            
            # Извлекаем блоки разной длины
            for offset in range(0, len(context) - 16, 4):
                for size in [16, 24, 32, 48, 64]:
                    if offset + size <= len(context):
                        chunk = context[offset:offset+size]
                        if len(set(chunk)) > size // 4:  # Минимальная энтропия
                            candidates.append(chunk)
            
            pos += 1
    
    print(f"✓ Всего hex кандидатов: {len(candidates)}")
    return candidates

def search_mathematical_keys():
    """Поиск математически сгенерированных ключей"""
    print("🔍 Поиск математических ключей...")
    
    candidates = []
    
    # На основе timestamp
    timestamp = 1753096202
    
    # Различные математические операции
    math_keys = [
        str(timestamp),
        str(timestamp * 2),
        str(timestamp // 2),
        str(timestamp + 123456),
        str(timestamp ^ 0xDEADBEEF),
        hex(timestamp)[2:],
        hex(timestamp * 31337)[2:],
        # Байты timestamp в разном порядке
        struct.pack('>I', timestamp & 0xFFFFFFFF),  # big endian
        struct.pack('<I', timestamp & 0xFFFFFFFF),  # little endian
        struct.pack('>Q', timestamp),  # 64-bit big endian
        struct.pack('<Q', timestamp),  # 64-bit little endian
    ]
    
    # На основе vehicle_id
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    
    # Различные операции с vehicle_id
    try:
        vid_bytes = binascii.unhexlify(vehicle_id)
        math_keys.extend([
            vid_bytes,
            vid_bytes[:16],  # Первые 16 байт
            vid_bytes[8:],   # Последние 8 байт
            vid_bytes + struct.pack('<I', timestamp),  # Комбинация
        ])
    except:
        pass
    
    # На основе "CunBA"
    cunba = b"CunBA"
    math_keys.extend([
        cunba * 6,  # Повторение
        cunba + struct.pack('<I', timestamp),
        cunba + vid_bytes[:11] if len(vid_bytes) >= 11 else cunba,
    ])
    
    candidates.extend(math_keys)
    print(f"✓ Сгенерировано {len(math_keys)} математических кандидатов")
    
    return candidates

def search_combined_keys():
    """Поиск комбинированных ключей"""
    print("🔍 Поиск комбинированных ключей...")
    
    candidates = []
    
    # Базовые компоненты
    components = [
        "CunBA",
        "unlock", 
        "mega",
        "0d79ff047f5cec5bf2ec2ec7d3e464ce",
        "1753096202",
        "HS256",
        "jwt"
    ]
    
    # Комбинации по 2
    for comp1, comp2 in combinations(components, 2):
        candidates.extend([
            comp1 + comp2,
            comp1 + "_" + comp2,
            comp1 + "-" + comp2,
            comp1 + "." + comp2,
            comp2 + comp1,
            comp2 + "_" + comp1,
        ])
    
    # Хэши комбинаций
    import hashlib
    for candidate in candidates[:]:  # Копия списка
        # MD5
        candidates.append(hashlib.md5(candidate.encode()).hexdigest())
        # SHA1 (первые 32 символа)  
        candidates.append(hashlib.sha1(candidate.encode()).hexdigest()[:32])
        # SHA256 (первые 32 символа)
        candidates.append(hashlib.sha256(candidate.encode()).hexdigest()[:32])
    
    print(f"✓ Сгенерировано {len(candidates)} комбинированных кандидатов")
    return candidates

def test_all_hex_candidates(hex_candidates):
    """Тестирование hex кандидатов"""
    print(f"🔑 Тестирование {len(hex_candidates)} hex кандидатов...")
    
    tested = 0
    for candidate in hex_candidates:
        tested += 1
        if tested % 500 == 0:
            print(f"   Протестировано {tested}/{len(hex_candidates)}...")
        
        # Тестируем как есть (bytes)
        if test_key(candidate):
            print(f"🎉 НАЙДЕН HEX КЛЮЧ!")
            print(f"Ключ (hex): {binascii.hexlify(candidate).decode()}")
            print(f"Ключ (ascii): {candidate.decode('ascii', errors='ignore')}")
            return candidate
        
        # Тестируем как hex строку
        hex_str = binascii.hexlify(candidate).decode()
        if test_key(hex_str):
            print(f"🎉 НАЙДЕН HEX STRING КЛЮЧ!")
            print(f"Ключ: {hex_str}")
            return hex_str
    
    print("❌ Hex ключ не найден")
    return None

def main():
    """Главная функция hex анализа"""
    print("🔐 HEX АНАЛИЗ UNLOCK БИНАРНИКА")
    print("="*60)
    print(f"Цель: найти SECRET_KEY в бинарных данных")
    print()
    
    all_candidates = []
    
    # 1. Поиск байтовых паттернов
    hex_candidates = search_byte_patterns()
    all_candidates.extend(hex_candidates)
    
    # 2. Математические ключи  
    math_candidates = search_mathematical_keys()
    all_candidates.extend(math_candidates)
    
    # 3. Комбинированные ключи
    combined_candidates = search_combined_keys()
    all_candidates.extend(combined_candidates)
    
    print(f"\n📊 Всего кандидатов: {len(all_candidates)}")
    
    # Тестируем hex кандидаты
    result = test_all_hex_candidates(hex_candidates[:2000])  # Ограничиваем
    
    if not result:
        # Тестируем остальные
        print(f"🔑 Тестирование остальных {len(combined_candidates)} кандидатов...")
        
        tested = 0
        for candidate in combined_candidates:
            tested += 1
            if tested % 100 == 0:
                print(f"   Протестировано {tested}/{len(combined_candidates)}...")
            
            if test_key(candidate):
                print(f"🎉 НАЙДЕН КОМБИНИРОВАННЫЙ КЛЮЧ!")
                print(f"Ключ: '{candidate}'")
                return candidate
        
        print("❌ Ключ не найден hex анализом")
    
    print("\n💡 Выводы:")
    print("   - Статический анализ не обнаружил SECRET_KEY")
    print("   - Ключ может быть:")
    print("     • Генерирован динамически на сервере")  
    print("     • Зашифрован сложным алгоритмом")
    print("     • Находится в другом файле/библиотеке")
    print("     • Получен через сетевой запрос")

if __name__ == "__main__":
    main()

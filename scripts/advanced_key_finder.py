#!/usr/bin/env python3
"""
Продвинутый поиск SECRET_KEY для JWT токена
Используем все доступные методы для поиска правильного ключа
"""

import jwt
import hashlib
import binascii
import base64
import itertools
import string
from pathlib import Path

# Рабочий токен и его payload
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
WORKING_PAYLOAD = {
    "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
    "iss": "CunBA",
    "timestamp": 1753096202
}

def test_key(key):
    """Тест ключа - возвращает True если ключ правильный"""
    try:
        test_token = jwt.encode(WORKING_PAYLOAD, key, algorithm='HS256')
        return test_token == WORKING_TOKEN
    except:
        return False

def method1_common_keys():
    """Метод 1: Общие ключи и их вариации"""
    print("🔍 Метод 1: Тестирование общих ключей...")
    
    base_words = ["CunBA", "unlock", "secret", "key", "jwt", "mega", "android", "qualcomm", "8155"]
    variations = []
    
    # Простые ключи
    for word in base_words:
        variations.extend([
            word, word.upper(), word.lower(),
            word + "123", word + "_key", word + "_secret",
            "key_" + word, "secret_" + word
        ])
    
    # Комбинации
    combinations = [
        "CunBA_unlock", "unlock_CunBA", "mega_unlock", "CunBA_mega",
        "com.cunba.mega.unlock", "cunba.mega.unlock", "mega.unlock",
        "android_unlock", "qualcomm_unlock"
    ]
    variations.extend(combinations)
    
    # Хэши популярных слов
    for word in ["CunBA", "unlock", "mega"]:
        variations.extend([
            hashlib.md5(word.encode()).hexdigest(),
            hashlib.sha1(word.encode()).hexdigest(),
            hashlib.sha256(word.encode()).hexdigest()[:32],
            hashlib.sha256(word.encode()).hexdigest()
        ])
    
    for key in variations:
        if test_key(key):
            print(f"✅ НАЙДЕН! Метод 1: '{key}'")
            return key
    
    print("❌ Метод 1: не найдено")
    return None

def method2_extract_from_binary():
    """Метод 2: Извлечение из бинарника с расширенным поиском"""
    print("🔍 Метод 2: Расширенное извлечение из unlock бинарника...")
    
    try:
        with open("unlock", "rb") as f:
            binary_data = f.read()
    except:
        print("❌ Файл unlock не найден")
        return None
    
    candidates = set()
    
    # Поиск всех возможных строк длиной от 8 до 64 символов
    for i in range(len(binary_data) - 64):
        for length in range(8, 65):
            if i + length > len(binary_data):
                continue
                
            chunk = binary_data[i:i+length]
            
            # Только ASCII символы
            try:
                candidate = chunk.decode('ascii')
                if all(32 <= ord(c) <= 126 for c in candidate):
                    candidates.add(candidate)
            except:
                continue
    
    print(f"Найдено {len(candidates)} кандидатов из бинарника")
    
    for candidate in list(candidates)[:1000]:  # Ограничиваем до 1000
        if test_key(candidate):
            print(f"✅ НАЙДЕН! Метод 2: '{candidate}'")
            return candidate
    
    print("❌ Метод 2: не найдено")
    return None

def method3_base64_decode():
    """Метод 3: Base64 декодирование найденных строк"""
    print("🔍 Метод 3: Base64 декодирование...")
    
    # Найденные ранее строки из бинарника
    base64_candidates = [
        "sssss3issssssmossssssmssssss/dssssssisssss",
        "sssss3lssssssmossssssRssssss/dsssss3",
        "sssss3issssshssssssbsssssscsssss3ksssss=",
        "c3Nzc3Mzaml0c3Nzc3Ntb3Nzc3Nzc21zc3Nzcy9kc3Nzc3Nzc2lzc3Nzc3M="
    ]
    
    for b64_str in base64_candidates:
        # Попробуем как base64
        try:
            decoded = base64.b64decode(b64_str).decode('ascii', errors='ignore')
            if test_key(decoded):
                print(f"✅ НАЙДЕН! Метод 3 (base64): '{decoded}'")
                return decoded
        except:
            pass
        
        # Попробуем как hex
        try:
            if len(b64_str) % 2 == 0:
                decoded = binascii.unhexlify(b64_str).decode('ascii', errors='ignore')
                if test_key(decoded):
                    print(f"✅ НАЙДЕН! Метод 3 (hex): '{decoded}'")
                    return decoded
        except:
            pass
    
    print("❌ Метод 3: не найдено")
    return None

def method4_xor_decode():
    """Метод 4: XOR декодирование найденных паттернов"""
    print("🔍 Метод 4: XOR декодирование...")
    
    base_strings = [
        "sssss3issssssmossssssmssssss/dssssssisssss",
        "sssss3lssssssmossssssRssssss/dsssss3"
    ]
    
    for base_str in base_strings:
        # Попробуем XOR с разными ключами
        for xor_key in range(1, 256):
            try:
                decoded = ''.join(chr(ord(c) ^ xor_key) for c in base_str)
                # Проверяем, что результат читаемый
                if all(32 <= ord(c) <= 126 for c in decoded):
                    if test_key(decoded):
                        print(f"✅ НАЙДЕН! Метод 4 (XOR 0x{xor_key:02x}): '{decoded}'")
                        return decoded
            except:
                continue
    
    print("❌ Метод 4: не найдено")
    return None

def method5_bruteforce_short():
    """Метод 5: Брутфорс коротких ключей"""
    print("🔍 Метод 5: Брутфорс коротких ключей...")
    
    charset = string.ascii_letters + string.digits + "._-"
    
    # Брутфорс от 1 до 12 символов
    for length in range(1, 13):
        print(f"  Тестируем длину {length}...")
        count = 0
        
        for key_tuple in itertools.product(charset, repeat=length):
            key = ''.join(key_tuple)
            count += 1
            
            if test_key(key):
                print(f"✅ НАЙДЕН! Метод 5 (брутфорс): '{key}'")
                return key
            
            # Ограничиваем количество попыток
            if count > 50000:
                break
    
    print("❌ Метод 5: не найдено")
    return None

def method6_timestamp_based():
    """Метод 6: Ключи основанные на временной метке"""
    print("🔍 Метод 6: Ключи на основе timestamp...")
    
    timestamp = 1753096202
    timestamp_variations = [
        str(timestamp),
        str(timestamp)[-6:],  # Последние 6 цифр
        str(timestamp)[:6],   # Первые 6 цифр
        hex(timestamp)[2:],   # В hex
        f"CunBA_{timestamp}",
        f"unlock_{timestamp}",
        f"key_{timestamp}",
        hashlib.md5(str(timestamp).encode()).hexdigest()[:16]
    ]
    
    for key in timestamp_variations:
        if test_key(key):
            print(f"✅ НАЙДЕН! Метод 6: '{key}'")
            return key
    
    print("❌ Метод 6: не найдено")
    return None

def main():
    """Главная функция поиска"""
    print("🔐 ПРОДВИНУТЫЙ ПОИСК SECRET_KEY")
    print("="*60)
    print(f"Целевой токен: {WORKING_TOKEN[:50]}...")
    print(f"Payload: {WORKING_PAYLOAD}")
    print()
    
    methods = [
        method1_common_keys,
        method2_extract_from_binary, 
        method3_base64_decode,
        method4_xor_decode,
        method6_timestamp_based,
        method5_bruteforce_short  # Последний, так как самый долгий
    ]
    
    for i, method in enumerate(methods, 1):
        print(f"\n🚀 Запускаем метод {i}/{len(methods)}:")
        result = method()
        
        if result:
            print(f"\n🎉 SUCCESS! НАЙДЕН ПРАВИЛЬНЫЙ SECRET_KEY!")
            print(f"Ключ: '{result}'")
            print(f"Длина: {len(result)} символов")
            
            # Проверяем еще раз
            test_token = jwt.encode(WORKING_PAYLOAD, result, algorithm='HS256')
            print(f"Проверка: {'✅ СОВПАДАЕТ' if test_token == WORKING_TOKEN else '❌ НЕ СОВПАДАЕТ'}")
            
            return result
    
    print("\n😞 SECRET_KEY НЕ НАЙДЕН всеми методами")
    print("💡 Возможные причины:")
    print("   - Ключ слишком сложный или длинный")
    print("   - Ключ генерируется динамически")
    print("   - Ключ находится в другом файле/сервере")

if __name__ == "__main__":
    main()

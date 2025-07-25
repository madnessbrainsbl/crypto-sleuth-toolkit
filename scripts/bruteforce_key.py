#!/usr/bin/env python3
"""
Брутфорс SECRET_KEY для рабочего JWT токена
"""

import jwt
import itertools
import string
import hashlib

# Рабочий токен
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

# Payload рабочего токена
KNOWN_PAYLOAD = {
    "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
    "iss": "CunBA",
    "timestamp": 1753096202
}

def try_common_keys():
    """Попробовать общие ключи"""
    common_keys = [
        "CunBA",
        "cunba", 
        "CUNBA",
        "unlock",
        "UNLOCK",
        "secret",
        "SECRET",
        "key",
        "KEY", 
        "jwt",
        "JWT",
        "HS256",
        "vehicle",
        "android",
        "qualcomm",
        "8155",
        # Комбинации
        "CunBA_secret",
        "CunBA_key",
        "CunBA_unlock",
        "unlock_CunBA",
        "vehicle_unlock",
        "mega_unlock",
        "com.cunba.mega.unlock",
        # Хэши
        hashlib.md5(b"CunBA").hexdigest(),
        hashlib.sha1(b"CunBA").hexdigest(),
        hashlib.sha256(b"CunBA").hexdigest(),
    ]
    
    print("🔍 Тестирование общих ключей...")
    for key in common_keys:
        if test_key(key):
            return key
    return None

def test_key(key):
    """Тестирование конкретного ключа"""
    try:
        # Генерируем токен с этим ключом
        test_token = jwt.encode(KNOWN_PAYLOAD, key, algorithm='HS256')
        
        # Сравниваем с рабочим токеном
        if test_token == WORKING_TOKEN:
            print(f"✅ НАЙДЕН ПРАВИЛЬНЫЙ КЛЮЧ!")
            print(f"   Ключ: '{key}'")
            print(f"   Длина: {len(key)} символов")
            return True
            
        # Также пробуем декодировать оригинальный токен
        decoded = jwt.decode(WORKING_TOKEN, key, algorithms=['HS256'])
        if decoded == KNOWN_PAYLOAD:
            print(f"✅ НАЙДЕН ПРАВИЛЬНЫЙ КЛЮЧ (через декодирование)!")
            print(f"   Ключ: '{key}'")
            return True
            
    except jwt.InvalidSignatureError:
        pass
    except Exception:
        pass
    
    return False

def try_variations_of_found_keys():
    """Попробовать вариации найденных ключей"""
    base_keys = [
        "sssss3issssssmossssssmssssss/dssssssisssss",
        "sssss3lssssssmossssssRssssss/dsssss3",
        "CunBA",
    ]
    
    print("🔍 Тестирование вариаций найденных ключей...")
    
    for base_key in base_keys:
        # Попробуем разные форматы
        variations = [
            base_key.upper(),
            base_key.lower(),
            base_key.strip(),
            base_key.replace('s', ''),
            base_key.replace('sss', ''),
            # Попробуем интерпретировать как hex
        ]
        
        for variation in variations:
            if test_key(variation):
                return variation
    
    return None

def try_short_bruteforce():
    """Брутфорс коротких ключей"""
    print("🔍 Брутфорс коротких ключей (1-8 символов)...")
    
    charset = string.ascii_letters + string.digits + "_-."
    
    for length in range(1, 9):
        print(f"   Пробуем длину {length}...")
        count = 0
        for key_tuple in itertools.product(charset, repeat=length):
            key = ''.join(key_tuple)
            count += 1
            
            if test_key(key):
                return key
                
            # Ограничиваем количество попыток
            if count > 10000:
                break
    
    return None

def main():
    print("🔐 Поиск правильного SECRET_KEY для рабочего токена")
    print("="*60)
    print(f"Рабочий токен: {WORKING_TOKEN[:50]}...")
    print(f"Известный payload: {KNOWN_PAYLOAD}")
    print()
    
    # 1. Пробуем общие ключи
    key = try_common_keys()
    if key:
        return key
    
    # 2. Пробуем вариации найденных ключей
    key = try_variations_of_found_keys()
    if key:
        return key
    
    # 3. Короткий брутфорс
    key = try_short_bruteforce()
    if key:
        return key
    
    print("😞 Ключ не найден в доступном пространстве поиска")
    print("💡 Возможно, ключ слишком длинный или сложный для брутфорса")

if __name__ == "__main__":
    main()

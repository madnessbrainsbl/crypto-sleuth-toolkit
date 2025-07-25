#!/usr/bin/env python3
"""
Проверка рабочего токена с разными SECRET_KEY кандидатами
"""

import jwt
import sys

# Рабочий токен, который сработал
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

# Кандидаты SECRET_KEY найденные при анализе
KEY_CANDIDATES = [
    "sssss3issssssmossssssmssssss/dssssssisssss",
    "sssss3issssshssssssbsssssscsssss3ksssss=",
    "sssss3lssssssmossssssRssssss/dsssss3",
    "sssss3lssssssmossssssmssssss/dsssss3",
    "CunBA",  # Простой ключ
    "SECRET_KEY",  # Стандартный ключ
]

def test_token_with_keys():
    """Тестирование рабочего токена с разными ключами"""
    print("🔐 Тестирование рабочего токена с разными SECRET_KEY:")
    print("="*60)
    
    for i, key in enumerate(KEY_CANDIDATES, 1):
        try:
            # Пытаемся декодировать токен с этим ключом
            decoded = jwt.decode(WORKING_TOKEN, key, algorithms=['HS256'])
            print(f"✅ КЛЮЧ #{i} РАБОТАЕТ!")
            print(f"   Ключ: {key}")
            print(f"   Декодированный payload: {decoded}")
            print()
            return key
        except jwt.InvalidSignatureError:
            print(f"❌ Ключ #{i} НЕ работает: {key[:30]}...")
        except Exception as e:
            print(f"⚠️  Ключ #{i} ошибка: {e}")
    
    print("😞 Ни один из кандидатов не подошел!")
    return None

def recreate_token_with_found_key(correct_key):
    """Пересоздание токена с найденным ключом"""
    if not correct_key:
        return
        
    print("\n🔄 Пересоздание токена с найденным ключом:")
    print("="*50)
    
    # Payload из рабочего токена
    payload = {
        "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
        "iss": "CunBA", 
        "timestamp": 1753096202
    }
    
    try:
        recreated_token = jwt.encode(payload, correct_key, algorithm='HS256')
        print(f"🎯 Пересозданный токен:")
        print(f"   {recreated_token}")
        
        # Проверяем, идентичен ли он оригинальному
        if recreated_token == WORKING_TOKEN:
            print("✅ ИДЕНТИЧЕН оригинальному!")
        else:
            print("⚠️  Отличается от оригинального")
            
    except Exception as e:
        print(f"❌ Ошибка создания токена: {e}")

if __name__ == "__main__":
    print("🔍 Анализ рабочего JWT токена")
    print(f"Токен: {WORKING_TOKEN}")
    print()
    
    # Декодируем без проверки подписи для информации
    try:
        decoded_info = jwt.decode(WORKING_TOKEN, options={"verify_signature": False})
        print("📋 Информация о токене:")
        for key, value in decoded_info.items():
            print(f"   {key}: {value}")
        print()
    except Exception as e:
        print(f"Ошибка декодирования: {e}")
    
    # Тестируем ключи
    working_key = test_token_with_keys()
    
    # Пересоздаем токен с найденным ключом
    recreate_token_with_found_key(working_key)

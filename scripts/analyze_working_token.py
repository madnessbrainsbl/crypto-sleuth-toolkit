#!/usr/bin/env python3
"""
Анализ рабочего токена для определения правильного SECRET_KEY
"""

import jwt
import json
from datetime import datetime

# Рабочий токен (который активировал unlock)
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

# Нерабочий токен (мой сгенерированный)
MY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5Njc2MSwiZXhwIjoxNzUzMDk3MDYxfQ.StCOSqg0VcOs3UTTOfYsq1JWitZ9bLL9gTepJD8LMuY"

def analyze_tokens():
    """Анализ обоих токенов"""
    print("🔍 Анализ рабочего и нерабочего токенов")
    print("="*60)
    
    print("\n📊 РАБОЧИЙ ТОКЕН:")
    print("-" * 30)
    try:
        working_decoded = jwt.decode(WORKING_TOKEN, options={"verify_signature": False})
        print(f"Header: {jwt.get_unverified_header(WORKING_TOKEN)}")
        print(f"Payload: {json.dumps(working_decoded, indent=2)}")
        
        if 'timestamp' in working_decoded:
            ts = working_decoded['timestamp']
            dt = datetime.fromtimestamp(ts)
            print(f"Время создания: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Timestamp: {ts}")
    except Exception as e:
        print(f"Ошибка: {e}")
    
    print("\n📊 МОЙ ТОКЕН:")
    print("-" * 30)
    try:
        my_decoded = jwt.decode(MY_TOKEN, options={"verify_signature": False})
        print(f"Header: {jwt.get_unverified_header(MY_TOKEN)}")
        print(f"Payload: {json.dumps(my_decoded, indent=2)}")
        
        if 'timestamp' in my_decoded:
            ts = my_decoded['timestamp']
            dt = datetime.fromtimestamp(ts)
            print(f"Время создания: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Timestamp: {ts}")
    except Exception as e:
        print(f"Ошибка: {e}")

def try_reverse_engineer_key():
    """Попытка определить SECRET_KEY через обратную инженерию"""
    print("\n🔓 Попытка определить SECRET_KEY рабочего токена:")
    print("="*50)
    
    # Известный payload рабочего токена
    working_payload = {
        "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
        "iss": "CunBA",
        "timestamp": 1753096202
    }
    
    # Список возможных ключей для проверки
    possible_keys = [
        # Простые ключи
        "CunBA",
        "unlock", 
        "secret",
        "key",
        "mega",
        "android",
        # Комбинации
        "CunBA_unlock",
        "mega_unlock",
        "cunba_secret",
        # Найденные ранее ключи
        "sssss3issssssmossssssmssssss/dssssssisssss",
        "sssss3lssssssmossssssRssssss/dsssss3",
        # Хэши
        "5d41402abc4b2a76b9719d911017c592",  # md5("CunBA")
        # Вариации с временной меткой
        f"CunBA_{1753096202}",
        f"unlock_{1753096202}",
        # Base64 вариации найденных ключей
        "c3Nzc3Mzaml0c3Nzc3Ntb3Nzc3Nzc21zc3Nzcy9kc3Nzc3Nzc2lzc3Nzc3M=",
    ]
    
    print(f"Тестируем {len(possible_keys)} возможных ключей...")
    
    for i, key in enumerate(possible_keys):
        try:
            # Генерируем токен с этим ключом
            test_token = jwt.encode(working_payload, key, algorithm='HS256')
            
            if test_token == WORKING_TOKEN:
                print(f"\n🎉 НАЙДЕН ПРАВИЛЬНЫЙ SECRET_KEY!")
                print(f"Ключ #{i+1}: '{key}'")
                print(f"Длина: {len(key)} символов")
                print(f"Тип: {type(key)}")
                return key
                
        except Exception as e:
            continue
    
    print("❌ SECRET_KEY не найден среди кандидатов")
    return None

def create_working_generator(secret_key):
    """Создание генератора с найденным ключом"""
    if not secret_key:
        return
        
    print(f"\n🔧 Создание генератора с найденным ключом:")
    print("="*50)
    
    generator_code = f'''#!/usr/bin/env python3
"""
Рабочий генератор JWT токенов для unlock системы
SECRET_KEY найден через обратную инженерию рабочего токена
"""

import jwt
from datetime import datetime

# ПРАВИЛЬНЫЙ SECRET_KEY (найден через анализ рабочего токена)
SECRET_KEY = "{secret_key}"

def generate_unlock_token(vehicle_id):
    """Генерация рабочего JWT токена для unlock"""
    payload = {{
        "vehicle_id": vehicle_id,
        "iss": "CunBA",
        "timestamp": int(datetime.now().timestamp())
    }}
    
    try:
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token
    except Exception as e:
        print(f"Ошибка генерации токена: {{e}}")
        return None

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        vehicle_id = sys.argv[1]
    else:
        vehicle_id = input("Введите vehicle_id: ")
    
    token = generate_unlock_token(vehicle_id)
    if token:
        print("✅ Сгенерированный JWT токен:")
        print("="*80)
        print(token)
        print("="*80)
'''
    
    with open("D:/vzlom/working_generator.py", "w", encoding="utf-8") as f:
        f.write(generator_code)
    
    print(f"✅ Создан файл working_generator.py с правильным ключом")

if __name__ == "__main__":
    # Анализируем токены
    analyze_tokens()
    
    # Пытаемся найти SECRET_KEY
    found_key = try_reverse_engineer_key()
    
    # Создаем рабочий генератор
    create_working_generator(found_key)

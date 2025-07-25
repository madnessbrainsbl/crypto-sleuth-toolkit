#!/usr/bin/env python3
"""
Точный поиск SECRET_KEY для рабочего токена
Используем известные рабочие данные для обратной инженерии
"""

import jwt
import hashlib
import hmac
import base64
import binascii
import json

# 100% РАБОЧИЙ ТОКЕН (который активировал unlock)
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

# ТОЧНЫЙ PAYLOAD рабочего токена
EXACT_PAYLOAD = {
    "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
    "iss": "CunBA", 
    "timestamp": 1753096202
}

def test_exact_key(key):
    """Тест ключа с точным payload"""
    try:
        test_token = jwt.encode(EXACT_PAYLOAD, key, algorithm='HS256')
        return test_token == WORKING_TOKEN
    except:
        return False

def comprehensive_key_search():
    """Всесторонний поиск ключа"""
    print("🔍 ВСЕСТОРОННИЙ ПОИСК SECRET_KEY")
    print("="*60)
    print(f"Целевой токен: {WORKING_TOKEN}")
    print(f"Payload: {EXACT_PAYLOAD}")
    print()
    
    # Все возможные кандидаты ключей
    key_candidates = []
    
    # 1. Прямые кандидаты из переписки
    direct_candidates = [
        "CunBA",  # Самый очевидный
        "sssss3issssssmossssssmssssss/dssssssisssss",  # Из working_script.py
        "sssss3lssssssmossssssRssssss/dsssss3",  # Другая найденная строка
    ]
    key_candidates.extend(direct_candidates)
    
    # 2. Vehicle ID и timestamp комбинации
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    timestamp = 1753096202
    
    vid_candidates = [
        vehicle_id,
        vehicle_id.upper(),
        str(timestamp),
        f"CunBA_{vehicle_id}",
        f"CunBA_{timestamp}",
        f"unlock_{vehicle_id}",
        f"mega_{vehicle_id}_{timestamp}",
    ]
    key_candidates.extend(vid_candidates)
    
    # 3. Хэши всех базовых строк
    base_strings = ["CunBA", "unlock", "mega", vehicle_id, str(timestamp)]
    for base in base_strings:
        key_candidates.extend([
            hashlib.md5(base.encode()).hexdigest(),
            hashlib.sha1(base.encode()).hexdigest(),
            hashlib.sha256(base.encode()).hexdigest(),
            hashlib.sha256(base.encode()).hexdigest()[:32],
            hashlib.sha256(base.encode()).hexdigest()[:16],
        ])
    
    # 4. Из ELF файла - попробуем извлечь строки
    try:
        with open("unlock", "rb") as f:
            binary_data = f.read()
        
        # Поиск строк 8-64 символа  
        strings = []
        current = ""
        for byte in binary_data:
            if 32 <= byte <= 126:  # ASCII
                current += chr(byte)
            else:
                if 8 <= len(current) <= 64:
                    strings.append(current)
                current = ""
        
        # Добавляем уникальные строки
        unique_strings = list(set(strings))[:500]  # Ограничиваем
        key_candidates.extend(unique_strings)
        print(f"Добавлено {len(unique_strings)} строк из бинарника")
        
    except:
        print("Бинарник unlock не найден")
    
    # 5. Base64 декодированные варианты
    b64_candidates = [
        "c3Nzc3Mzaml0c3Nzc3Ntb3Nzc3Nzc21zc3Nzcy9kc3Nzc3Nzc2lzc3Nzc3M=",
        "Y3Nzc3MzaW1vY3Nzc3Ntb3Nzc3Nzc21zc3Nzcy9kc3Nzc3Nzc2lzc3Nzc3M=",
    ]
    
    for b64 in b64_candidates:
        try:
            decoded = base64.b64decode(b64).decode('ascii', errors='ignore')
            key_candidates.append(decoded)
        except:
            pass
    
    # Убираем дубликаты
    key_candidates = list(set(key_candidates))
    print(f"Всего кандидатов для тестирования: {len(key_candidates)}")
    print()
    
    # Тестирование всех кандидатов
    for i, key in enumerate(key_candidates):
        if i % 1000 == 0 and i > 0:
            print(f"Протестировано {i}/{len(key_candidates)}...")
        
        if test_exact_key(key):
            print(f"\n🎉 НАЙДЕН ПРАВИЛЬНЫЙ SECRET_KEY!")
            print(f"Ключ: '{key}'")
            print(f"Длина: {len(key)} символов") 
            print(f"Тип: {type(key)}")
            
            # Двойная проверка
            verification_token = jwt.encode(EXACT_PAYLOAD, key, algorithm='HS256')
            print(f"Проверка совпадения: {'✅ ДА' if verification_token == WORKING_TOKEN else '❌ НЕТ'}")
            
            return key
    
    print("\n❌ SECRET_KEY не найден среди всех кандидатов")
    return None

def create_final_generator(secret_key):
    """Создание финального генератора токенов"""
    if not secret_key:
        return
    
    generator_code = f'''#!/usr/bin/env python3
"""
ФИНАЛЬНЫЙ ГЕНЕРАТОР JWT ТОКЕНОВ
SECRET_KEY найден через полный анализ рабочего токена
"""
import jwt
from datetime import datetime

# ПРАВИЛЬНЫЙ SECRET_KEY
SECRET_KEY = "{secret_key}"

def generate_unlock_token(vehicle_id):
    """Генерация JWT токена для unlock системы"""
    payload = {{
        "vehicle_id": vehicle_id,
        "iss": "CunBA",
        "timestamp": int(datetime.now().timestamp())
    }}
    
    try:
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token
    except Exception as e:
        print(f"Ошибка генерации: {{e}}")
        return None

if __name__ == "__main__":
    import sys
    
    # Получаем vehicle_id
    if len(sys.argv) > 1:
        vehicle_id = sys.argv[1]
    else:
        vehicle_id = input("Введите vehicle_id: ")
    
    # Генерируем токен
    token = generate_unlock_token(vehicle_id)
    
    if token:
        print("\\n✅ Сгенерированный JWT токен:")
        print("=" * 80)
        print(token)
        print("=" * 80)
        print("\\n💡 Используйте этот токен в ./unlock команде")
    else:
        print("❌ Не удалось сгенерировать токен")
'''
    
    with open("D:/vzlom/final_working_generator.py", "w", encoding="utf-8") as f:
        f.write(generator_code)
    
    print(f"\n✅ Создан final_working_generator.py с найденным ключом!")

if __name__ == "__main__":
    found_key = comprehensive_key_search()
    create_final_generator(found_key)

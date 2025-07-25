#!/usr/bin/env python3
"""
Анализ разницы между рабочим и нерабочим JWT токенами
для определения правильного SECRET_KEY
"""

import jwt
import json
import base64
import binascii
import hashlib
import hmac
import itertools
from datetime import datetime

# 100% РАБОЧИЙ ТОКЕН (сработал, машина перезагрузилась) 
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

# НЕ РАБОЧИЙ ТОКЕН (сгенерированный, не прошел)
NON_WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5Njc2MSwiZXhwIjoxNzUzMDk3MDYxfQ.StCOSqg0VcOs3UTTOfYsq1JWitZ9bLL9gTepJD8LMuY"

def analyze_token_differences():
    """Анализ различий между токенами"""
    print("🔍 АНАЛИЗ РАЗЛИЧИЙ МЕЖДУ ТОКЕНАМИ")
    print("="*60)
    
    # Декодируем оба токена
    working_payload = jwt.decode(WORKING_TOKEN, options={"verify_signature": False})
    non_working_payload = jwt.decode(NON_WORKING_TOKEN, options={"verify_signature": False})
    
    print("РАБОЧИЙ ТОКЕН payload:")
    print(json.dumps(working_payload, indent=2))
    
    print("\nНЕ РАБОЧИЙ ТОКЕН payload:")
    print(json.dumps(non_working_payload, indent=2))
    
    # Найти различия
    print("\n🔎 РАЗЛИЧИЯ:")
    for key in set(working_payload.keys()) | set(non_working_payload.keys()):
        working_val = working_payload.get(key, "ОТСУТСТВУЕТ")
        non_working_val = non_working_payload.get(key, "ОТСУТСТВУЕТ")
        
        if working_val != non_working_val:
            print(f"  {key}:")
            print(f"    Рабочий: {working_val}")
            print(f"    Не рабочий: {non_working_val}")
    
    return working_payload, non_working_payload

def reverse_engineer_from_working_token():
    """Обратная инженерия SECRET_KEY из рабочего токена"""
    print("\n🔓 ПОИСК SECRET_KEY ЧЕРЕЗ ОБРАТНУЮ ИНЖЕНЕРИЮ")
    print("="*60)
    
    # Точные данные рабочего токена
    EXACT_PAYLOAD = {
        "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
        "iss": "CunBA",
        "timestamp": 1753096202
    }
    
    # Компоненты для подписи
    parts = WORKING_TOKEN.split('.')
    message = f"{parts[0]}.{parts[1]}".encode('ascii')
    target_signature = base64.urlsafe_b64decode(parts[2] + '==')
    
    print(f"Сообщение для подписи: {message.decode()}")
    print(f"Целевая подпись (hex): {binascii.hexlify(target_signature).decode()}")
    
    # Генерируем кандидаты ключей на основе имеющейся информации
    key_candidates = generate_comprehensive_key_candidates()
    
    print(f"\nТестируем {len(key_candidates)} кандидатов ключей...")
    
    for i, key in enumerate(key_candidates):
        if i % 1000 == 0 and i > 0:
            print(f"Протестировано {i}/{len(key_candidates)}...")
        
        try:
            # Тестируем HMAC напрямую
            test_signature = hmac.new(key.encode('utf-8'), message, hashlib.sha256).digest()
            
            if test_signature == target_signature:
                print(f"\n🎉 НАЙДЕН SECRET_KEY!")
                print(f"Ключ: '{key}'")
                print(f"Длина: {len(key)} символов")
                
                # Двойная проверка через JWT библиотеку
                verification_token = jwt.encode(EXACT_PAYLOAD, key, algorithm='HS256')
                if verification_token == WORKING_TOKEN:
                    print("✅ Подтверждено через JWT библиотеку!")
                    return key
                else:
                    print("❌ JWT библиотека дает другой результат")
                
        except Exception as e:
            continue
    
    print("❌ SECRET_KEY не найден")
    return None

def generate_comprehensive_key_candidates():
    """Генерация всесторонних кандидатов ключей"""
    candidates = set()
    
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    timestamp = 1753096202
    
    # 1. Базовые строки
    base_strings = [
        "CunBA", "cunba", "CUNBA",
        "unlock", "UNLOCK", "Unlock",
        "mega", "MEGA", "Mega",
        "secret", "SECRET", "Secret",
        "key", "KEY", "Key",
        "jwt", "JWT",
        "android", "Android", "ANDROID",
        "qualcomm", "Qualcomm", "QUALCOMM",
        "8155", "qnx", "QNX",
        vehicle_id, vehicle_id.upper(),
        str(timestamp)
    ]
    candidates.update(base_strings)
    
    # 2. Комбинации с разделителями
    separators = ["", "_", "-", ".", ":", "/", "\\", "|"]
    combinations = [
        ("CunBA", "unlock"), ("unlock", "CunBA"),
        ("CunBA", "mega"), ("mega", "CunBA"),
        ("CunBA", "secret"), ("secret", "CunBA"),
        ("CunBA", "key"), ("key", "CunBA"),
        ("CunBA", vehicle_id), (vehicle_id, "CunBA"),
        ("CunBA", str(timestamp)), (str(timestamp), "CunBA"),
        ("unlock", "mega"), ("mega", "unlock"),
        ("unlock", vehicle_id), (vehicle_id, "unlock"),
        ("unlock", str(timestamp)), (str(timestamp), "unlock"),
    ]
    
    for combo in combinations:
        for sep in separators:
            candidates.add(sep.join(combo))
    
    # 3. Хэши различных данных
    hash_sources = [
        "CunBA", "unlock", "mega", vehicle_id, str(timestamp),
        f"CunBA{vehicle_id}", f"unlock{vehicle_id}", f"CunBA{timestamp}",
        f"{vehicle_id}CunBA", f"{vehicle_id}unlock", f"{timestamp}CunBA"
    ]
    
    for source in hash_sources:
        candidates.add(hashlib.md5(source.encode()).hexdigest())
        candidates.add(hashlib.sha1(source.encode()).hexdigest())
        candidates.add(hashlib.sha256(source.encode()).hexdigest())
        candidates.add(hashlib.sha256(source.encode()).hexdigest()[:32])
        candidates.add(hashlib.sha256(source.encode()).hexdigest()[:16])
        candidates.add(hashlib.sha256(source.encode()).hexdigest()[:8])
    
    # 4. Временные вариации
    dt = datetime.fromtimestamp(timestamp)
    time_variations = [
        str(timestamp)[:10], str(timestamp)[-6:],
        hex(timestamp)[2:], hex(timestamp)[2:].upper(),
        str(dt.year), str(dt.month), str(dt.day),
        f"{dt.year}{dt.month:02d}{dt.day:02d}",
        f"{dt.hour:02d}{dt.minute:02d}{dt.second:02d}",
        f"{dt.year}{dt.month:02d}{dt.day:02d}{dt.hour:02d}{dt.minute:02d}",
    ]
    candidates.update(time_variations)
    
    # 5. Системные данные QNX
    system_variations = [
        "qnx", "QNX", "Qnx",
        "automotive", "AUTOMOTIVE",
        "vehicle", "VEHICLE", "Vehicle",
        "huron", "HURON", "Huron",
        "mega_platform", "MEGA_PLATFORM",
        "cunba_mega", "CUNBA_MEGA",
        "unlock_cunba", "UNLOCK_CUNBA"
    ]
    candidates.update(system_variations)
    
    # 6. Математические преобразования
    try:
        vid_int = int(vehicle_id, 16)
        math_results = [
            str(vid_int % 1000000),
            str(vid_int % 100000),
            str(vid_int % 10000),
            str((vid_int + timestamp) % 0xFFFFFFFF),
            str(vid_int ^ timestamp),
            str(abs(hash(vehicle_id)) % 1000000),
            hex(vid_int % 0xFFFFFFFF)[2:],
            hex((vid_int + timestamp) % 0xFFFFFFFF)[2:],
        ]
        candidates.update(math_results)
    except:
        pass
    
    # 7. Base64 вариации найденных в бинарнике
    binary_strings = [
        "sssss3issssssmossssssmssssss/dssssssisssss",
        "sssss3lssssssmossssssRssssss/dsssss3",
    ]
    
    for b_str in binary_strings:
        candidates.add(b_str)
        # Попробуем как base64
        try:
            decoded = base64.b64decode(b_str + '==').decode('ascii', errors='ignore')
            if len(decoded) >= 4:
                candidates.add(decoded)
        except:
            pass
        
        # XOR декодирование
        for xor_key in range(1, 128):
            try:
                decoded = ''.join(chr(ord(c) ^ xor_key) for c in b_str if 32 <= (ord(c) ^ xor_key) <= 126)
                if len(decoded) >= 8:
                    candidates.add(decoded)
            except:
                pass
    
    # Убираем пустые строки и слишком короткие
    candidates = {c for c in candidates if c and len(c) >= 1}
    
    return list(candidates)

def create_working_generator(secret_key):
    """Создание рабочего генератора токенов"""
    if not secret_key:
        print("❌ Не удалось найти SECRET_KEY")
        return
    
    generator_code = f'''#!/usr/bin/env python3
"""
РАБОЧИЙ ГЕНЕРАТОР JWT ТОКЕНОВ
SECRET_KEY найден через анализ 100% рабочего токена
"""
import jwt
from datetime import datetime

# НАЙДЕННЫЙ SECRET_KEY
SECRET_KEY = "{secret_key}"

def generate_unlock_token(vehicle_id):
    """Генерация рабочего JWT токена для unlock системы"""
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

def test_token_with_known_good():
    """Тестирование с известным рабочим токеном"""
    test_payload = {{
        "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
        "iss": "CunBA",
        "timestamp": 1753096202
    }}
    
    test_token = jwt.encode(test_payload, SECRET_KEY, algorithm='HS256')
    expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
    
    print(f"Тест генерации: {{'✅ УСПЕХ' if test_token == expected else '❌ НЕУДАЧА'}}")
    if test_token == expected:
        print("Ключ работает корректно!")
    else:
        print(f"Ожидался: {{expected}}")
        print(f"Получен:  {{test_token}}")

if __name__ == "__main__":
    import sys
    
    # Тест с известным токеном
    print("🧪 Тестирование SECRET_KEY...")
    test_token_with_known_good()
    print()
    
    # Генерация нового токена
    if len(sys.argv) > 1:
        vehicle_id = sys.argv[1]
    else:
        vehicle_id = input("Введите vehicle_id: ")
    
    token = generate_unlock_token(vehicle_id)
    
    if token:
        print("\\n✅ Сгенерированный JWT токен:")
        print("=" * 80)
        print(token)
        print("=" * 80)
        print("\\n💡 Используйте этот токен в unlock команде")
    else:
        print("❌ Не удалось сгенерировать токен")
'''
    
    with open("D:/vzlom/working_unlock_generator.py", "w", encoding="utf-8") as f:
        f.write(generator_code)
    
    print(f"\n✅ Создан working_unlock_generator.py с найденным SECRET_KEY!")
    print(f"Ключ: '{secret_key}'")

def main():
    """Главная функция"""
    print("🚀 TOKEN DIFFERENCE ANALYZER")
    print("="*80)
    print("Анализ различий между рабочим и нерабочим токенами")
    print("Поиск SECRET_KEY через обратную инженерию")
    print()
    
    # Анализ различий
    working_payload, non_working_payload = analyze_token_differences()
    
    print("\n📝 КЛЮЧЕВЫЕ ВЫВОДЫ:")
    print("- Рабочий токен НЕ содержит поле 'exp'")
    print("- Нерабочий токен содержит поле 'exp' (время истечения)")
    print("- Система может отклонять токены с полем 'exp'")
    print("- Разные timestamp указывают на разное время создания")
    
    # Поиск SECRET_KEY
    found_key = reverse_engineer_from_working_token()
    
    # Создание генератора
    create_working_generator(found_key)
    
    if found_key:
        print(f"\n🎉 МИССИЯ ВЫПОЛНЕНА!")
        print(f"SECRET_KEY найден: '{found_key}'")
        print(f"Создан рабочий генератор: working_unlock_generator.py")
    else:
        print(f"\n😞 SECRET_KEY не найден автоматически")
        print("💡 Рекомендации:")
        print("   1. Проверьте другие системные данные (hostname, MAC и т.д.)")
        print("   2. Попробуйте статический анализ с Ghidra/IDA")
        print("   3. Исследуйте другие файлы в системе")

if __name__ == "__main__":
    main()

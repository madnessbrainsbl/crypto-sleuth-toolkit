#!/usr/bin/env python3
"""
Финальный анализатор для поиска SECRET_KEY
Максимальное покрытие всех возможных вариантов
"""

import jwt
import hashlib
import hmac
import base64
import binascii
import itertools
import string
from datetime import datetime

# 100% рабочий токен
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

EXACT_PAYLOAD = {
    "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
    "iss": "CunBA",
    "timestamp": 1753096202
}

def test_key_direct(key):
    """Прямой тест ключа через HMAC и JWT"""
    try:
        # Проверяем через JWT библиотеку
        test_token = jwt.encode(EXACT_PAYLOAD, key, algorithm='HS256')
        return test_token == WORKING_TOKEN
    except:
        return False

def generate_extended_candidates():
    """Расширенная генерация кандидатов"""
    print("🔍 Генерируем расширенный список кандидатов...")
    
    candidates = set()
    
    # Базовые данные
    vehicle_id = "0d79ff047f5cec5bf2ec2ec7d3e464ce"
    timestamp = 1753096202
    dt = datetime.fromtimestamp(timestamp)
    
    # 1. Все возможные строки из переписки разработчика
    dev_strings = [
        "CunBA", "cunba", "CUNBA",
        "unlock", "UNLOCK", "Unlock", 
        "mega", "MEGA", "Mega",
        "android", "Android", "ANDROID",
        "qualcomm", "Qualcomm", "QUALCOMM",
        "8155", "qnx", "QNX", "Qnx",
        "huron", "HURON", "Huron",
        "secret", "SECRET", "Secret",
        "key", "KEY", "Key",
        "jwt", "JWT", "Jwt",
        "password", "PASSWORD", "Password",
        "pass", "PASS", "Pass",
        "token", "TOKEN", "Token",
        "auth", "AUTH", "Auth",
        "sign", "SIGN", "Sign",
        "hmac", "HMAC", "Hmac",
        "sha256", "SHA256", "Sha256",
        "vehicle", "VEHICLE", "Vehicle",
        "automotive", "AUTOMOTIVE", "Automotive",
        "platform", "PLATFORM", "Platform"
    ]
    candidates.update(dev_strings)
    
    # 2. Строки из бинарника (найденные ранее)
    binary_strings = [
        "sssss3issssssmossssssmssssss/dssssssisssss",
        "sssss3lssssssmossssssRssssss/dsssss3",
        "sssss3issssshssssssbsssssscsssss3ksssss=",
        "c3Nzc3Mzaml0c3Nzc3Ntb3Nzc3Nzc21zc3Nzcy9kc3Nzc3Nzc2lzc3Nzc3M=",
    ]
    candidates.update(binary_strings)
    
    # 3. Данные из токена
    token_based = [
        vehicle_id, vehicle_id.upper(), vehicle_id.lower(),
        str(timestamp), hex(timestamp)[2:], hex(timestamp)[2:].upper(),
        "CunBA", "cunba", "CUNBA"
    ]
    candidates.update(token_based)
    
    # 4. Временные вариации
    time_variants = [
        str(timestamp)[:10], str(timestamp)[:8], str(timestamp)[:6],
        str(timestamp)[-10:], str(timestamp)[-8:], str(timestamp)[-6:],
        str(dt.year), str(dt.month), str(dt.day),
        str(dt.hour), str(dt.minute), str(dt.second),
        f"{dt.year}{dt.month:02d}{dt.day:02d}",
        f"{dt.hour:02d}{dt.minute:02d}{dt.second:02d}",
        f"{dt.year}{dt.month:02d}",
        f"{dt.month:02d}{dt.day:02d}",
    ]
    candidates.update(time_variants)
    
    # 5. Комбинации с разделителями
    separators = ["", "_", "-", ".", ":", "/", "\\", "|", "+", "=", "@", "#", "$", "%", "^", "&", "*"]
    
    base_combinations = [
        ("CunBA", "unlock"), ("unlock", "CunBA"),
        ("CunBA", "mega"), ("mega", "CunBA"),
        ("CunBA", "secret"), ("secret", "CunBA"),
        ("CunBA", "key"), ("key", "CunBA"),
        ("CunBA", "password"), ("password", "CunBA"),
        ("CunBA", vehicle_id), (vehicle_id, "CunBA"),
        ("CunBA", str(timestamp)), (str(timestamp), "CunBA"),
        ("unlock", "mega"), ("mega", "unlock"),
        ("unlock", "key"), ("key", "unlock"),
        ("unlock", vehicle_id), (vehicle_id, "unlock"),
        ("mega", "key"), ("key", "mega"),
        ("mega", vehicle_id), (vehicle_id, "mega"),
    ]
    
    for combo in base_combinations:
        for sep in separators[:8]:  # Ограничиваем количество
            candidates.add(sep.join(combo))
    
    # 6. Хэши всех базовых строк
    hash_sources = list(candidates)[:50]  # Берем первые 50 для хэширования
    
    for source in hash_sources:
        if isinstance(source, str) and len(source) >= 3:
            try:
                candidates.add(hashlib.md5(source.encode()).hexdigest())
                candidates.add(hashlib.sha1(source.encode()).hexdigest())
                candidates.add(hashlib.sha256(source.encode()).hexdigest())
                candidates.add(hashlib.sha256(source.encode()).hexdigest()[:32])
                candidates.add(hashlib.sha256(source.encode()).hexdigest()[:16])
                candidates.add(hashlib.sha256(source.encode()).hexdigest()[:8])
            except:
                pass
    
    # 7. Системные комбинации
    system_combos = [
        f"com.cunba.mega.unlock",
        f"cunba.mega.unlock", 
        f"mega.unlock",
        f"unlock.cunba",
        f"android.unlock",
        f"qnx.unlock",
        f"huron.unlock",
        f"qualcomm.unlock",
        f"8155.unlock",
    ]
    candidates.update(system_combos)
    
    # 8. Математические операции с vehicle_id
    try:
        vid_int = int(vehicle_id, 16)
        math_operations = [
            str(vid_int % 1000000),
            str(vid_int % 100000),
            str(vid_int % 10000),
            str(vid_int % 1000),
            str((vid_int + timestamp) % 0xFFFFFFFF),
            str(vid_int ^ timestamp),
            str(vid_int ^ 0x12345678),
            str(abs(hash(vehicle_id)) % 1000000),
            hex(vid_int % 0xFFFFFFFF)[2:],
            hex((vid_int + timestamp) % 0xFFFFFFFF)[2:],
        ]
        candidates.update(math_operations)
    except:
        pass
    
    # 9. Попытка декодирования Base64 строк
    for b64_str in binary_strings:
        try:
            # Стандартное base64
            decoded = base64.b64decode(b64_str + '==').decode('ascii', errors='ignore')
            if len(decoded) >= 4:
                candidates.add(decoded)
        except:
            pass
        
        try:
            # URL-safe base64
            decoded = base64.urlsafe_b64decode(b64_str + '==').decode('ascii', errors='ignore')
            if len(decoded) >= 4:
                candidates.add(decoded)
        except:
            pass
    
    # 10. XOR декодирование подозрительных строк
    suspicious_strings = [
        "sssss3issssssmossssssmssssss/dssssssisssss",
        "sssss3lssssssmossssssRssssss/dsssss3",
    ]
    
    for sus_str in suspicious_strings:
        # Попробуем XOR с разными ключами
        for xor_key in range(1, 128):
            try:
                decoded = ""
                for char in sus_str:
                    xor_char = chr(ord(char) ^ xor_key)
                    if 32 <= ord(xor_char) <= 126:  # Printable ASCII
                        decoded += xor_char
                    else:
                        break
                
                if len(decoded) >= 8 and len(decoded) == len(sus_str):
                    candidates.add(decoded)
            except:
                continue
    
    # 11. Брутфорс коротких ключей (1-6 символов)
    charset = string.ascii_letters + string.digits
    for length in range(1, 7):
        if len(candidates) > 50000:  # Ограничиваем размер
            break
        count = 0
        for key_tuple in itertools.product(charset, repeat=length):
            key = ''.join(key_tuple)
            candidates.add(key)
            count += 1
            if count > 5000:  # Ограничиваем количество для каждой длины
                break
    
    # Убираем пустые и слишком короткие строки
    candidates = {c for c in candidates if c and len(str(c)) >= 1}
    
    print(f"Сгенерировано {len(candidates)} уникальных кандидатов")
    return list(candidates)

def ultimate_brute_force():
    """Финальный брутфорс поиск"""
    print("🚀 ФИНАЛЬНЫЙ ПОИСК SECRET_KEY")
    print("="*60)
    
    candidates = generate_extended_candidates()
    
    print(f"🎯 Тестируем {len(candidates)} кандидатов...")
    
    found_keys = []
    tested = 0
    
    for key in candidates:
        tested += 1
        
        if tested % 5000 == 0:
            print(f"   Протестировано {tested}/{len(candidates)}...")
        
        if test_key_direct(key):
            print(f"\n🎉 НАЙДЕН SECRET_KEY!")
            print(f"Ключ: '{key}'")
            print(f"Длина: {len(key)} символов")
            print(f"Тип: {type(key)}")
            
            found_keys.append(key)
            
            # Проверяем еще раз для уверенности
            verification = jwt.encode(EXACT_PAYLOAD, key, algorithm='HS256')
            match = verification == WORKING_TOKEN
            print(f"Двойная проверка: {'✅ СОВПАДАЕТ' if match else '❌ НЕ СОВПАДАЕТ'}")
            
            if match:
                return key
    
    print(f"\n😞 SECRET_KEY не найден среди {tested} кандидатов")
    return None

def create_final_generator(secret_key):
    """Создание финального генератора"""
    if not secret_key:
        return
    
    generator_code = f'''#!/usr/bin/env python3
"""
ФИНАЛЬНЫЙ РАБОЧИЙ ГЕНЕРАТОР JWT ТОКЕНОВ
SECRET_KEY найден через исчерпывающий анализ
"""
import jwt
from datetime import datetime

# НАЙДЕННЫЙ SECRET_KEY 
SECRET_KEY = "{secret_key}"

def generate_unlock_token(vehicle_id):
    """Генерация рабочего JWT токена (БЕЗ поля exp!)"""
    payload = {{
        "vehicle_id": vehicle_id,
        "iss": "CunBA",
        "timestamp": int(datetime.now().timestamp())
    }}
    
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def test_known_working():
    """Тест с известным рабочим токеном"""
    test_payload = {{
        "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
        "iss": "CunBA", 
        "timestamp": 1753096202
    }}
    
    result = jwt.encode(test_payload, SECRET_KEY, algorithm='HS256')
    expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
    
    success = result == expected
    print(f"✅ Тест пройден: {{success}}")
    return success

if __name__ == "__main__":
    import sys
    
    print("🧪 Тестируем найденный ключ...")
    if not test_known_working():
        print("❌ Ошибка! Ключ не работает!")
        exit(1)
    
    print("✅ Ключ работает корректно!")
    print()
    
    # Генерация токена
    vehicle_id = sys.argv[1] if len(sys.argv) > 1 else input("Vehicle ID: ")
    
    token = generate_unlock_token(vehicle_id)
    
    print("\\n🎯 СГЕНЕРИРОВАННЫЙ ТОКЕН:")
    print("=" * 80)
    print(token)
    print("=" * 80)
    print()
    print("💡 ВАЖНО: НЕ добавляйте поле 'exp' - система его отклоняет!")
    print("🚗 Используйте в команде: ./unlock [токен]")
'''
    
    with open("D:/vzlom/final_unlock_generator.py", "w", encoding="utf-8") as f:
        f.write(generator_code)
    
    print(f"\n✅ Создан final_unlock_generator.py!")

def main():
    """Главная функция"""
    print("🔐 ULTIMATE KEY FINDER")
    print("="*80) 
    print("Финальная попытка найти SECRET_KEY для JWT токенов unlock")
    print("Максимальное покрытие всех возможных вариантов")
    print()
    
    found_key = ultimate_brute_force()
    
    if found_key:
        print(f"\n🎉 МИССИЯ ВЫПОЛНЕНА!")
        print(f"SECRET_KEY найден: '{found_key}'")
        
        create_final_generator(found_key)
        
        print(f"\n🎯 ИТОГ:")
        print(f"✅ Ключ: '{found_key}'")
        print(f"✅ Длина: {len(found_key)} символов")
        print(f"✅ Генератор создан: final_unlock_generator.py")
        print(f"✅ Готов к использованию!")
        
    else:
        print(f"\n💡 СЛЕДУЮЩИЕ ШАГИ:")
        print("1. Попробуйте статический анализ ELF файла с Ghidra")
        print("2. Исследуйте системные файлы на QNX устройстве")
        print("3. Проанализируйте другие связанные процессы")
        print("4. Возможно, ключ генерируется динамически")

if __name__ == "__main__":
    main()

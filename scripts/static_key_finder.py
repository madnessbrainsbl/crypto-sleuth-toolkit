#!/usr/bin/env python3
"""
Статический анализ unlock бинарника для поиска SECRET_KEY
Работает без Android устройства
"""

import re
import jwt
import binascii
import base64
from pathlib import Path

# Рабочий токен для валидации ключей
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
WORKING_PAYLOAD = {
    "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce", 
    "iss": "CunBA",
    "timestamp": 1753096202
}

def test_key(key):
    """Проверка ключа"""
    try:
        test_token = jwt.encode(WORKING_PAYLOAD, key, algorithm='HS256')
        return test_token == WORKING_TOKEN
    except:
        return False

def extract_strings_from_binary():
    """Извлечение всех строк из бинарника"""
    print("🔍 Извлечение строк из unlock бинарника...")
    
    try:
        with open("unlock", "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("❌ Файл unlock не найден")
        return []
    
    # Поиск ASCII строк (минимум 4 символа)
    strings = []
    current_string = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # Печатные ASCII символы
            current_string += chr(byte)
        else:
            if len(current_string) >= 4:
                strings.append(current_string)
            current_string = ""
    
    # Добавляем последнюю строку
    if len(current_string) >= 4:
        strings.append(current_string)
    
    print(f"✓ Найдено {len(strings)} строк")
    return strings

def search_potential_keys(strings):
    """Поиск потенциальных ключей среди строк"""
    print("🔍 Поиск потенциальных SECRET_KEY...")
    
    potential_keys = []
    
    # Фильтры для потенциальных ключей
    for s in strings:
        # Длина от 8 до 128 символов
        if 8 <= len(s) <= 128:
            # Содержит буквы и цифры
            if re.match(r'^[a-zA-Z0-9+/=_\-\.]+$', s):
                # Достаточная энтропия (не повторяющийся паттерн)
                if len(set(s)) >= 6:
                    potential_keys.append(s)
    
    print(f"✓ Найдено {len(potential_keys)} потенциальных ключей")
    return potential_keys

def search_jwt_related_strings(strings):
    """Поиск строк связанных с JWT"""
    print("🔍 Поиск JWT-связанных строк...")
    
    jwt_strings = []
    jwt_keywords = ['jwt', 'hmac', 'secret', 'key', 'cunba', 'unlock', 'vehicle', 'HS256', 'iss']
    
    for s in strings:
        for keyword in jwt_keywords:
            if keyword.lower() in s.lower():
                jwt_strings.append(s)
                break
    
    print(f"✓ Найдено {len(jwt_strings)} JWT-связанных строк")
    for s in jwt_strings[:20]:  # Показываем первые 20
        print(f"   • {s}")
    
    return jwt_strings

def analyze_base64_strings(strings):
    """Анализ строк как потенциальный Base64"""
    print("🔍 Анализ Base64 строк...")
    
    base64_candidates = []
    
    for s in strings:
        # Потенциальный Base64: содержит +, /, = и имеет правильную длину
        if re.match(r'^[A-Za-z0-9+/]+=*$', s) and len(s) % 4 == 0 and len(s) >= 16:
            try:
                decoded = base64.b64decode(s).decode('ascii', errors='ignore')
                base64_candidates.append({
                    'original': s,
                    'decoded': decoded,
                    'length': len(s)
                })
            except:
                continue
    
    print(f"✓ Найдено {len(base64_candidates)} Base64 кандидатов")
    for candidate in base64_candidates[:10]:
        print(f"   • {candidate['original'][:40]}... -> {candidate['decoded'][:40]}...")
    
    return base64_candidates

def search_for_cunba_context():
    """Поиск контекста вокруг строки CunBA"""
    print("🔍 Поиск контекста вокруг 'CunBA'...")
    
    try:
        with open("unlock", "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return []
    
    contexts = []
    cunba_bytes = b'CunBA'
    
    pos = 0
    while True:
        pos = data.find(cunba_bytes, pos)
        if pos == -1:
            break
        
        # Извлекаем контекст (256 байт до и после)
        start = max(0, pos - 256)
        end = min(len(data), pos + len(cunba_bytes) + 256)
        context = data[start:end]
        
        # Ищем строки в контексте
        context_strings = []
        current_string = ""
        
        for byte in context:
            if 32 <= byte <= 126:
                current_string += chr(byte)
            else:
                if len(current_string) >= 8:
                    context_strings.append(current_string)
                current_string = ""
        
        contexts.extend(context_strings)
        pos += 1
    
    print(f"✓ Найдено {len(contexts)} строк в контексте CunBA")
    for ctx in contexts[:10]:
        print(f"   • {ctx}")
    
    return contexts

def test_all_candidates(candidates):
    """Тестирование всех кандидатов ключей"""
    print(f"🔑 Тестирование {len(candidates)} кандидатов...")
    
    tested = 0
    for candidate in candidates:
        tested += 1
        if tested % 100 == 0:
            print(f"   Протестировано {tested}/{len(candidates)}...")
        
        if test_key(candidate):
            print(f"🎉 НАЙДЕН ПРАВИЛЬНЫЙ КЛЮЧ!")
            print(f"Ключ: '{candidate}'")
            print(f"Длина: {len(candidate)} символов")
            return candidate
    
    print("❌ Правильный ключ не найден среди кандидатов")
    return None

def main():
    """Главная функция статического анализа"""
    print("🔐 СТАТИЧЕСКИЙ АНАЛИЗ UNLOCK БИНАРНИКА")
    print("="*60)
    print(f"Цель: найти SECRET_KEY для токена {WORKING_TOKEN[:30]}...")
    print()
    
    # 1. Извлечение всех строк
    all_strings = extract_strings_from_binary()
    if not all_strings:
        return
    
    # 2. Поиск JWT-связанных строк
    jwt_strings = search_jwt_related_strings(all_strings)
    
    # 3. Поиск потенциальных ключей
    potential_keys = search_potential_keys(all_strings)
    
    # 4. Анализ Base64
    base64_candidates = analyze_base64_strings(all_strings)
    
    # 5. Контекст вокруг CunBA
    cunba_context = search_for_cunba_context()
    
    # Собираем все кандидаты
    all_candidates = set()
    all_candidates.update(potential_keys)
    all_candidates.update(jwt_strings)
    all_candidates.update(cunba_context)
    
    # Добавляем декодированные Base64
    for b64 in base64_candidates:
        all_candidates.add(b64['decoded'])
        all_candidates.add(b64['original'])
    
    # Убираем слишком короткие и слишком длинные
    filtered_candidates = [c for c in all_candidates if 4 <= len(c) <= 200]
    
    print(f"\n📊 Итого кандидатов для тестирования: {len(filtered_candidates)}")
    
    # Тестируем все кандидаты
    result = test_all_candidates(filtered_candidates)
    
    if not result:
        print("\n💡 Рекомендации:")
        print("   1. Попробуйте динамический анализ с Frida на устройстве")
        print("   2. Проверьте другие файлы в системе Android")
        print("   3. Ключ может генерироваться алгоритмически")

if __name__ == "__main__":
    main()

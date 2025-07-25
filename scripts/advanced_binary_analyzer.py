#!/usr/bin/env python3
"""
Расширенный анализ бинарника для поиска скрытых/обфусцированных ключей
"""

import jwt
import hashlib
import hmac
import struct
import binascii
import base64
import os
import re
from itertools import combinations

# Константы для поиска
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
EXACT_PAYLOAD = {
    "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
    "iss": "CunBA",
    "timestamp": 1753096202
}

def test_key_candidate(key):
    """Тест кандидата ключа"""
    try:
        test_token = jwt.encode(EXACT_PAYLOAD, key, algorithm='HS256')
        return test_token == WORKING_TOKEN
    except:
        return False

def find_hidden_strings():
    """Поиск скрытых строк через различные декодирования"""
    print("🔍 ПОИСК СКРЫТЫХ СТРОК")
    print("="*50)
    
    candidates = set()
    
    try:
        with open("unlock", "rb") as f:
            data = f.read()
        
        print(f"Размер файла: {len(data)} байт")
        
        # 1. Поиск Base64 последовательностей в сыром виде
        print("\n🔤 Поиск Base64 последовательностей...")
        b64_pattern = re.compile(rb'[A-Za-z0-9+/]{20,}={0,2}')
        b64_matches = b64_pattern.findall(data)
        
        for match in b64_matches:
            try:
                decoded = base64.b64decode(match).decode('ascii', errors='ignore')
                if len(decoded) >= 8 and decoded.isprintable():
                    candidates.add(decoded)
                    print(f"   Base64: {match.decode()[:50]}... -> {decoded}")
            except:
                pass
        
        # 2. Поиск Hex-кодированных данных
        print("\n🔢 Поиск Hex последовательностей...")
        hex_pattern = re.compile(rb'[0-9a-fA-F]{32,}')
        hex_matches = hex_pattern.findall(data)
        
        for match in hex_matches[:20]:  # Ограничиваем вывод
            try:
                hex_str = match.decode('ascii')
                if len(hex_str) % 2 == 0:
                    decoded_bytes = binascii.unhexlify(hex_str)
                    decoded = decoded_bytes.decode('ascii', errors='ignore')
                    if len(decoded) >= 4 and decoded.isprintable():
                        candidates.add(decoded)
                        print(f"   Hex: {hex_str[:50]}... -> {decoded}")
            except:
                pass
        
        # 3. Поиск строк в разных кодировках
        print("\n🌐 Поиск в различных кодировках...")
        encodings = ['utf-8', 'latin1', 'ascii', 'utf-16', 'utf-32']
        
        for encoding in encodings:
            try:
                text = data.decode(encoding, errors='ignore')
                # Ищем длинные алфанумерические последовательности
                words = re.findall(r'[A-Za-z0-9+/=_-]{16,64}', text)
                for word in words[:100]:  # Ограничиваем
                    candidates.add(word)
            except:
                continue
        
        # 4. XOR декодирование с различными ключами
        print("\n🔀 XOR декодирование...")
        sample_size = min(100000, len(data))  # Берем образец
        sample_data = data[:sample_size]
        
        # Попробуем XOR с разными однобайтовыми ключами
        for xor_key in range(1, 256):
            try:
                decoded_bytes = bytes(b ^ xor_key for b in sample_data)
                # Ищем ASCII строки в результате
                current_string = ""
                strings_found = []
                
                for byte in decoded_bytes:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string += chr(byte)
                    else:
                        if len(current_string) >= 16:
                            strings_found.append(current_string)
                        current_string = ""
                
                # Добавляем найденные строки
                for s in strings_found[:5]:  # Ограничиваем
                    if any(keyword in s.lower() for keyword in ['cunba', 'key', 'secret', 'unlock']):
                        candidates.add(s)
                        print(f"   XOR(0x{xor_key:02x}): {s}")
                        
            except:
                continue
        
        print(f"\nНайдено {len(candidates)} скрытых строк для тестирования")
        return list(candidates)
        
    except Exception as e:
        print(f"❌ Ошибка поиска скрытых строк: {e}")
        return []

def analyze_data_segments():
    """Анализ сегментов данных в ELF файле"""
    print("\n📊 АНАЛИЗ СЕГМЕНТОВ ДАННЫХ")
    print("="*50)
    
    candidates = set()
    
    try:
        with open("unlock", "rb") as f:
            data = f.read()
        
        # Простой поиск сегментов с потенциальными ключами
        # Ищем области с высокой энтропией
        chunk_size = 64
        high_entropy_chunks = []
        
        for i in range(0, len(data) - chunk_size, chunk_size):
            chunk = data[i:i+chunk_size]
            
            # Вычисляем простую энтропию
            byte_counts = {}
            for byte in chunk:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            entropy = 0
            for count in byte_counts.values():
                probability = count / len(chunk)
                if probability > 0:
                    entropy -= probability * (probability.bit_length() - 1)
            
            # Ищем чанки с высокой энтропией
            if entropy > 4.0:  # Высокая энтропия
                try:
                    # Попробуем интерпретировать как строку
                    text = chunk.decode('ascii', errors='ignore')
                    if len(text) >= 16 and text.isprintable():
                        high_entropy_chunks.append((i, text, entropy))
                except:
                    pass
        
        high_entropy_chunks.sort(key=lambda x: x[2], reverse=True)
        
        print(f"Найдено {len(high_entropy_chunks)} чанков с высокой энтропией")
        
        for offset, text, entropy in high_entropy_chunks[:10]:
            print(f"   0x{offset:08x}: энтропия {entropy:.2f} - {text[:50]}")
            candidates.add(text.strip())
        
        return list(candidates)
        
    except Exception as e:
        print(f"❌ Ошибка анализа сегментов: {e}")
        return []

def find_constant_pools():
    """Поиск пулов констант и статических данных"""
    print("\n🎯 ПОИСК ПУЛОВ КОНСТАНТ")
    print("="*50)
    
    candidates = set()
    
    try:
        with open("unlock", "rb") as f:
            data = f.read()
        
        # Ищем NULL-terminated strings
        null_strings = []
        current_string = b""
        
        for i, byte in enumerate(data):
            if byte == 0:  # NULL terminator
                if len(current_string) >= 8:
                    try:
                        text = current_string.decode('ascii')
                        if text.isprintable():
                            null_strings.append((i - len(current_string), text))
                    except:
                        pass
                current_string = b""
            elif 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) >= 8:
                    try:
                        text = current_string.decode('ascii')
                        if text.isprintable():
                            null_strings.append((i - len(current_string), text))
                    except:
                        pass
                current_string = b""
        
        # Фильтруем интересные строки
        interesting_strings = []
        for offset, text in null_strings:
            # Ключевые слова или подозрительные паттерны
            if any(kw in text.lower() for kw in ['key', 'secret', 'pass', 'token', 'sign', 'auth', 'cunba']):
                interesting_strings.append((offset, text))
            # Длинные алфанумерические строки
            elif len(text) >= 16 and re.match(r'^[A-Za-z0-9+/=_-]+$', text):
                interesting_strings.append((offset, text))
        
        print(f"Найдено {len(interesting_strings)} интересных строк")
        
        for offset, text in interesting_strings[:20]:
            print(f"   0x{offset:08x}: {text}")
            candidates.add(text)
        
        return list(candidates)
        
    except Exception as e:
        print(f"❌ Ошибка поиска пулов констант: {e}")
        return []

def analyze_embedded_keys():
    """Поиск встроенных ключей через специфичные паттерны"""
    print("\n🔐 ПОИСК ВСТРОЕННЫХ КЛЮЧЕЙ")
    print("="*50)
    
    candidates = set()
    
    try:
        with open("unlock", "rb") as f:
            data = f.read()
        
        # 1. Поиск ключей в формате PEM (хотя маловероятно в ELF)
        pem_patterns = [
            b'-----BEGIN',
            b'-----END',
            b'PRIVATE KEY',
            b'PUBLIC KEY'
        ]
        
        for pattern in pem_patterns:
            pos = data.find(pattern)
            if pos != -1:
                print(f"   Найден PEM паттерн в 0x{pos:08x}: {pattern}")
        
        # 2. Поиск ключей в виде массивов байтов
        # Ищем паттерны как static const unsigned char key[] = {...}
        print("\nПоиск массивов байтов...")
        
        # Ищем последовательности которые выглядят как инициализированные массивы
        for i in range(0, len(data) - 64, 4):
            chunk = data[i:i+64]
            
            # Проверяем на паттерн массива (много запятых или пробелов)
            if chunk.count(b',') > 10 or chunk.count(b' ') > 20:
                try:
                    text = chunk.decode('ascii', errors='ignore')
                    if any(c in text for c in ['0x', '{', '}', ',']):
                        print(f"   0x{i:08x}: возможный массив - {text[:50]}")
                except:
                    pass
        
        # 3. Поиск base64 блоков
        print("\nПоиск base64 блоков...")
        base64_pattern = re.compile(rb'[A-Za-z0-9+/]{40,}={0,2}')
        matches = base64_pattern.finditer(data)
        
        for match in matches:
            try:
                b64_data = match.group()
                decoded = base64.b64decode(b64_data)
                if len(decoded) >= 16:  # Минимальная длина ключа
                    decoded_str = decoded.decode('ascii', errors='ignore')
                    if decoded_str.isprintable():
                        candidates.add(decoded_str)
                        print(f"   0x{match.start():08x}: base64 -> {decoded_str[:50]}")
                    else:
                        # Может быть бинарный ключ
                        candidates.add(decoded.hex())
            except:
                pass
        
        # 4. Поиск строк рядом с "CunBA"
        print("\nПоиск ключей рядом с 'CunBA'...")
        cunba_pattern = re.compile(rb'CunBA', re.IGNORECASE)
        matches = cunba_pattern.finditer(data)
        
        for match in matches:
            start = max(0, match.start() - 100)
            end = min(len(data), match.end() + 100)
            context = data[start:end]
            
            # Ищем строки в контексте
            context_strings = []
            current = ""
            for byte in context:
                if 32 <= byte <= 126:
                    current += chr(byte)
                else:
                    if len(current) >= 8:
                        context_strings.append(current)
                    current = ""
            
            for ctx_str in context_strings:
                if ctx_str.lower() != 'cunba' and len(ctx_str) >= 8:
                    candidates.add(ctx_str)
                    print(f"   Рядом с CunBA: {ctx_str}")
        
        return list(candidates)
        
    except Exception as e:
        print(f"❌ Ошибка поиска встроенных ключей: {e}")
        return []

def comprehensive_key_test():
    """Комплексное тестирование всех найденных кандидатов"""
    print("\n🎯 КОМПЛЕКСНОЕ ТЕСТИРОВАНИЕ")
    print("="*50)
    
    all_candidates = set()
    
    # Собираем кандидатов из всех источников
    print("Собираем кандидатов...")
    
    hidden_strings = find_hidden_strings()
    all_candidates.update(hidden_strings)
    
    data_segments = analyze_data_segments()
    all_candidates.update(data_segments)
    
    constant_pools = find_constant_pools()
    all_candidates.update(constant_pools)
    
    embedded_keys = analyze_embedded_keys()
    all_candidates.update(embedded_keys)
    
    # Убираем дубликаты и фильтруем
    candidates = []
    for candidate in all_candidates:
        if isinstance(candidate, str) and len(candidate) >= 1:
            candidates.append(candidate)
    
    print(f"\n🎯 ФИНАЛЬНОЕ ТЕСТИРОВАНИЕ {len(candidates)} КАНДИДАТОВ")
    print("="*60)
    
    tested = 0
    for candidate in candidates:
        tested += 1
        
        if tested % 100 == 0:
            print(f"Протестировано {tested}/{len(candidates)}...")
        
        if test_key_candidate(candidate):
            print(f"\n🎉 НАЙДЕН SECRET_KEY!")
            print(f"Ключ: '{candidate}'")
            print(f"Длина: {len(candidate)} символов")
            print(f"Источник: расширенный анализ бинарника")
            
            # Создаем финальный генератор
            create_final_generator(candidate)
            return candidate
    
    print(f"\n❌ Ключ не найден среди {len(candidates)} расширенных кандидатов")
    return None

def create_final_generator(secret_key):
    """Создание финального генератора с найденным ключом"""
    generator_code = f'''#!/usr/bin/env python3
"""
ФИНАЛЬНЫЙ ГЕНЕРАТОР - КЛЮЧ НАЙДЕН ЧЕРЕЗ РАСШИРЕННЫЙ АНАЛИЗ
"""
import jwt
from datetime import datetime

SECRET_KEY = "{secret_key}"

def generate_unlock_token(vehicle_id):
    payload = {{
        "vehicle_id": vehicle_id,
        "iss": "CunBA",
        "timestamp": int(datetime.now().timestamp())
    }}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

if __name__ == "__main__":
    import sys
    vehicle_id = sys.argv[1] if len(sys.argv) > 1 else input("Vehicle ID: ")
    token = generate_unlock_token(vehicle_id)
    print("="*80)
    print(token)
    print("="*80)
'''
    
    with open("D:/vzlom/final_found_generator.py", "w", encoding="utf-8") as f:
        f.write(generator_code)
    
    print(f"\n✅ Создан final_found_generator.py с найденным ключом!")

def main():
    """Главная функция"""
    print("🔬 ADVANCED BINARY ANALYZER")
    print("="*80)
    print("Расширенный анализ для поиска скрытых и обфусцированных ключей")
    print()
    
    if not os.path.exists("unlock"):
        print("❌ Файл 'unlock' не найден")
        return
    
    # Запускаем комплексное тестирование
    found_key = comprehensive_key_test()
    
    if found_key:
        print(f"\n🎉 МИССИЯ ВЫПОЛНЕНА!")
        print(f"SECRET_KEY найден: '{found_key}'")
    else:
        print(f"\n💡 ДАЛЬНЕЙШИЕ ДЕЙСТВИЯ:")
        print("   1. Анализ с профессиональными инструментами (Ghidra/IDA)")
        print("   2. Динамический анализ на целевой системе")
        print("   3. Поиск в системных файлах QNX")
        print("   4. Возможно, ключ генерируется алгоритмически")

if __name__ == "__main__":
    main()

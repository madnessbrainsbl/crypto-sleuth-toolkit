#!/usr/bin/env python3
"""
Windows Key Extractor - адаптация CryKeX для поиска криптографических ключей
Анализирует ELF файл unlock для поиска возможных HMAC/JWT ключей
"""

import os
import re
import binascii
import hashlib
import hmac
import jwt
import base64
from itertools import combinations

# Наш рабочий токен для проверки
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
WORKING_PAYLOAD = {
    "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
    "iss": "CunBA",
    "timestamp": 1753096202
}

class WindowsKeyExtractor:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.binary_data = None
        self.potential_keys = set()
        
    def load_binary(self):
        """Загружаем бинарный файл"""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            print(f"✅ Загружен файл {self.binary_path} ({len(self.binary_data)} байт)")
            return True
        except Exception as e:
            print(f"❌ Ошибка загрузки файла: {e}")
            return False
    
    def test_key(self, key):
        """Тестирование ключа"""
        try:
            test_token = jwt.encode(WORKING_PAYLOAD, key, algorithm='HS256')
            return test_token == WORKING_TOKEN
        except:
            return False
    
    def extract_ascii_strings(self, min_length=4, max_length=128):
        """Извлечение ASCII строк из бинарника"""
        print(f"🔍 Извлекаем ASCII строки ({min_length}-{max_length} символов)...")
        
        strings = []
        current_string = ""
        
        for byte in self.binary_data:
            if 32 <= byte <= 126:  # ASCII printable characters
                current_string += chr(byte)
            else:
                if min_length <= len(current_string) <= max_length:
                    strings.append(current_string)
                current_string = ""
        
        # Добавляем последнюю строку если нужно
        if min_length <= len(current_string) <= max_length:
            strings.append(current_string)
        
        unique_strings = list(set(strings))
        print(f"Найдено {len(unique_strings)} уникальных ASCII строк")
        return unique_strings
    
    def find_crypto_patterns(self):
        """Поиск паттернов, характерных для криптографических ключей"""
        print("🔍 Ищем криптографические паттерны...")
        
        patterns = []
        
        # 1. Base64 паттерны (длинные строки с base64 символами)
        b64_pattern = re.compile(rb'[A-Za-z0-9+/]{16,}={0,2}')
        b64_matches = b64_pattern.findall(self.binary_data)
        
        for match in b64_matches:
            try:
                decoded = base64.b64decode(match).decode('ascii', errors='ignore')
                if len(decoded) >= 8:
                    patterns.append(decoded)
            except:
                pass
        
        # 2. Hex паттерны (длинные hex строки)
        hex_pattern = re.compile(rb'[0-9a-fA-F]{16,}')
        hex_matches = hex_pattern.findall(self.binary_data)
        
        for match in hex_matches:
            try:
                hex_str = match.decode('ascii')
                if len(hex_str) % 2 == 0:
                    decoded = binascii.unhexlify(hex_str).decode('ascii', errors='ignore')
                    if len(decoded) >= 8:
                        patterns.append(decoded)
                patterns.append(hex_str)
            except:
                pass
        
        # 3. UUID/GUID паттерны
        uuid_pattern = re.compile(rb'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
        uuid_matches = uuid_pattern.findall(self.binary_data)
        
        for match in uuid_matches:
            patterns.append(match.decode('ascii'))
        
        print(f"Найдено {len(patterns)} криптографических паттернов")
        return patterns
    
    def search_key_candidates(self):
        """Комплексный поиск кандидатов ключей"""
        print("🔑 КОМПЛЕКСНЫЙ ПОИСК КЛЮЧЕЙ")
        print("="*50)
        
        # 1. ASCII строки
        ascii_strings = self.extract_ascii_strings()
        self.potential_keys.update(ascii_strings)
        
        # 2. Криптографические паттерны  
        crypto_patterns = self.find_crypto_patterns()
        self.potential_keys.update(crypto_patterns)
        
        # 3. Поиск конкретных строк связанных с JWT/CunBA
        jwt_related = []
        data_lower = self.binary_data.lower()
        
        jwt_keywords = [b'cunba', b'jwt', b'hmac', b'hs256', b'secret', b'key', b'unlock', b'mega', b'vehicle']
        
        for keyword in jwt_keywords:
            pos = 0
            while True:
                pos = data_lower.find(keyword, pos)
                if pos == -1:
                    break
                
                # Извлекаем контекст вокруг найденного слова
                start = max(0, pos - 64)
                end = min(len(self.binary_data), pos + 64)
                context = self.binary_data[start:end]
                
                # Ищем строки в контексте
                context_strings = []
                current = ""
                for byte in context:
                    if 32 <= byte <= 126:
                        current += chr(byte)
                    else:
                        if len(current) >= 4:
                            context_strings.append(current)
                        current = ""
                
                jwt_related.extend(context_strings)
                pos += 1
        
        self.potential_keys.update(jwt_related)
        
        # 4. Генерация хэшей от найденных строк
        hash_candidates = []
        for candidate in list(self.potential_keys):
            if len(candidate) >= 4:
                hash_candidates.extend([
                    hashlib.md5(candidate.encode()).hexdigest(),
                    hashlib.sha1(candidate.encode()).hexdigest(),
                    hashlib.sha256(candidate.encode()).hexdigest(),
                    hashlib.sha256(candidate.encode()).hexdigest()[:32],
                    hashlib.sha256(candidate.encode()).hexdigest()[:16],
                ])
        
        self.potential_keys.update(hash_candidates)
        
        print(f"Всего найдено {len(self.potential_keys)} потенциальных ключей")
    
    def brute_force_test(self):
        """Брутфорс тестирование всех найденных ключей"""
        print("\n🎯 ТЕСТИРОВАНИЕ КЛЮЧЕЙ")
        print("="*50)
        
        tested = 0
        found_keys = []
        
        for key in self.potential_keys:
            tested += 1
            
            if tested % 1000 == 0:
                print(f"Протестировано {tested}/{len(self.potential_keys)}...")
            
            if self.test_key(key):
                found_keys.append(key)
                print(f"\n🎉 НАЙДЕН КЛЮЧ!")
                print(f"Ключ: '{key}'")
                print(f"Длина: {len(key)} символов")
                
                # Двойная проверка
                verification_token = jwt.encode(WORKING_PAYLOAD, key, algorithm='HS256')
                match = verification_token == WORKING_TOKEN
                print(f"Проверка: {'✅ СОВПАДАЕТ' if match else '❌ НЕ СОВПАДАЕТ'}")
        
        return found_keys
    
    def entropy_analysis(self):
        """Анализ энтропии потенциальных ключей"""
        print("\n📊 АНАЛИЗ ЭНТРОПИИ")
        print("="*50)
        
        high_entropy_keys = []
        
        for key in self.potential_keys:
            if len(key) >= 16:  # Анализируем только длинные ключи
                # Простой расчет энтропии
                char_counts = {}
                for char in key:
                    char_counts[char] = char_counts.get(char, 0) + 1
                
                entropy = 0
                key_length = len(key)
                for count in char_counts.values():
                    probability = count / key_length
                    if probability > 0:
                        import math
                        entropy -= probability * math.log2(probability)
                
                if entropy > 3.5:  # Высокая энтропия
                    high_entropy_keys.append((key, entropy))
        
        # Сортируем по энтропии
        high_entropy_keys.sort(key=lambda x: x[1], reverse=True)
        
        print(f"Найдено {len(high_entropy_keys)} ключей с высокой энтропией")
        for key, entropy in high_entropy_keys[:10]:
            print(f"Энтропия {entropy:.2f}: {key[:50]}...")
        
        return [key for key, _ in high_entropy_keys]

def main():
    """Главная функция"""
    print("🔐 WINDOWS KEY EXTRACTOR")
    print("="*60)
    print("Адаптация CryKeX для поиска JWT HMAC ключей в ELF файлах")
    print()
    
    binary_path = "unlock"
    if not os.path.exists(binary_path):
        print(f"❌ Файл {binary_path} не найден")
        return
    
    extractor = WindowsKeyExtractor(binary_path)
    
    # Загружаем бинарник
    if not extractor.load_binary():
        return
    
    # Ищем кандидатов
    extractor.search_key_candidates()
    
    # Анализ энтропии
    high_entropy = extractor.entropy_analysis()
    
    # Брутфорс тестирование
    found_keys = extractor.brute_force_test()
    
    if found_keys:
        print(f"\n🎉 УСПЕХ! Найдено {len(found_keys)} рабочих ключей:")
        for key in found_keys:
            print(f"  - '{key}'")
        
        # Создаем генератор с первым найденным ключом
        main_key = found_keys[0]
        
        generator_code = f'''#!/usr/bin/env python3
"""
ФИНАЛЬНЫЙ ГЕНЕРАТОР - КЛЮЧ НАЙДЕН ЧЕРЕЗ АНАЛИЗ БИНАРНИКА
"""
import jwt
from datetime import datetime

SECRET_KEY = "{main_key}"

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
        
        with open("D:/vzlom/crykex_generator.py", "w", encoding="utf-8") as f:
            f.write(generator_code)
        
        print(f"\n✅ Создан crykex_generator.py с найденным ключом!")
    
    else:
        print("\n😞 Ключи не найдены")
        print("💡 Возможные причины:")
        print("   - Ключ зашифрован или обфусцирован")
        print("   - Ключ генерируется динамически во время выполнения")
        print("   - Ключ хранится в другом файле или на сервере")

if __name__ == "__main__":
    main()

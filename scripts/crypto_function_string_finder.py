#!/usr/bin/env python3
"""
Поиск строк и констант вокруг адресов криптографических функций
Автоматизированный анализ для поиска SECRET_KEY
"""
import struct
import re
import hashlib
import jwt

# Рабочий токен для тестирования
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
EXACT_PAYLOAD = {"vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce", "iss": "CunBA", "timestamp": 1753096202}

# Адреса криптографических функций из Ghidra
CRYPTO_FUNCTIONS = {
    0x0010d54c: "crypto_handler_1_case3_true",
    0x0010d5c4: "crypto_handler_2_case3_false",
    0x00109ac4: "crypto_handler_3_other_true",
    0x0010d8e4: "crypto_handler_4_other_false"
}

class CryptoFunctionAnalyzer:
    def __init__(self, binary_path="unlock"):
        self.binary_path = binary_path
        self.binary_data = None
        self.found_keys = set()
        
    def load_binary(self):
        """Загружает бинарный файл"""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            print(f"✅ Загружен {self.binary_path} ({len(self.binary_data)} байт)")
            return True
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            return False
    
    def find_function_in_binary(self, func_addr):
        """Находит возможное местоположение функции в бинарном файле"""
        possible_offsets = []
        
        # Метод 1: Прямое использование адреса как смещения
        if func_addr < len(self.binary_data):
            possible_offsets.append(func_addr)
        
        # Метод 2: Поиск по сигнатуре адреса в little endian
        addr_bytes = struct.pack('<I', func_addr & 0xFFFFFFFF)
        for i in range(len(self.binary_data) - 4):
            if self.binary_data[i:i+4] == addr_bytes:
                possible_offsets.append(i)
        
        # Метод 3: Различные базовые адреса
        common_bases = [0x400000, 0x100000, 0x10000, 0x1000]
        for base in common_bases:
            if func_addr > base:
                offset = func_addr - base
                if offset < len(self.binary_data):
                    possible_offsets.append(offset)
        
        # Метод 4: Маскирование старших битов
        for mask_bits in [16, 20, 24]:
            masked_addr = func_addr & ((1 << mask_bits) - 1)
            if masked_addr < len(self.binary_data):
                possible_offsets.append(masked_addr)
        
        return list(set(possible_offsets))
    
    def extract_strings_around_offset(self, offset, radius=2000):
        """Извлекает строки в радиусе от заданного смещения"""
        start = max(0, offset - radius)
        end = min(len(self.binary_data), offset + radius)
        
        region = self.binary_data[start:end]
        strings = []
        current_string = ""
        current_start = start
        
        for i, byte in enumerate(region):
            if 32 <= byte <= 126:  # Printable ASCII
                if not current_string:
                    current_start = start + i
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:
                    strings.append({
                        'text': current_string,
                        'offset': current_start,
                        'distance_from_target': abs((start + i) - offset)
                    })
                current_string = ""
        
        if len(current_string) >= 4:
            strings.append({
                'text': current_string,
                'offset': current_start,
                'distance_from_target': abs(end - offset)
            })
        
        # Сортируем по близости к целевому адресу
        strings.sort(key=lambda x: x['distance_from_target'])
        return strings
    
    def is_potential_crypto_string(self, text):
        """Проверяет, может ли строка быть криптографической"""
        crypto_indicators = [
            # Прямые индикаторы
            'key', 'secret', 'token', 'auth', 'sign', 'hmac', 'sha', 'hash',
            'jwt', 'crypto', 'cipher', 'unlock', 'cunba', 'mega',
            
            # Системные индикаторы  
            'serial', 'uuid', 'guid', 'device', 'hardware', 'build',
            'version', 'platform', 'android', 'qnx',
            
            # Форматы ключей
            'password', 'pass', 'pwd', 'pin', 'code'
        ]
        
        text_lower = text.lower()
        has_crypto_keyword = any(kw in text_lower for kw in crypto_indicators)
        
        # Проверяем на base64-подобные строки
        is_base64_like = (
            re.match(r'^[A-Za-z0-9+/=_-]{16,}$', text) and 
            len(text) >= 16 and 
            text.count('=') <= 2
        )
        
        # Проверяем на hex строки
        is_hex_like = (
            re.match(r'^[0-9a-fA-F]{16,}$', text) and 
            len(text) % 2 == 0
        )
        
        # Проверяем длину (потенциальные ключи обычно 16-128 символов)
        good_length = 16 <= len(text) <= 128
        
        return has_crypto_keyword or (good_length and (is_base64_like or is_hex_like))
    
    def analyze_constants_around_function(self, offset, radius=1000):
        """Анализирует числовые константы вокруг функции"""
        start = max(0, offset - radius)  
        end = min(len(self.binary_data), offset + radius)
        
        constants = []
        
        # Ищем 32-битные и 64-битные константы
        for i in range(start, end - 8, 4):
            try:
                # 32-битные значения
                val32 = struct.unpack('<I', self.binary_data[i:i+4])[0]
                if self.is_interesting_constant(val32):
                    constants.append({
                        'value': val32,
                        'hex': f"0x{val32:x}",
                        'offset': i,
                        'size': 4,
                        'distance': abs(i - offset)
                    })
                
                # 64-битные значения
                if i + 8 <= end:
                    val64 = struct.unpack('<Q', self.binary_data[i:i+8])[0]
                    if self.is_interesting_constant(val64):
                        constants.append({
                            'value': val64,
                            'hex': f"0x{val64:x}",
                            'offset': i,
                            'size': 8,
                            'distance': abs(i - offset)
                        })
            except:
                continue
        
        # Убираем дубли и сортируем по близости
        unique_constants = []
        seen_values = set()
        
        for const in constants:
            if const['value'] not in seen_values:
                seen_values.add(const['value'])
                unique_constants.append(const)
        
        unique_constants.sort(key=lambda x: x['distance'])
        return unique_constants[:20]  # Топ 20
    
    def is_interesting_constant(self, value):
        """Проверяет, интересна ли константа для криптоанализа"""
        # Исключаем очевидно неинтересные значения
        if value == 0 or value == 0xFFFFFFFF or value == 0xFFFFFFFFFFFFFFFF:
            return False
        
        # Ищем значения в разумных диапазонах
        if 0x1000 <= value <= 0xFFFFFFF:  # Разумный диапазон для адресов/констант
            return True
        
        # Проверяем на известные криптографические константы
        crypto_constants = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,  # SHA-256 H0-H3
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,  # SHA-256 H4-H7
            0x36363636, 0x5c5c5c5c,  # HMAC padding
        }
        
        return value in crypto_constants
    
    def analyze_all_crypto_functions(self):
        """Анализирует все криптографические функции"""
        if not self.load_binary():
            return
        
        print("\n🔍 АНАЛИЗ КРИПТОГРАФИЧЕСКИХ ФУНКЦИЙ")
        print("="*70)
        
        all_candidates = set()
        
        for func_addr, func_name in CRYPTO_FUNCTIONS.items():
            print(f"\n🎯 Анализ {func_name} (0x{func_addr:x}):")
            print("-" * 50)
            
            # Находим возможные расположения функции в файле
            offsets = self.find_function_in_binary(func_addr)
            print(f"Найдено {len(offsets)} возможных расположений в файле")
            
            for i, offset in enumerate(offsets[:3]):  # Берем топ 3
                print(f"\n📍 Расположение #{i+1} - смещение 0x{offset:x}:")
                
                # Извлекаем строки
                strings = self.extract_strings_around_offset(offset)
                crypto_strings = [s for s in strings if self.is_potential_crypto_string(s['text'])]
                
                if crypto_strings:
                    print("  🔤 Потенциальные криптографические строки:")
                    for s in crypto_strings[:10]:  # Топ 10
                        print(f"    '{s['text']}' (расстояние: {s['distance_from_target']})")
                        all_candidates.add(s['text'])
                
                # Анализируем константы
                constants = self.analyze_constants_around_function(offset)
                if constants:
                    print("  🔢 Интересные константы:")
                    for const in constants[:5]:  # Топ 5
                        print(f"    {const['hex']} ({const['value']}) - расстояние: {const['distance']}")
                        # Добавляем константы как потенциальные ключи
                        all_candidates.add(const['hex'])
                        all_candidates.add(str(const['value']))
        
        print(f"\n🧪 ТЕСТИРОВАНИЕ {len(all_candidates)} КАНДИДАТОВ:")
        print("="*50)
        
        # Тестируем все найденные кандидаты
        for i, candidate in enumerate(all_candidates):
            if self.test_key(candidate):
                print(f"\n🎉 НАЙДЕН SECRET_KEY: '{candidate}'")
                return candidate
            
            if (i + 1) % 50 == 0:
                print(f"Протестировано: {i + 1}/{len(all_candidates)}")
        
        print("\n❌ SECRET_KEY не найден среди кандидатов")
        
        # Сохраняем все кандидаты для дальнейшего анализа
        self.save_candidates_to_file(all_candidates)
        return None
    
    def save_candidates_to_file(self, candidates):
        """Сохраняет всех кандидатов в файл для дальнейшего анализа"""
        with open("crypto_function_candidates.txt", "w", encoding="utf-8") as f:
            f.write("# Кандидаты SECRET_KEY из анализа криптофункций\n")
            f.write(f"# Всего кандидатов: {len(candidates)}\n\n")
            
            for candidate in sorted(candidates):
                f.write(f"{candidate}\n")
        
        print(f"💾 Сохранено {len(candidates)} кандидатов в crypto_function_candidates.txt")
    
    def test_key(self, key):
        """Тестирует ключ с рабочим токеном"""
        try:
            test_token = jwt.encode(EXACT_PAYLOAD, key, algorithm='HS256')
            return test_token == WORKING_TOKEN
        except:
            return False

if __name__ == "__main__":
    print("🚀 АНАЛИЗ КРИПТОГРАФИЧЕСКИХ ФУНКЦИЙ ДЛЯ ПОИСКА SECRET_KEY")
    print("="*80)
    
    analyzer = CryptoFunctionAnalyzer()
    secret_key = analyzer.analyze_all_crypto_functions()
    
    if secret_key:
        print(f"\n✅ УСПЕХ! SECRET_KEY: '{secret_key}'")
        
        # Тестируем найденный ключ
        try:
            new_payload = EXACT_PAYLOAD.copy()
            new_payload['timestamp'] = 1753099999  # Новое время
            new_token = jwt.encode(new_payload, secret_key, algorithm='HS256')
            print(f"\n🎯 Новый токен для тестирования:")
            print(new_token)
        except Exception as e:
            print(f"Ошибка создания нового токена: {e}")
    else:
        print(f"\n💡 РЕКОМЕНДАЦИИ:")
        print("1. Проверьте файл crypto_function_candidates.txt с найденными кандидатами")
        print("2. Используйте GDB для runtime анализа")
        print("3. Декомпилируйте функции в Ghidra более детально")
        print("4. Попробуйте системную информацию с QNX устройства")

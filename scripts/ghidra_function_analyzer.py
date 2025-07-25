#!/usr/bin/env python3
"""
Анализ функции FUN_00103994 для поиска SECRET_KEY
Основан на декомпилированном коде из Ghidra
"""
import jwt
import hashlib
import hmac
import base64
import struct
import binascii

# Рабочий токен для тестирования
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"

EXACT_PAYLOAD = {
    "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
    "iss": "CunBA",
    "timestamp": 1753096202
}

class GhidraFunctionAnalyzer:
    def __init__(self, binary_path="unlock"):
        self.binary_path = binary_path
        self.binary_data = None
        
        # Ключевые адреса из декомпилированной функции
        self.key_offsets = {
            'data_buffer': 0x5db4,
            'data_pointer': 0x5d00, 
            'data_size': 0x5d20,
            'alt_buffer': 0x142c,
            'status_flag': 0x5c90,
            'context_ptr': 0x18,
            'magic_buffer': 0x5430
        }
        
        # Функции-обработчики
        self.handler_functions = [
            0x0010d54c,  # FUN_0010d54c - case 3, bVar4 == true
            0x0010d5c4,  # FUN_0010d5c4 - case 3, bVar4 == false  
            0x00109ac4,  # FUN_00109ac4 - other cases, bVar4 == true
            0x0010d8e4   # FUN_0010d8e4 - other cases, bVar4 == false
        ]
        
    def load_binary(self):
        """Загружает бинарный файл"""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            print(f"✅ Загружен файл {self.binary_path} ({len(self.binary_data)} байт)")
            return True
        except Exception as e:
            print(f"❌ Ошибка загрузки: {e}")
            return False
    
    def analyze_protocol_parser(self):
        """Анализирует протокольный парсер на основе функции FUN_00103994"""
        print("\n🔍 АНАЛИЗ ПРОТОКОЛЬНОГО ПАРСЕРА")
        print("="*60)
        
        # Константы из функции
        error_codes = {
            0xffffffffffffffec: "INVALID_DATA (-20)",
            0xffffffffffffffe2: "ACCESS_DENIED (-30)"
        }
        
        # Магические числа и лимиты
        magic_numbers = {
            0x20000f: "Максимальный размер для uint3",
            0x20000: "Максимальный размер для uVar1", 
            0x3fff: "Маска для 14-битного значения",
            0x3ffff: "Маска для 18-битного значения",
            0x3ff: "Маска для 10-битного значения",
            0x800: "Размер буфера (2048 байт)",
            0xffffffffffffff89: "Граничное значение проверки"
        }
        
        print("📊 КОНСТАНТЫ ИЗ ФУНКЦИИ:")
        for value, desc in magic_numbers.items():
            print(f"  0x{value:x}: {desc}")
            
        return self.search_related_strings()
    
    def search_related_strings(self):
        """Ищет строки связанные с протокольным парсером"""
        if not self.binary_data:
            return []
            
        print("\n🔍 ПОИСК СВЯЗАННЫХ СТРОК В БИНАРНИКЕ:")
        
        # Ищем ASCII строки рядом с функциями-обработчиками
        potential_keys = set()
        
        # Конвертируем адреса функций в возможные позиции в файле
        for func_addr in self.handler_functions:
            # Простое приближение - адрес может быть смещением в файле
            possible_offsets = [
                func_addr & 0xFFFFFF,  # Убираем старшие биты
                func_addr & 0xFFFFF,   # Еще меньше
                func_addr & 0xFFFF,    # Только младшие 16 бит
            ]
            
            for offset in possible_offsets:
                if offset < len(self.binary_data):
                    # Ищем строки в окрестности
                    start = max(0, offset - 1000)
                    end = min(len(self.binary_data), offset + 1000)
                    region = self.binary_data[start:end]
                    
                    # Извлекаем ASCII строки
                    strings = self.extract_ascii_strings(region, min_length=8)
                    for s in strings:
                        if self.is_potential_key(s):
                            potential_keys.add(s)
        
        print(f"Найдено {len(potential_keys)} потенциальных ключей:")
        for key in sorted(potential_keys)[:20]:
            print(f"  - {key}")
            
        return list(potential_keys)
    
    def extract_ascii_strings(self, data, min_length=4):
        """Извлекает ASCII строки из данных"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
                
        if len(current_string) >= min_length:
            strings.append(current_string)
            
        return strings
    
    def is_potential_key(self, s):
        """Проверяет, может ли строка быть криптографическим ключом"""
        if len(s) < 8 or len(s) > 128:
            return False
            
        # Ключевые слова
        key_indicators = [
            'key', 'secret', 'token', 'auth', 'sign', 'hmac',
            'cunba', 'unlock', 'mega', 'jwt', 'crypto', 'hash'
        ]
        
        s_lower = s.lower()
        has_keyword = any(keyword in s_lower for keyword in key_indicators)
        
        # Проверка на Base64-подобную строку
        import re
        is_base64_like = bool(re.match(r'^[A-Za-z0-9+/=_-]+$', s))
        
        # Проверка на hex
        is_hex_like = bool(re.match(r'^[0-9a-fA-F]+$', s)) and len(s) % 2 == 0
        
        return has_keyword or (is_base64_like and len(s) >= 16) or (is_hex_like and len(s) >= 32)
    
    def generate_keys_from_constants(self):
        """Генерирует ключи на основе констант из функции"""
        print("\n🔑 ГЕНЕРАЦИЯ КЛЮЧЕЙ ИЗ КОНСТАНТ ФУНКЦИИ:")
        
        candidates = set()
        
        # Используем адреса как источники ключей
        for name, offset in self.key_offsets.items():
            # Hex представление
            candidates.add(f"{offset:x}")
            candidates.add(f"{offset:08x}")
            
            # С префиксами
            candidates.add(f"key_{offset:x}")
            candidates.add(f"secret_{offset:x}")
            candidates.add(f"unlock_{offset:x}")
            candidates.add(f"cunba_{offset:x}")
            
            # Хеши адресов
            addr_str = f"{offset:x}"
            candidates.add(hashlib.md5(addr_str.encode()).hexdigest())
            candidates.add(hashlib.sha256(addr_str.encode()).hexdigest())
        
        # Комбинации функций
        for func_addr in self.handler_functions:
            func_str = f"{func_addr:x}"
            candidates.add(func_str)
            candidates.add(f"func_{func_str}")
            candidates.add(hashlib.md5(func_str.encode()).hexdigest())
        
        # Магические числа как ключи
        magic_nums = [0x20000f, 0x20000, 0x3fff, 0x3ffff, 0x3ff, 0x800]
        for num in magic_nums:
            candidates.add(f"{num:x}")
            candidates.add(f"magic_{num:x}")
            candidates.add(hashlib.md5(f"{num:x}".encode()).hexdigest())
        
        print(f"Сгенерировано {len(candidates)} кандидатов из констант функции")
        return list(candidates)
    
    def analyze_memory_layout(self):
        """Анализирует структуру памяти из функции"""
        print("\n🧠 АНАЛИЗ СТРУКТУРЫ ПАМЯТИ:")
        print("="*60)
        
        # Структура данных на основе смещений
        memory_structure = {
            0x18: "context_ptr - Указатель на контекст",
            0x142c: "alt_buffer - Альтернативный буфер",
            0x5430: "magic_buffer - Буфер с магическим значением 0x800",
            0x5c90: "status_flag - Флаг состояния (проверяется на == 0)",
            0x5d00: "data_pointer - Указатель на данные",
            0x5d20: "data_size - Размер данных", 
            0x5db4: "data_buffer - Основной буфер данных"
        }
        
        for offset, desc in sorted(memory_structure.items()):
            print(f"  +0x{offset:04x}: {desc}")
        
        # Возможные ключи на основе структуры
        struct_keys = []
        
        # Размер структуры
        max_offset = max(memory_structure.keys())
        struct_size = max_offset + 8  # Добавляем место для данных
        
        struct_keys.extend([
            f"struct_{struct_size:x}",
            f"size_{struct_size}",
            hashlib.md5(f"struct_{struct_size}".encode()).hexdigest(),
        ])
        
        # Ключи на основе расстояний между полями
        offsets = sorted(memory_structure.keys())
        for i in range(len(offsets) - 1):
            distance = offsets[i+1] - offsets[i]
            struct_keys.append(f"dist_{distance:x}")
        
        print(f"\nСгенерировано {len(struct_keys)} ключей на основе структуры памяти")
        return struct_keys
    
    def test_all_candidates(self):
        """Тестирует все сгенерированные кандидаты ключей"""
        print("\n🧪 ТЕСТИРОВАНИЕ ВСЕХ КАНДИДАТОВ:")
        print("="*60)
        
        all_candidates = set()
        
        # Собираем кандидатов из всех источников
        if self.load_binary():
            all_candidates.update(self.analyze_protocol_parser())
        
        all_candidates.update(self.generate_keys_from_constants())
        all_candidates.update(self.analyze_memory_layout())
        
        print(f"\n🎯 Общее количество кандидатов: {len(all_candidates)}")
        
        # Тестируем каждый кандидат
        tested = 0
        for candidate in all_candidates:
            if self.test_jwt_key(candidate):
                print(f"🎉 НАЙДЕН КЛЮЧ: {candidate}")
                return candidate
            tested += 1
            
            if tested % 100 == 0:
                print(f"Протестировано: {tested}/{len(all_candidates)}")
        
        print("❌ Ключ не найден среди сгенерированных кандидатов")
        return None
    
    def test_jwt_key(self, key):
        """Тестирует ключ с JWT"""
        try:
            test_token = jwt.encode(EXACT_PAYLOAD, key, algorithm='HS256')
            return test_token == WORKING_TOKEN
        except:
            return False

# Запуск анализа
if __name__ == "__main__":
    print("🚀 АНАЛИЗ ФУНКЦИИ FUN_00103994 ДЛЯ ПОИСКА SECRET_KEY")
    print("="*70)
    
    analyzer = GhidraFunctionAnalyzer()
    result = analyzer.test_all_candidates()
    
    if result:
        print(f"\n✅ SUCCESS! Найден SECRET_KEY: {result}")
    else:
        print("\n💡 РЕКОМЕНДАЦИИ:")
        print("1. Декомпилируйте функции-обработчики в Ghidra:")
        for addr in analyzer.handler_functions:
            print(f"   - FUN_{addr:08x}")
        print("2. Найдите вызовы FUN_00103994 и проследите источник данных")
        print("3. Проверьте строки вокруг адресов функций в бинарнике")
        print("4. Используйте GDB для мониторинга памяти во время выполнения")

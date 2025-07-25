#!/usr/bin/env python3
"""
Анализ данных в конкретных адресах памяти из декомпилированной функции
Фокус на поиске ключей в буферах и структурах данных
"""
import jwt
import struct
import hashlib

WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
EXACT_PAYLOAD = {"vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce", "iss": "CunBA", "timestamp": 1753096202}

class MemoryAddressAnalyzer:
    def __init__(self, binary_path="unlock"):
        self.binary_path = binary_path
        self.binary_data = None
        
        # Ключевые адреса из функции FUN_00103994
        self.critical_addresses = {
            # Основные буферы данных
            0x5db4: "main_data_buffer",      # param_1 + 0x5db4
            0x142c: "alt_buffer",            # param_1 + 0x142c  
            0x5430: "magic_buffer_0x800",    # param_1 + 0x5430, размер 0x800
            
            # Указатели и размеры
            0x5d00: "data_pointer",          # param_1 + 0x5d00
            0x5d20: "data_size",            # param_1 + 0x5d20
            0x18: "context_pointer",         # param_1 + 0x18
            
            # Флаги состояния
            0x5c90: "status_flag",           # param_1 + 0x5c90 (проверяется на == 0)
        }
        
        # Функции-обработчики (возможные адреса криптографических функций)
        self.crypto_functions = {
            0x0010d54c: "crypto_handler_1",  # case 3, bVar4 == true
            0x0010d5c4: "crypto_handler_2",  # case 3, bVar4 == false
            0x00109ac4: "crypto_handler_3",  # other cases, bVar4 == true  
            0x0010d8e4: "crypto_handler_4"   # other cases, bVar4 == false
        }
        
    def load_binary(self):
        """Загружает бинарный файл"""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            print(f"✅ Загружен бинарник {self.binary_path} ({len(self.binary_data)} байт)")
            return True
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            return False
    
    def extract_data_at_addresses(self):
        """Извлекает данные из критических адресов"""
        if not self.load_binary():
            return []
            
        print("\n🔍 ИЗВЛЕЧЕНИЕ ДАННЫХ ИЗ КРИТИЧЕСКИХ АДРЕСОВ:")
        print("="*60)
        
        potential_keys = set()
        
        for addr, name in self.critical_addresses.items():
            print(f"\n📍 Анализ адреса 0x{addr:x} ({name}):")
            
            # Интерпретируем адрес как смещение в файле
            possible_offsets = self.convert_address_to_file_offset(addr)
            
            for offset in possible_offsets:
                if 0 <= offset < len(self.binary_data):
                    # Извлекаем данные разной длины
                    data_chunks = self.extract_data_chunks(offset)
                    
                    for chunk_size, chunk_data in data_chunks.items():
                        # Интерпретируем как строку
                        try:
                            string_data = chunk_data.decode('ascii', errors='ignore').strip('\x00')
                            if len(string_data) >= 8 and string_data.isprintable():
                                potential_keys.add(string_data)
                                print(f"  ASCII[{chunk_size}]: '{string_data}'")
                        except:
                            pass
                        
                        # Интерпретируем как hex
                        hex_data = chunk_data.hex()
                        if len(hex_data) >= 16:
                            potential_keys.add(hex_data)
                            print(f"  HEX[{chunk_size}]: {hex_data}")
                        
                        # Интерпретируем как числа (little endian)
                        if len(chunk_data) >= 4:
                            try:
                                uint32_val = struct.unpack('<I', chunk_data[:4])[0]
                                potential_keys.add(str(uint32_val))
                                potential_keys.add(f"{uint32_val:x}")
                                print(f"  UINT32: {uint32_val} (0x{uint32_val:x})")
                            except:
                                pass
                        
                        if len(chunk_data) >= 8:
                            try:
                                uint64_val = struct.unpack('<Q', chunk_data[:8])[0]
                                potential_keys.add(str(uint64_val))
                                potential_keys.add(f"{uint64_val:x}")
                                print(f"  UINT64: {uint64_val} (0x{uint64_val:x})")
                            except:
                                pass
        
        return list(potential_keys)
    
    def convert_address_to_file_offset(self, address):
        """Конвертирует адрес памяти в возможные смещения в файле"""
        # Различные способы интерпретации адреса
        offsets = []
        
        # 1. Прямое использование как смещение
        if address < len(self.binary_data):
            offsets.append(address)
        
        # 2. Убираем старшие биты (возможная база загрузки)
        for shift in [12, 16, 20, 24]:
            offset = address & ((1 << shift) - 1)
            if offset < len(self.binary_data):
                offsets.append(offset)
        
        # 3. Вычитаем возможные базовые адреса
        possible_bases = [0x10000, 0x100000, 0x400000, 0x1000000]
        for base in possible_bases:
            if address > base:
                offset = address - base
                if offset < len(self.binary_data):
                    offsets.append(offset)
        
        return list(set(offsets))  # Убираем дубли
    
    def extract_data_chunks(self, offset):
        """Извлекает данные разного размера из заданного смещения"""
        chunks = {}
        sizes = [4, 8, 16, 32, 64, 128, 256]
        
        for size in sizes:
            if offset + size <= len(self.binary_data):
                chunks[size] = self.binary_data[offset:offset + size]
        
        return chunks
    
    def analyze_crypto_function_areas(self):
        """Анализирует области вокруг адресов криптографических функций"""
        print("\n🔐 АНАЛИЗ ОБЛАСТЕЙ КРИПТОГРАФИЧЕСКИХ ФУНКЦИЙ:")
        print("="*60)
        
        potential_keys = set()
        
        for func_addr, name in self.crypto_functions.items():
            print(f"\n🎯 Функция 0x{func_addr:x} ({name}):")
            
            # Конвертируем адрес функции в смещение файла
            possible_offsets = self.convert_address_to_file_offset(func_addr)
            
            for base_offset in possible_offsets:
                if base_offset < len(self.binary_data):
                    # Анализируем область ±500 байт вокруг функции
                    start = max(0, base_offset - 500)
                    end = min(len(self.binary_data), base_offset + 500)
                    
                    # Ищем строки в этой области
                    strings = self.extract_strings_from_region(start, end)
                    
                    for s in strings:
                        if self.is_crypto_related_string(s):
                            potential_keys.add(s)
                            print(f"  Найдена строка: '{s}'")
        
        return list(potential_keys)
    
    def extract_strings_from_region(self, start, end):
        """Извлекает ASCII строки из области памяти"""
        strings = []
        current_string = ""
        
        for i in range(start, end):
            byte = self.binary_data[i]
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= 8:  # Минимум 8 символов
                    strings.append(current_string)
                current_string = ""
        
        if len(current_string) >= 8:
            strings.append(current_string)
        
        return strings
    
    def is_crypto_related_string(self, s):
        """Проверяет, связана ли строка с криптографией"""
        crypto_keywords = [
            'key', 'secret', 'token', 'auth', 'sign', 'hmac', 'sha', 'hash',
            'cunba', 'unlock', 'mega', 'jwt', 'crypto', 'cipher', 'algorithm'
        ]
        
        s_lower = s.lower()
        return any(keyword in s_lower for keyword in crypto_keywords)
    
    def generate_structure_based_keys(self):
        """Генерирует ключи на основе структуры памяти"""
        print("\n🏗️ ГЕНЕРАЦИЯ КЛЮЧЕЙ НА ОСНОВЕ СТРУКТУРЫ:")
        print("="*60)
        
        keys = set()
        
        # Ключи на основе смещений
        for addr, name in self.critical_addresses.items():
            keys.add(f"{addr:x}")
            keys.add(f"{addr:08x}")
            keys.add(f"offset_{addr:x}")
            keys.add(f"{name}_{addr:x}")
            
            # Хеши смещений
            keys.add(hashlib.md5(f"{addr:x}".encode()).hexdigest())
            keys.add(hashlib.sha256(f"{addr:x}".encode()).hexdigest())
        
        # Комбинации смещений
        addrs = list(self.critical_addresses.keys())
        for i in range(len(addrs)):
            for j in range(i+1, len(addrs)):
                combined = addrs[i] ^ addrs[j]  # XOR
                keys.add(f"{combined:x}")
                
                sum_val = (addrs[i] + addrs[j]) & 0xFFFFFFFF
                keys.add(f"{sum_val:x}")
        
        # Магические константы из функции
        magic_constants = [0x20000f, 0x20000, 0x3fff, 0x3ffff, 0x3ff, 0x800, 8]
        for const in magic_constants:
            keys.add(f"magic_{const:x}")
            keys.add(hashlib.md5(f"magic_{const}".encode()).hexdigest())
        
        print(f"Сгенерировано {len(keys)} ключей на основе структуры")
        return list(keys)
    
    def test_all_keys(self):
        """Тестирует все найденные ключи"""
        print("\n🧪 ТЕСТИРОВАНИЕ ВСЕХ КЛЮЧЕЙ:")
        print("="*60)
        
        all_keys = set()
        
        # Собираем ключи из всех источников
        all_keys.update(self.extract_data_at_addresses())
        all_keys.update(self.analyze_crypto_function_areas())
        all_keys.update(self.generate_structure_based_keys())
        
        print(f"\n🎯 Общее количество кандидатов: {len(all_keys)}")
        
        # Тестируем каждый ключ
        for i, key in enumerate(all_keys):
            if self.test_key(key):
                print(f"\n🎉 НАЙДЕН SECRET_KEY: '{key}'")
                return key
            
            if (i + 1) % 100 == 0:
                print(f"Протестировано: {i + 1}/{len(all_keys)}")
        
        print("\n❌ SECRET_KEY не найден среди кандидатов")
        return None
    
    def test_key(self, key):
        """Тестирует ключ с рабочим токеном"""
        try:
            test_token = jwt.encode(EXACT_PAYLOAD, key, algorithm='HS256')
            return test_token == WORKING_TOKEN
        except:
            return False

if __name__ == "__main__":
    print("🚀 АНАЛИЗ КРИТИЧЕСКИХ АДРЕСОВ ПАМЯТИ ДЛЯ ПОИСКА SECRET_KEY")
    print("="*70)
    
    analyzer = MemoryAddressAnalyzer()
    secret_key = analyzer.test_all_keys()
    
    if secret_key:
        print(f"\n✅ УСПЕХ! SECRET_KEY найден: '{secret_key}'")
        
        # Проверяем ключ
        try:
            new_payload = EXACT_PAYLOAD.copy()
            new_payload['timestamp'] = 1753096999  # Новое время
            new_token = jwt.encode(new_payload, secret_key, algorithm='HS256')
            print(f"\n🎯 Тестовый токен с новым временем:")
            print(new_token)
        except Exception as e:
            print(f"Ошибка создания нового токена: {e}")
    else:
        print(f"\n💡 РЕКОМЕНДАЦИИ ДЛЯ ДАЛЬНЕЙШЕГО АНАЛИЗА:")
        print("1. Используйте GDB для мониторинга памяти во время выполнения")
        print("2. Декомпилируйте функции-обработчики:")
        for addr, name in analyzer.crypto_functions.items():
            print(f"   - 0x{addr:x} ({name})")
        print("3. Проследите вызовы функции FUN_00103994 в Ghidra")
        print("4. Найдите где инициализируются буферы данных")

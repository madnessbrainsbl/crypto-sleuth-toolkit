#!/usr/bin/env python3
"""
Ghidra-подобный анализатор ELF файлов
Автоматизированный поиск криптографических функций и ключей
"""

import os
import struct
import binascii
import re
import jwt
import hashlib
from collections import defaultdict

# Рабочий токен для тестирования
WORKING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZWhpY2xlX2lkIjoiMGQ3OWZmMDQ3ZjVjZWM1YmYyZWMyZWM3ZDNlNDY0Y2UiLCJpc3MiOiJDdW5CQSIsInRpbWVzdGFtcCI6MTc1MzA5NjIwMn0.MWlqDVyQK4lhpZNZgaBS6gHisirYceGIxWvb9Q1-zXw"
EXACT_PAYLOAD = {
    "vehicle_id": "0d79ff047f5cec5bf2ec2ec7d3e464ce",
    "iss": "CunBA",
    "timestamp": 1753096202
}

class ELFAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = None
        self.strings = []
        self.functions = []
        self.crypto_candidates = set()
        
    def load_file(self):
        """Загрузка ELF файла"""
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()
            print(f"✅ Загружен файл {self.filepath} ({len(self.data)} байт)")
            return True
        except Exception as e:
            print(f"❌ Ошибка загрузки файла: {e}")
            return False
    
    def parse_elf_header(self):
        """Парсинг ELF заголовка"""
        print("\n🔍 ПАРСИНГ ELF ЗАГОЛОВКА")
        print("="*50)
        
        if len(self.data) < 64:
            print("❌ Файл слишком мал для ELF")
            return False
            
        # ELF Magic
        if self.data[:4] != b'\x7fELF':
            print("❌ Не ELF файл")
            return False
            
        ei_class = self.data[4]  # 1=32bit, 2=64bit
        ei_data = self.data[5]   # 1=little endian, 2=big endian
        ei_version = self.data[6]
        
        print(f"ELF класс: {'64-bit' if ei_class == 2 else '32-bit'}")
        print(f"Порядок байт: {'Little Endian' if ei_data == 1 else 'Big Endian'}")
        print(f"Версия: {ei_version}")
        
        # Получаем тип машины
        if ei_class == 2:  # 64-bit
            fmt = '<H' if ei_data == 1 else '>H'
            e_machine = struct.unpack(fmt, self.data[18:20])[0]
        else:  # 32-bit
            fmt = '<H' if ei_data == 1 else '>H'
            e_machine = struct.unpack(fmt, self.data[18:20])[0]
            
        machine_names = {
            0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64",
            0x3: "x86", 0x8: "MIPS", 0x14: "PowerPC"
        }
        
        machine = machine_names.get(e_machine, f"Unknown (0x{e_machine:x})")
        print(f"Архитектура: {machine}")
        
        return True
    
    def extract_strings(self):
        """Извлечение строк из файла"""
        print("\n📝 ИЗВЛЕЧЕНИЕ СТРОК")
        print("="*50)
        
        self.strings = []
        current_string = ""
        
        for i, byte in enumerate(self.data):
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:
                    self.strings.append({
                        'offset': i - len(current_string),
                        'value': current_string,
                        'length': len(current_string)
                    })
                current_string = ""
        
        print(f"Найдено {len(self.strings)} строк")
        
        # Категоризация строк
        crypto_strings = []
        cunba_strings = []
        key_like_strings = []
        
        for s in self.strings:
            value_lower = s['value'].lower()
            
            # Криптографические термины
            crypto_terms = ['hmac', 'sha', 'md5', 'aes', 'rsa', 'jwt', 'sign', 'crypt', 'hash']
            if any(term in value_lower for term in crypto_terms):
                crypto_strings.append(s)
            
            # CunBA связанные
            cunba_terms = ['cunba', 'unlock', 'mega', 'vehicle', 'token', 'key', 'secret']
            if any(term in value_lower for term in cunba_terms):
                cunba_strings.append(s)
            
            # Похожие на ключи строки
            if (len(s['value']) >= 16 and 
                re.match(r'^[A-Za-z0-9+/=_-]+$', s['value']) and
                not re.match(r'^[0-9]+$', s['value'])):
                key_like_strings.append(s)
        
        print(f"🔐 Криптографические строки: {len(crypto_strings)}")
        print(f"🚗 CunBA/unlock строки: {len(cunba_strings)}")
        print(f"🔑 Похожие на ключи: {len(key_like_strings)}")
        
        # Показываем наиболее интересные
        if crypto_strings:
            print("\n🔐 КРИПТОГРАФИЧЕСКИЕ СТРОКИ:")
            for s in crypto_strings[:10]:
                print(f"   0x{s['offset']:08x}: {s['value']}")
        
        if cunba_strings:
            print("\n🚗 CUNBA/UNLOCK СТРОКИ:")
            for s in cunba_strings[:10]:
                print(f"   0x{s['offset']:08x}: {s['value']}")
                self.crypto_candidates.add(s['value'])
        
        if key_like_strings:
            print("\n🔑 ПОХОЖИЕ НА КЛЮЧИ СТРОКИ:")
            for s in key_like_strings[:10]:
                print(f"   0x{s['offset']:08x}: {s['value']}")
                self.crypto_candidates.add(s['value'])
        
        return len(self.strings)
    
    def find_crypto_constants(self):
        """Поиск криптографических констант"""
        print("\n🔍 ПОИСК КРИПТОГРАФИЧЕСКИХ КОНСТАНТ")
        print("="*50)
        
        # Известные константы
        constants = {
            # SHA-256 инициализационные векторы
            b'\x6a\x09\xe6\x67': 'SHA-256 H0',
            b'\xbb\x67\xae\x85': 'SHA-256 H1', 
            b'\x3c\x6e\xf3\x72': 'SHA-256 H2',
            b'\xa5\x4f\xf5\x3a': 'SHA-256 H3',
            b'\x51\x0e\x52\x7f': 'SHA-256 H4',
            b'\x9b\x05\x68\x8c': 'SHA-256 H5',
            b'\x1f\x83\xd9\xab': 'SHA-256 H6',
            b'\x5b\xe0\xcd\x19': 'SHA-256 H7',
            
            # HMAC константы  
            b'\x36' * 64: 'HMAC ipad (64 bytes)',
            b'\x5c' * 64: 'HMAC opad (64 bytes)',
            b'\x36' * 32: 'HMAC ipad (32 bytes)',
            b'\x5c' * 32: 'HMAC opad (32 bytes)',
            
            # JWT Base64 заголовки
            b'eyJhbGciOiJIUzI1NiI': 'JWT HS256 header',
            b'eyJ0eXAiOiJKV1Qi': 'JWT typ header',
            
            # Другие
            b'CunBA': 'CunBA string',
            b'unlock': 'unlock string',
        }
        
        found_constants = []
        for constant, description in constants.items():
            pos = 0
            while True:
                pos = self.data.find(constant, pos)
                if pos == -1:
                    break
                found_constants.append((pos, constant, description))
                pos += 1
        
        if found_constants:
            print("✅ Найдены константы:")
            for offset, constant, desc in found_constants:
                print(f"   0x{offset:08x}: {desc}")
                
                # Извлекаем контекст вокруг константы
                start = max(0, offset - 50)
                end = min(len(self.data), offset + len(constant) + 50)
                context = self.data[start:end]
                
                # Ищем строки в контексте
                context_str = ""
                for byte in context:
                    if 32 <= byte <= 126:
                        context_str += chr(byte)
                    else:
                        if len(context_str) >= 8:
                            self.crypto_candidates.add(context_str)
                        context_str = ""
        else:
            print("❌ Криптографические константы не найдены")
        
        return len(found_constants)
    
    def analyze_data_sections(self):
        """Анализ секций данных"""
        print("\n📊 АНАЛИЗ СЕКЦИЙ ДАННЫХ")
        print("="*50)
        
        # Простой анализ - ищем области с интересными данными
        chunk_size = 1024
        interesting_chunks = []
        
        for i in range(0, len(self.data) - chunk_size, chunk_size):
            chunk = self.data[i:i+chunk_size]
            
            # Подсчитываем статистику
            printable_count = sum(1 for b in chunk if 32 <= b <= 126)
            zero_count = chunk.count(0)
            
            # Ищем чанки с высоким содержанием печатных символов
            if printable_count > chunk_size * 0.8 and zero_count < chunk_size * 0.2:
                try:
                    text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    interesting_chunks.append((i, text))
                except:
                    pass
        
        print(f"Найдено {len(interesting_chunks)} интересных секций данных")
        
        for offset, text in interesting_chunks[:5]:
            print(f"   0x{offset:08x}: {text[:100]}")
            
            # Извлекаем потенциальные ключи из текста  
            words = re.findall(r'[A-Za-z0-9+/=_-]{16,64}', text)
            for word in words:
                if not re.match(r'^[0-9.]+$', word):  # Исключаем числа
                    self.crypto_candidates.add(word)
    
    def search_xor_encoded_keys(self):
        """Поиск XOR-кодированных ключей"""
        print("\n🔀 ПОИСК XOR-КОДИРОВАННЫХ КЛЮЧЕЙ")
        print("="*50)
        
        # Берем образец данных для анализа
        sample_size = min(50000, len(self.data))
        sample = self.data[:sample_size]
        
        found_keys = []
        
        # Пробуем XOR с различными ключами
        for xor_byte in range(1, 256):
            if xor_byte % 50 == 0:
                print(f"   Тестируем XOR ключ 0x{xor_byte:02x}...")
                
            decoded = bytes(b ^ xor_byte for b in sample)
            
            # Ищем ASCII строки в декодированных данных
            current_string = ""
            strings_found = []
            
            for byte in decoded:
                if 32 <= byte <= 126:
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 8:
                        strings_found.append(current_string)
                    current_string = ""
            
            # Проверяем найденные строки на интересность
            for string in strings_found:
                if any(keyword in string.lower() for keyword in ['cunba', 'unlock', 'secret', 'key', 'jwt', 'hmac']):
                    found_keys.append((xor_byte, string))
                    print(f"   XOR(0x{xor_byte:02x}): {string}")
                    self.crypto_candidates.add(string)
        
        return found_keys
    
    def test_crypto_candidates(self):
        """Тестирование всех найденных кандидатов"""
        print(f"\n🧪 ТЕСТИРОВАНИЕ {len(self.crypto_candidates)} КАНДИДАТОВ")
        print("="*50)
        
        if not self.crypto_candidates:
            print("❌ Нет кандидатов для тестирования")
            return None
        
        tested = 0
        for candidate in self.crypto_candidates:
            tested += 1
            
            if tested % 50 == 0:
                print(f"   Протестировано {tested}/{len(self.crypto_candidates)}...")
            
            try:
                test_token = jwt.encode(EXACT_PAYLOAD, candidate, algorithm='HS256')
                if test_token == WORKING_TOKEN:
                    print(f"\n🎉 НАЙДЕН SECRET_KEY!")
                    print(f"Ключ: '{candidate}'")
                    print(f"Длина: {len(candidate)} символов")
                    print(f"Источник: Ghidra-подобный анализ")
                    return candidate
            except:
                continue
        
        print("❌ Ни один кандидат не подошел")
        return None
    
    def full_analysis(self):
        """Полный анализ файла"""
        print("🔬 GHIDRA-ПОДОБНЫЙ АНАЛИЗАТОР")
        print("="*80)
        print("Автоматизированный анализ ELF файла для поиска криптографических ключей")
        print()
        
        if not self.load_file():
            return None
        
        # Парсинг ELF заголовка
        if not self.parse_elf_header():
            return None
        
        # Извлечение строк
        self.extract_strings()
        
        # Поиск криптографических констант
        self.find_crypto_constants()
        
        # Анализ секций данных
        self.analyze_data_sections()
        
        # Поиск XOR-кодированных ключей
        self.search_xor_encoded_keys()
        
        # Тестирование кандидатов
        found_key = self.test_crypto_candidates()
        
        if found_key:
            # Создаем генератор с найденным ключом
            self.create_generator(found_key)
            return found_key
        else:
            print(f"\n💡 РЕКОМЕНДАЦИИ:")
            print("   1. Установите настоящий Ghidra для более глубокого анализа")
            print("   2. Попробуйте динамический анализ на QNX системе")
            print("   3. Исследуйте системные файлы и переменные окружения")
            print("   4. Возможно, ключ генерируется алгоритмически")
            return None
    
    def create_generator(self, secret_key):
        """Создание генератора с найденным ключом"""
        generator_code = f'''#!/usr/bin/env python3
"""
ГЕНЕРАТОР С КЛЮЧОМ ИЗ GHIDRA-АНАЛИЗА
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
        
        with open("D:/vzlom/ghidra_found_generator.py", "w", encoding="utf-8") as f:
            f.write(generator_code)
        
        print(f"\n✅ Создан ghidra_found_generator.py с найденным ключом!")

def main():
    """Главная функция"""
    if not os.path.exists("unlock"):
        print("❌ Файл 'unlock' не найден в текущей директории")
        return
    
    analyzer = ELFAnalyzer("unlock")
    found_key = analyzer.full_analysis()
    
    if found_key:
        print(f"\n🎉 АНАЛИЗ ЗАВЕРШЕН УСПЕШНО!")
        print(f"SECRET_KEY: '{found_key}'")
    else:
        print(f"\n📋 ОТЧЕТ ОБ АНАЛИЗЕ:")
        print(f"   Найдено строк: {len(analyzer.strings)}")
        print(f"   Протестировано кандидатов: {len(analyzer.crypto_candidates)}")
        print(f"   Результат: ключ не найден автоматически")

if __name__ == "__main__":
    main()
